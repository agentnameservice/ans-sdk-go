package pop

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// CallerIdentity is the authenticated identity of an A2A caller.
//
// It is the result of AUTHENTICATION, not authorization. A non-nil
// CallerIdentity means the request provably came from this agent; the callee
// MUST still decide whether this agent may perform the requested action.
type CallerIdentity struct {
	// AnsName is the caller's ans:// name, from the verified status token.
	AnsName string
	// AgentID is the caller's agent id, from the verified status token.
	AgentID string
	// Fingerprint is SHA-256 of the identity certificate that signed the proof.
	Fingerprint [32]byte
	// JKT is the RFC 7638 thumbprint of the key that signed the proof. A callee
	// that also accepts a DPoP-bound OAuth2 access token MUST compare this to
	// the token's cnf.jkt claim to complete RFC 9449 §4.3 token binding — the
	// ath check proves only that proof and token were presented together, not
	// that the token was issued to this key.
	JKT string
}

// FingerprintHex returns the identity-certificate fingerprint as lowercase hex.
func (c *CallerIdentity) FingerprintHex() string {
	return hex.EncodeToString(c.Fingerprint[:])
}

// callerConfig is the resolved options for VerifyCaller / Middleware.
type callerConfig struct {
	requireReceipt bool
	allowed        map[string]bool // canonical ans:// names; empty = accept any proven agent
	pinErr         error           // why the expected-peer configuration can never be satisfied
	logger         *slog.Logger
	popSkew        time.Duration
	statusSkew     time.Duration
	now            func() time.Time
	verifyOpts     []VerifyOption
}

func defaultCallerConfig() callerConfig {
	return callerConfig{
		requireReceipt: true,
		logger:         slog.New(slog.DiscardHandler),
		popSkew:        DefaultPoPSkew,
		statusSkew:     scitt.MaxClockSkew,
		now:            time.Now,
	}
}

// CallerOption configures VerifyCaller and Middleware.
type CallerOption func(*callerConfig)

// WithExpectedAnsName restricts accepted callers to the given ans:// name,
// version included: another version of the same host is a separate
// registration, possibly with a different owner, and does not match. May be
// combined; call it more than once or use WithAllowedAnsNames to allow a set,
// which is also how a callee carries a peer through a version rollover. When no
// expected name is set, any proven agent authenticates (and the callee
// authorizes downstream).
//
// A name that does not parse, or an empty allow-list, is a wiring mistake:
// Middleware panics at startup and VerifyCaller rejects every request with
// ErrMisconfigured.
func WithExpectedAnsName(ansName string) CallerOption {
	return func(c *callerConfig) { addAllowed(c, ansName) }
}

// WithAllowedAnsNames restricts accepted callers to the given set of ans://
// names. Supplying no names is a wiring mistake, not "accept anyone": a pin
// list that came back empty (an unset variable, say) must not silently turn
// pinning off.
func WithAllowedAnsNames(ansNames ...string) CallerOption {
	return func(c *callerConfig) {
		if len(ansNames) == 0 && c.pinErr == nil {
			c.pinErr = errors.New("no ans:// names supplied to WithAllowedAnsNames")
		}
		for _, n := range ansNames {
			addAllowed(c, n)
		}
	}
}

// canonicalAnsName renders a parsed ans:// name in one spelling so that pins,
// certificate SANs, and status tokens compare on version and host alone.
func canonicalAnsName(ans *verify.AnsName) string {
	return "ans://" + ans.Version.String() + "." + ans.Host
}

// addAllowed records an expected ans:// name by its canonical form. A name that
// does not parse is recorded as a misconfiguration instead, so it can neither
// match a caller nor be silently dropped.
func addAllowed(c *callerConfig, ansName string) {
	ans, err := verify.ParseAnsName(ansName)
	if err != nil {
		if c.pinErr == nil {
			c.pinErr = err
		}
		return
	}
	if c.allowed == nil {
		c.allowed = make(map[string]bool)
	}
	c.allowed[canonicalAnsName(ans)] = true
}

// misconfiguration reports a CallerOption that can never be satisfied.
func (c *callerConfig) misconfiguration() error {
	if c.pinErr != nil {
		return wrapErr(ErrMisconfigured, "expected-peer configuration is unusable", c.pinErr)
	}
	return nil
}

// checkCallerOptions applies opts once so an expected-peer configuration that
// can never be satisfied fails at wiring time, the way a nil dependency does,
// rather than as a rejection of every request.
func checkCallerOptions(opts []CallerOption) error {
	cfg := defaultCallerConfig()
	for _, o := range opts {
		o(&cfg)
	}
	return cfg.misconfiguration()
}

// WithRequireReceipt sets whether a SCITT receipt is required (default true).
// When false, identity rests on the status token + possession proof and the
// receipt's transparency-log anchoring is not checked.
func WithRequireReceipt(require bool) CallerOption {
	return func(c *callerConfig) { c.requireReceipt = require }
}

// WithLogger sets the structured logger (component=pop is added). Defaults to a
// discarding logger.
func WithLogger(l *slog.Logger) CallerOption {
	return func(c *callerConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithPoPSkew sets the DPoP proof freshness window (default DefaultPoPSkew).
func WithPoPSkew(d time.Duration) CallerOption {
	return func(c *callerConfig) {
		if d > 0 {
			c.popSkew = d
		}
	}
}

// WithVerifyOptions forwards options to the underlying proof verification:
// WithBoundAccessToken when the request presented a DPoP-bound OAuth2 access
// token, and WithReceivedContent for the content the embedder received.
// Middleware adds both automatically, from the Authorization header and the
// request body; this hook exists for non-HTTP embedders.
func WithVerifyOptions(vopts ...VerifyOption) CallerOption {
	return func(c *callerConfig) { c.verifyOpts = append(c.verifyOpts, vopts...) }
}

// withCallerClock injects a clock for deterministic tests.
func withCallerClock(now func() time.Time) CallerOption {
	return func(c *callerConfig) { c.now = now }
}

// VerifyCaller authenticates an A2A caller from its DPoP proof and SCITT
// headers, returning the proven CallerIdentity. It composes the three proofs —
// possession (VerifyProof), liveness (status token), identity (receipt) — and
// binds them to one identity certificate.
//
// It authenticates; it does not authorize. See CallerIdentity.
func VerifyCaller(ctx context.Context, proofJWS string, h *scitt.Headers, method, rawURL string,
	keys scitt.KeyLookup, replay ReplayCache, opts ...CallerOption) (*CallerIdentity, error) {
	cfg := defaultCallerConfig()
	for _, o := range opts {
		o(&cfg)
	}

	log := cfg.logger.With("component", "pop")
	id, err := verifyCaller(ctx, &cfg, log, proofJWS, h, method, rawURL, keys, replay)
	if err != nil {
		logRejection(ctx, log, err)
		return nil, err
	}
	// Success is per-request and duplicates the access log, so it is DEBUG; the
	// fingerprint is encoded only if that level is actually enabled.
	if log.Enabled(ctx, slog.LevelDebug) {
		log.DebugContext(ctx, "caller authenticated",
			"ansName", id.AnsName, "agentId", id.AgentID, "fingerprint", id.FingerprintHex())
	}
	return id, nil
}

// logRejection emits a failed authentication at the level an operator needs.
// A rejection is expected application behavior (INFO), but a saturated replay
// cache or an unclassified failure means the service itself is broken (ERROR),
// and a client that hung up is neither (DEBUG).
func logRejection(ctx context.Context, log *slog.Logger, err error) {
	category := errorCategory(err)
	level := slog.LevelInfo
	switch category {
	case string(ErrClientGone):
		level = slog.LevelDebug
	case string(ErrReplayCacheFull), string(ErrMisconfigured), categoryUnknown:
		level = slog.LevelError
	}
	log.Log(ctx, level, "caller rejected", "category", category, "err", err.Error())
}

// verifyCaller runs the verification pipeline (no logging — the caller logs the
// outcome once).
func verifyCaller(ctx context.Context, cfg *callerConfig, log *slog.Logger, proofJWS string,
	h *scitt.Headers, method, rawURL string, keys scitt.KeyLookup, replay ReplayCache) (*CallerIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(ErrClientGone, "request context done before verification", err)
	}
	if keys == nil {
		return nil, newErr(ErrMisconfigured, "nil KeyLookup: cannot verify SCITT artifacts")
	}
	if replay == nil {
		return nil, newErr(ErrMisconfigured, "nil ReplayCache: cannot enforce single-use proofs")
	}
	if err := cfg.misconfiguration(); err != nil {
		return nil, err
	}
	if proofJWS == "" {
		return nil, newErr(ErrMissingHeaders, "no DPoP proof on request")
	}
	if h == nil || len(h.StatusToken) == 0 {
		return nil, newErr(ErrMissingHeaders, "no ANS status token on request")
	}
	if cfg.requireReceipt && len(h.Receipt) == 0 {
		return nil, newErr(ErrMissingHeaders, "no SCITT receipt on request")
	}

	now := cfg.now()

	// Possession: the caller holds the identity key, for this request. Neither
	// the content comparison nor the jti record happens yet — see below.
	vcfg := resolveVerifyOptions(cfg.verifyOpts)
	proof, err := verifyProofUnrecorded(ctx, proofJWS, method, rawURL, now, cfg.popSkew, &vcfg)
	if err != nil {
		return nil, err
	}
	if log.Enabled(ctx, slog.LevelDebug) {
		log.DebugContext(ctx, "possession proof verified (DPoP)",
			"jti", proof.JTI, "htu", proof.HTU, "fingerprint", hex.EncodeToString(proof.Fingerprint[:]))
	}

	// Liveness: the identity cert is currently valid (ACTIVE, not revoked).
	st, err := scitt.VerifyStatusTokenAt(h.StatusToken, keys, cfg.statusSkew, now.Unix())
	if err != nil {
		return nil, wrapErr(ErrStatusInvalid, "status token verification failed", err)
	}
	log.DebugContext(ctx, "liveness verified (status token)",
		"ansName", st.Payload.AnsName, "agentId", st.Payload.AgentID, "status", string(st.Payload.Status))

	// Identity: the caller's leaf is in the transparency log.
	var rcpt *scitt.VerifiedReceipt
	if cfg.requireReceipt {
		rcpt, err = scitt.VerifyReceipt(h.Receipt, keys)
		if err != nil {
			return nil, wrapErr(ErrReceiptInvalid, "receipt verification failed", err)
		}
		log.DebugContext(ctx, "identity verified (SCITT receipt)",
			"leafIndex", rcpt.LeafIndex, "treeSize", rcpt.TreeSize)
	}

	id, err := verifyBinding(proof, st, rcpt, cfg)
	if err != nil {
		return nil, err
	}

	// Content: hashed only now that the proof belongs to a vouched agent, so an
	// unauthenticated flood never makes the callee read and hash bodies.
	if err := checkContent(proof, vcfg.content); err != nil {
		return nil, err
	}

	// Single-use: recorded last, once the proof is known to belong to an agent
	// the transparency log vouches for. Recording earlier would let anyone with
	// a self-signed certificate consume the bounded cache and fail-close
	// authentication for every legitimate caller.
	if err := commitReplay(proof, replay); err != nil {
		return nil, err
	}
	return id, nil
}

// verifyBinding ties a verified proof, status token, and (optional) receipt to
// one agent. It is pure (no I/O, no clock) so it is unit-testable on its own.
func verifyBinding(proof *ProofResult, st *scitt.VerifiedStatusToken,
	rcpt *scitt.VerifiedReceipt, cfg *callerConfig) (*CallerIdentity, error) {
	// 1. The proof's certificate fingerprint must be a vouched identity cert.
	if !scitt.MatchesIdentityCert(&st.Payload, proof.Fingerprint) {
		return nil, newErr(ErrBindingFailed,
			"proof certificate fingerprint is not in the status token's ValidIdentityCerts")
	}

	// 2. The certificate's own ans:// SAN must equal the status token AnsName.
	//    Fail closed if the cert carries no ans:// SAN.
	ci := verify.CertIdentityFromX509(proof.Cert)
	certAns := ci.AnsName()
	if certAns == nil {
		return nil, newErr(ErrBindingFailed, "proof certificate has no ans:// URI SAN")
	}
	stAns, err := verify.ParseAnsName(st.Payload.AnsName)
	if err != nil {
		return nil, wrapErr(ErrBindingFailed, "status token AnsName is invalid", err)
	}
	if canonicalAnsName(certAns) != canonicalAnsName(stAns) {
		return nil, newErr(ErrBindingFailed, fmt.Sprintf(
			"proof certificate ans:// SAN %s does not match the status token AnsName %s",
			echo(certAns.String()), echo(st.Payload.AnsName)))
	}

	// 3. The receipt's leaf must name the same agent as the status token.
	if rcpt != nil {
		if err := receiptNamesAgent(rcpt, &st.Payload, stAns); err != nil {
			return nil, err
		}
	}

	// 4. Optional expected-peer pinning.
	if len(cfg.allowed) > 0 && !cfg.allowed[canonicalAnsName(stAns)] {
		return nil, newErr(ErrExpectedPeerMismatch,
			"caller "+echo(canonicalAnsName(stAns))+" is not in the accepted set")
	}

	return &CallerIdentity{
		AnsName:     st.Payload.AnsName,
		AgentID:     st.Payload.AgentID,
		Fingerprint: proof.Fingerprint,
		JKT:         proof.JKT,
	}, nil
}

// leafEnvelope is the minimal projection of a transparency-log leaf needed to
// bind a receipt to the status token's agent.
//
// The log signs the event wrapped as payload.producer.event, never as a bare
// object (models.TransparencyLogV1). The flat shape models.EventItem describes
// belongs to the /events REST API and does not appear in a receipt.
type leafEnvelope struct {
	Payload       leafPayload `json:"payload"`
	SchemaVersion string      `json:"schemaVersion"`
}

type leafPayload struct {
	Producer leafProducer `json:"producer"`
}

type leafProducer struct {
	Event leafEvent `json:"event"`
}

// leafEvent carries both spellings of the agent identifier because the schemas
// disagree: V1 and V2 emit "ansId" (models.EventV1), V0 emits "agentId"
// (models.EventV0).
type leafEvent struct {
	AnsID   string `json:"ansId"`
	AgentID string `json:"agentId"`
	AnsName string `json:"ansName"`
}

// agentID returns whichever schema's identifier the leaf populated.
func (e leafEvent) agentID() string {
	if e.AnsID != "" {
		return e.AnsID
	}
	return e.AgentID
}

// receiptNamesAgent makes the receipt load-bearing: its leaf event must name
// the same agent the status token does. (The receipt's RootHash is not anchored
// to a witnessed tree head — see scitt.VerifiedReceipt — so this is
// leaf-signature trust, not tree-head trust.)
func receiptNamesAgent(rcpt *scitt.VerifiedReceipt, st *scitt.StatusTokenPayload, stAns *verify.AnsName) error {
	var env leafEnvelope
	if err := json.Unmarshal(rcpt.EventBytes, &env); err != nil {
		return wrapErr(ErrReceiptInvalid, "receipt leaf event is not decodable JSON", err)
	}
	ev := env.Payload.Producer.Event
	agentID := ev.agentID()
	if agentID == "" || ev.AnsName == "" {
		return newErr(ErrReceiptInvalid, fmt.Sprintf(
			"receipt leaf event (schemaVersion %q) does not name an agent (ansId/agentId and ansName)",
			echo(env.SchemaVersion)))
	}
	if ev.AnsID != "" && ev.AgentID != "" && ev.AnsID != ev.AgentID {
		return newErr(ErrReceiptInvalid, "receipt leaf event names two different agent ids (ansId and agentId)")
	}
	leafAns, err := verify.ParseAnsName(ev.AnsName)
	if err != nil {
		return wrapErr(ErrReceiptInvalid, "receipt leaf ansName is not an ans:// name", err)
	}
	if agentID != st.AgentID {
		return newErr(ErrBindingFailed, fmt.Sprintf(
			"receipt leaf agent id %s does not match status token agentId %s", echo(agentID), echo(st.AgentID)))
	}
	if canonicalAnsName(leafAns) != canonicalAnsName(stAns) {
		return newErr(ErrBindingFailed, fmt.Sprintf(
			"receipt leaf ansName %s does not match status token AnsName %s", echo(ev.AnsName), echo(st.AnsName)))
	}
	return nil
}

// categoryUnknown labels a failure that carries no ProofError type — always a
// defect in this package, hence logged at ERROR.
const categoryUnknown = "UNKNOWN"

// errorCategory returns a stable category label for logging/metrics.
func errorCategory(err error) string {
	var pe *ProofError
	if errors.As(err, &pe) {
		return string(pe.Type)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return string(ErrClientGone)
	}
	return categoryUnknown
}
