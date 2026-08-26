package pop

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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
	allowed        map[string]bool // lowercased ans hosts; empty = accept any proven agent
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

// WithExpectedAnsName restricts accepted callers to the given ans:// name. May
// be combined; call it more than once or use WithAllowedAnsNames to allow a
// set. When no expected name is set, any proven agent authenticates (and the
// callee authorizes downstream).
func WithExpectedAnsName(ansName string) CallerOption {
	return func(c *callerConfig) { addAllowed(c, ansName) }
}

// WithAllowedAnsNames restricts accepted callers to the given set of ans:// names.
func WithAllowedAnsNames(ansNames ...string) CallerOption {
	return func(c *callerConfig) {
		for _, n := range ansNames {
			addAllowed(c, n)
		}
	}
}

// addAllowed records the host of an expected ans:// name. A name that does not
// parse is stored verbatim (lowercased) so it simply never matches a real host
// — a misconfigured pin fails closed rather than opening the gate.
func addAllowed(c *callerConfig, ansName string) {
	if c.allowed == nil {
		c.allowed = make(map[string]bool)
	}
	if ans, err := verify.ParseAnsName(ansName); err == nil {
		c.allowed[strings.ToLower(ans.Host)] = true
		return
	}
	c.allowed[strings.ToLower(strings.TrimSpace(ansName))] = true
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

// WithVerifyOptions forwards options to the underlying VerifyProof — e.g.
// WithVerifyOptions(WithBoundAccessToken(token)) when the request presented a
// DPoP-bound OAuth2 access token. Middleware adds that binding automatically
// from the Authorization header; this hook exists for non-HTTP embedders.
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

	// Possession: the caller holds the identity key, for this request. The jti
	// is NOT recorded yet — see the commitReplay call below.
	proof, err := verifyProofUnrecorded(ctx, proofJWS, method, rawURL, now, cfg.popSkew, cfg.verifyOpts...)
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
	if !strings.EqualFold(certAns.Host, stAns.Host) {
		return nil, newErr(ErrBindingFailed,
			"proof certificate ans:// SAN host does not match the status token AnsName")
	}

	// 3. The receipt's leaf must name the same agent as the status token.
	if rcpt != nil {
		if err := receiptNamesAgent(rcpt, &st.Payload); err != nil {
			return nil, err
		}
	}

	// 4. Optional expected-peer pinning.
	if len(cfg.allowed) > 0 && !cfg.allowed[strings.ToLower(stAns.Host)] {
		return nil, newErr(ErrExpectedPeerMismatch, "caller ans host is not in the accepted set")
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
// The log signs the event wrapped as payload.producer.event, not as a bare
// object: see models.TransparencyLogV1. The flat shape models.EventItem
// describes belongs to the /events REST API and never appears in a receipt.
type leafEnvelope struct {
	Payload leafPayload `json:"payload"`
}

type leafPayload struct {
	Producer leafProducer `json:"producer"`
}

type leafProducer struct {
	Event leafEvent `json:"event"`
}

// leafEvent carries both spellings of the agent identifier because the schemas
// disagree: V1 emits "ansId" (models.EventV1), V0 emits "agentId"
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
func receiptNamesAgent(rcpt *scitt.VerifiedReceipt, st *scitt.StatusTokenPayload) error {
	var env leafEnvelope
	if err := json.Unmarshal(rcpt.EventBytes, &env); err != nil {
		return wrapErr(ErrReceiptInvalid, "receipt leaf event is not decodable JSON", err)
	}
	ev := env.Payload.Producer.Event
	agentID := ev.agentID()
	if agentID == "" && ev.AnsName == "" {
		return newErr(ErrReceiptInvalid, "receipt leaf event names no agent (ansId/agentId/ansName)")
	}
	if agentID != "" && st.AgentID != "" && agentID != st.AgentID {
		return newErr(ErrBindingFailed, "receipt leaf agentId does not match status token agentId")
	}
	if ev.AnsName != "" && st.AnsName != "" && !strings.EqualFold(ev.AnsName, st.AnsName) {
		return newErr(ErrBindingFailed, "receipt leaf ansName does not match status token ansName")
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
