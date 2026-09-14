package pop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// DPoPHeader is the HTTP header that carries the compact DPoP proof (RFC 9449).
const DPoPHeader = "DPoP"

// DefaultMaxContentBytes caps the request content Middleware buffers to verify
// ans_content_digest when WithMaxContentBytes is not set: 1 MiB.
const DefaultMaxContentBytes int64 = 1 << 20

// The two URL schemes an authority can arrive under; each has a default port
// that trustedKey and normalizeHTU drop.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// AccessTokenFromAuthorization returns the access token when an Authorization
// header value presents one under the DPoP auth scheme (RFC 9449 §7.1). Scheme
// comparison is case-insensitive (RFC 9110 §11.1). Bearer or absent
// Authorization yields ok=false: such a token is not sender-constrained, so the
// proof must carry no ath.
//
// A callee that completes token binding MUST use this rather than parsing the
// header itself. Middleware verifies the proof's ath against exactly the bytes
// this returns; a second, subtly different parser in the handler would let the
// two halves of RFC 9449 §4.3 operate on different values, and a request the
// handler reads as "no token" skips the cnf.jkt comparison entirely.
func AccessTokenFromAuthorization(v string) (string, bool) {
	const scheme = "DPoP"
	if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return "", false
	}
	rest := v[len(scheme):]
	if rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	tok := strings.Trim(rest, " \t")
	if tok == "" {
		return "", false
	}
	return tok, true
}

// callerCtxKeyType is an unexported context key type to avoid collisions.
type callerCtxKeyType struct{}

//nolint:gochecknoglobals // context-key sentinel: the idiomatic Go pattern for typed context values
var callerCtxKey = callerCtxKeyType{}

// CallerFromContext returns the authenticated caller that Middleware injected,
// or ok=false if the request did not pass through Middleware.
func CallerFromContext(ctx context.Context) (*CallerIdentity, bool) {
	id, ok := ctx.Value(callerCtxKey).(*CallerIdentity)
	return id, ok
}

// contextWithCaller stores id in ctx (used by Middleware; exported only via
// CallerFromContext).
func contextWithCaller(ctx context.Context, id *CallerIdentity) context.Context {
	return context.WithValue(ctx, callerCtxKey, id)
}

type middlewareConfig struct {
	externalURL     func(*http.Request) string
	externalSet     bool
	trustedHosts    map[string]bool // keyed by trustedKey, under both schemes
	callerOpts      []CallerOption
	logger          *slog.Logger
	maxContentBytes int64
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*middlewareConfig)

// WithExternalURL sets how the middleware reconstructs the externally-visible
// request URL used for htu matching, for callees behind a TLS-terminating
// proxy or a path-rewriting hop.
//
// The returned URL MUST include this request's externally-visible path —
// typically a trusted authority joined with r.URL.RequestURI():
//
//	pop.WithExternalURL(func(r *http.Request) string {
//		return "https://api.example.com" + r.URL.RequestURI()
//	})
//
// Returning a constant is a security bug, not a shortcut: htu would then
// compare every request against one string, so a proof minted for any path
// would be accepted on every path and only htm would still bind the target.
// Middleware probes the function at construction and panics if it ignores the
// path. Derive the authority from a TRUSTED source — a fixed value, or a
// proxy-set header the proxy strips from clients — never from raw
// client-supplied X-Forwarded-* headers, or the authority can be forged.
//
// Middleware requires this or WithTrustedHosts and panics at construction when
// neither is set. The request's own Host header is client-controlled: were it
// used unchecked, an attacker holding a proof captured from a call to another
// origin could present it here with a spoofed Host and satisfy the htu check.
func WithExternalURL(fn func(*http.Request) string) MiddlewareOption {
	return func(c *middlewareConfig) {
		if fn != nil {
			c.externalURL = fn
			c.externalSet = true
		}
	}
}

// probeExternalURL rejects an externalURL function that ignores the request
// path. Two synthetic requests differing only in path must produce different
// URLs; a function that collapses them silently removes htu's target binding,
// so this fails at wiring time rather than per request.
func probeExternalURL(fn func(*http.Request) string) {
	mk := func(path string) *http.Request {
		return &http.Request{
			Method: http.MethodGet,
			Host:   "probe.invalid",
			URL:    &url.URL{Path: path},
			Header: http.Header{},
		}
	}
	if fn(mk("/pop-probe-a")) == fn(mk("/pop-probe-b")) {
		panic("pop.WithExternalURL: function ignores the request path, so htu would not bind " +
			"the request target; append r.URL.RequestURI() to your external authority")
	}
}

// WithTrustedHosts restricts which authorities the htu comparison will accept,
// closing the spoofed-Host hole described in WithExternalURL. Each entry is an
// externally-visible authority ("api.example.com" or "api.example.com:8443"),
// matched case-insensitively with the request scheme's default port ignored:
// under https, "api.example.com" and "api.example.com:443" are the same origin
// while "api.example.com:80" is a different one. A request whose authority is
// not listed is rejected with 401.
//
// This composes with WithExternalURL rather than being overridden by it: when
// both are set, the allowlist constrains the authority that function returns.
//
// Panics if every supplied value is empty — a security option that silently
// becomes a no-op (an unset environment variable, say) is worse than none.
func WithTrustedHosts(hosts ...string) MiddlewareOption {
	return func(c *middlewareConfig) {
		for _, h := range hosts {
			if strings.TrimSpace(h) == "" {
				continue
			}
			if c.trustedHosts == nil {
				c.trustedHosts = make(map[string]bool)
			}
			c.trustedHosts[trustedKey(schemeHTTPS, h)] = true
			c.trustedHosts[trustedKey(schemeHTTP, h)] = true
		}
		if len(hosts) > 0 && len(c.trustedHosts) == 0 {
			panic("pop.WithTrustedHosts: every supplied host was empty")
		}
	}
}

// trustedKey renders an authority for allowlist lookup under one scheme:
// lowercased, with only that scheme's default port dropped, so "h:443" and "h"
// coincide under https while "h:80" stays a distinct https origin. This is the
// same port rule normalizeHTU applies to the target URL.
func trustedKey(scheme, authority string) string {
	authority = strings.ToLower(strings.TrimSpace(authority))
	switch scheme {
	case schemeHTTPS:
		authority = strings.TrimSuffix(authority, ":443")
	case schemeHTTP:
		authority = strings.TrimSuffix(authority, ":80")
	}
	return scheme + "://" + authority
}

// requestScheme is the scheme a server-side request arrived under.
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return schemeHTTPS
	}
	return schemeHTTP
}

// WithMaxContentBytes caps the request content Middleware reads to verify
// ans_content_digest; a request whose content exceeds it is rejected with 413
// before any hashing. Non-positive values are ignored. Defaults to
// DefaultMaxContentBytes.
func WithMaxContentBytes(n int64) MiddlewareOption {
	return func(c *middlewareConfig) {
		if n > 0 {
			c.maxContentBytes = n
		}
	}
}

// WithMiddlewareCallerOptions forwards CallerOptions (WithExpectedAnsName,
// WithRequireReceipt, WithPoPSkew, ...) to the per-request VerifyCaller.
func WithMiddlewareCallerOptions(opts ...CallerOption) MiddlewareOption {
	return func(c *middlewareConfig) { c.callerOpts = append(c.callerOpts, opts...) }
}

// WithMiddlewareLogger sets the structured logger used by the middleware and
// the verification it drives. Defaults to slog.Default(); pass a handler over
// io.Discard to silence it.
func WithMiddlewareLogger(l *slog.Logger) MiddlewareOption {
	return func(c *middlewareConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// securityHeaders are the request headers a verification decision reads. Every
// one is multiplicity-checked in preflight: Go's Header.Get returns only the
// first value, so a duplicate would let this verifier and any other hop act on
// different bytes.
//
//nolint:gochecknoglobals // fixed policy list, read-only
var securityHeaders = []string{
	DPoPHeader, "Authorization", scitt.HeaderReceipt, scitt.HeaderStatusToken,
}

// preflight applies the request-level checks that run before verification:
// header multiplicity (RFC 9449 §4.3 requires rejecting a request carrying more
// than one DPoP header; the same reasoning covers Authorization, which drives
// the ath binding, and the two SCITT headers, which carry the caller's identity
// and liveness), then the trusted-host allowlist. Returns nil when the request
// may proceed.
func (c *middlewareConfig) preflight(r *http.Request) *ProofError {
	for _, h := range securityHeaders {
		if len(r.Header.Values(h)) > 1 {
			return newErr(ErrMalformedProof, "duplicate "+h+" header")
		}
	}
	return c.checkAuthority(r)
}

// checkAuthority enforces the trusted-host allowlist. It applies whether the htu
// authority comes from the request or from WithExternalURL: in the latter case
// the allowlist constrains the authority that function returns, so the two
// options compose as defense in depth instead of one silently overriding the
// other.
func (c *middlewareConfig) checkAuthority(r *http.Request) *ProofError {
	if len(c.trustedHosts) == 0 {
		return nil
	}
	scheme, host := requestScheme(r), r.Host
	if c.externalSet {
		u, err := url.Parse(c.externalURL(r))
		if err != nil {
			return newErr(ErrHTTPBindingMismatch, "external URL is not parseable")
		}
		scheme, host = strings.ToLower(u.Scheme), u.Host
	}
	if !c.trustedHosts[trustedKey(scheme, host)] {
		return newErr(ErrHTTPBindingMismatch, "request authority is not in the trusted set")
	}
	return nil
}

// Middleware authenticates the A2A caller on every request — verifying the DPoP
// possession proof and the SCITT receipt/status token and binding all three to
// one identity certificate — and injects the proven CallerIdentity into the
// request context (read it with CallerFromContext).
//
// When the request presents a DPoP-bound OAuth2 access token
// ("Authorization: DPoP <token>"), the proof's ath is verified against it
// automatically; the token's own OAuth validation (issuer, scopes, expiry)
// remains the wrapped handler's concern.
//
// The request content is bound too: the proof's ans_content_digest must match
// the content received, so once the caller is bound to a live identity
// Middleware buffers the body (up to WithMaxContentBytes, else 413), compares
// the digest before recording the proof's jti, and passes the verified bytes on
// to the wrapped handler.
//
// It is fail-closed: any verification failure returns 401 and the wrapped
// handler is not called. It AUTHENTICATES only; the wrapped handler must
// authorize the CallerIdentity.
//
// Logging defaults to slog.Default() so rejections and operational failures are
// visible without extra wiring; pass
// WithMiddlewareLogger to redirect or silence them. Rejections log at INFO,
// successful authentications at DEBUG, and a saturated replay cache or an
// unclassified failure at ERROR.
//
// Panics at construction on a wiring mistake, which must fail at startup rather
// than per request inside the handler: a nil keys or replay, an expected-peer
// configuration that can never be satisfied (a pin that is not an ans:// name,
// an empty allow-list), or no trusted authority at all (neither WithTrustedHosts
// nor WithExternalURL), since the request's own Host header is client-controlled.
func Middleware(keys scitt.KeyLookup, replay ReplayCache, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	if keys == nil {
		panic("pop.Middleware: nil scitt.KeyLookup")
	}
	if replay == nil {
		panic("pop.Middleware: nil ReplayCache")
	}
	cfg := &middlewareConfig{
		externalURL:     defaultRequestURL,
		logger:          slog.Default(),
		maxContentBytes: DefaultMaxContentBytes,
	}
	for _, o := range opts {
		o(cfg)
	}
	// Drive VerifyCaller with the same logger so verification detail and the
	// 401 decision share one component=pop log stream.
	callerOpts := append([]CallerOption{WithLogger(cfg.logger)}, cfg.callerOpts...)
	if err := checkCallerOptions(callerOpts); err != nil {
		panic("pop.Middleware: " + err.Error())
	}
	if cfg.externalSet {
		probeExternalURL(cfg.externalURL)
	}
	if !cfg.externalSet && len(cfg.trustedHosts) == 0 {
		panic("pop.Middleware: no trusted authority configured; set WithTrustedHosts or WithExternalURL " +
			"so htu is never compared against the client-controlled Host header")
	}
	m := &middleware{
		cfg:        cfg,
		keys:       keys,
		replay:     replay,
		callerOpts: callerOpts,
		log:        cfg.logger.With("component", "pop"),
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, content, ok := m.authenticate(w, r)
			if !ok {
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(content))
			next.ServeHTTP(w, r.WithContext(contextWithCaller(r.Context(), id)))
		})
	}
}

// middleware is the verifier Middleware wires once at construction.
type middleware struct {
	cfg        *middlewareConfig
	keys       scitt.KeyLookup
	replay     ReplayCache
	callerOpts []CallerOption
	log        *slog.Logger
}

// authenticate runs the request-level preflight and VerifyCaller for one
// request, writing the rejection response itself. On success it returns the
// proven caller and the request content it consumed for the digest comparison.
func (m *middleware) authenticate(w http.ResponseWriter, r *http.Request) (*CallerIdentity, []byte, bool) {
	hdrs, err := scitt.ExtractHeaders(r.Header)
	if err != nil {
		m.log.InfoContext(r.Context(), "request rejected",
			"category", string(ErrScittHeaderInvalid), "err", err.Error())
		writeUnauthorized(w)
		return nil, nil, false
	}
	// RFC 9449 §4.3: reject a request carrying more than one DPoP header
	// field. The same applies to Authorization, which drives the ath
	// binding — otherwise this verifier reads the first value while a
	// downstream hop may act on a different one.
	if pe := m.cfg.preflight(r); pe != nil {
		m.log.InfoContext(r.Context(), "request rejected",
			"category", string(pe.Type), "err", pe.Message)
		writeUnauthorized(w)
		return nil, nil, false
	}
	var content []byte
	readContent := func() ([]byte, error) {
		body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, m.cfg.maxContentBytes))
		if readErr != nil {
			return nil, readErr
		}
		content = body
		return body, nil
	}
	perReq := append([]CallerOption(nil), m.callerOpts...)
	if tok, ok := AccessTokenFromAuthorization(r.Header.Get("Authorization")); ok {
		perReq = append(perReq, WithVerifyOptions(WithBoundAccessToken(tok)))
	}
	perReq = append(perReq, WithVerifyOptions(WithReceivedContent(readContent)))
	id, err := VerifyCaller(r.Context(), r.Header.Get(DPoPHeader), hdrs, r.Method,
		m.cfg.externalURL(r), m.keys, m.replay, perReq...)
	if err != nil {
		// VerifyCaller already logged the cause and its category.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request content too large", http.StatusRequestEntityTooLarge)
		} else {
			writeUnauthorized(w)
		}
		return nil, nil, false
	}
	return id, content, true
}

// AttachIdentity adds the caller's identity to an outbound A2A request: a
// freshly-signed DPoP proof (the DPoP header) plus the caller's own SCITT
// headers, so a pop.Middleware on the callee can authenticate it without mTLS.
//
// If the request already presents a DPoP-bound OAuth2 access token
// ("Authorization: DPoP <token>"), the proof is bound to it via ath — set the
// Authorization header before calling AttachIdentity.
//
// The request body, if any, is read once so the proof can bind its digest
// (ans_content_digest) and is restored as a re-readable body of known length;
// a request without a body binds the empty-content digest.
//
// scittHeaders carries the caller's X-SCITT-Receipt and X-ANS-Status-Token —
// obtain them from a scitt.HeaderSupplier; pop owns only the DPoP header. This
// is a free function that decorates any *http.Request; it is intentionally not
// attached to ans.AgentClient (whose job is verifying the server).
func AttachIdentity(req *http.Request, signer *Signer, scittHeaders http.Header) error {
	if req == nil {
		return newErr(ErrMisconfigured, "nil request")
	}
	if signer == nil {
		return newErr(ErrMisconfigured, "nil signer")
	}
	digest, err := bindRequestContent(req)
	if err != nil {
		return err
	}
	popts := []ProofOption{WithContentDigest(digest)}
	if tok, ok := AccessTokenFromAuthorization(req.Header.Get("Authorization")); ok {
		popts = append(popts, WithAccessToken(tok))
	}
	proof, err := signer.Sign(req.Context(), req.Method, req.URL.String(), popts...)
	if err != nil {
		return err
	}
	req.Header.Set(DPoPHeader, proof)
	for k, vals := range scittHeaders {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	return nil
}

// bindRequestContent reads req's content so the proof can carry its digest,
// then restores it as a re-readable body of known length. A request without
// content binds the empty-content digest.
func bindRequestContent(req *http.Request) ([sha256.Size]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return sha256.Sum256(nil), nil
	}
	content, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return [sha256.Size]byte{}, wrapErr(ErrContentUnreadable, "read request content", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(content))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(content)), nil }
	req.ContentLength = int64(len(content))
	return sha256.Sum256(content), nil
}

// defaultRequestURL reconstructs the request URL from a server-side request
// (whose URL is path-only) using its Host header. Host is client-controlled, so
// Middleware reaches this only behind WithTrustedHosts, whose allowlist has
// vetted r.Host first; see WithExternalURL.
func defaultRequestURL(r *http.Request) string {
	return requestScheme(r) + "://" + r.Host + r.URL.RequestURI()
}

// writeUnauthorized emits a fail-closed 401 with a DPoP challenge hint.
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", DPoPHeader)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
