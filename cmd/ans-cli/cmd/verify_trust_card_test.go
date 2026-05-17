package cmd

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeReceiptBytes stands in for SCITT receipt bytes; tests round-trip
// these through base64 to mirror how a Trust Card carries the staple.
var fakeReceiptBytes = []byte{
	0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x4C, 0x68, 0x65,
	0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x40,
}

// trustCardFixture builds a Trust Card body containing the supplied
// receipt bytes (base64-encoded) and an explicit agentId convenience
// field. Kept open to mutation so individual tests can drop fields.
func trustCardFixture(agentID string, receipt []byte) map[string]any {
	body := map[string]any{
		"agentName": "ans://v1.0.0.invoicing.acme.com",
	}
	if agentID != "" {
		body["agentId"] = agentID
	}
	if receipt != nil {
		body["transparencyReceipt"] = base64.StdEncoding.EncodeToString(receipt)
	}
	return body
}

// dualServer wires a stub Trust Card host and a stub Transparency Log
// receipt endpoint into a single helper. Returns both URLs and a
// teardown caller.
func dualServer(t *testing.T, cardBody map[string]any, receiptForTL []byte, tlStatus int) (cardURL, tlURL string, teardown func()) {
	t.Helper()
	cardSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cardBody)
	}))
	tlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cose")
		w.WriteHeader(tlStatus)
		if tlStatus < 400 {
			_, _ = w.Write(receiptForTL)
		}
	}))
	teardown = func() {
		cardSrv.Close()
		tlSrv.Close()
	}
	return cardSrv.URL + "/.well-known/ans/trust-card.json", tlSrv.URL, teardown
}

func TestRunVerifyTrustCard_HappyPath(t *testing.T) {
	body := trustCardFixture("ag-123", fakeReceiptBytes)
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusPass {
		t.Fatalf("overall: got %q, want PASS; reason=%s", r.Overall, r.Reason)
	}
	if r.StapledReceiptPresent != statusPass {
		t.Errorf("StapledReceiptPresent: %q", r.StapledReceiptPresent)
	}
	if r.ReceiptMatchesTL != statusPass {
		t.Errorf("ReceiptMatchesTL: %q", r.ReceiptMatchesTL)
	}
	if r.AgentID != "ag-123" {
		t.Errorf("AgentID: %q", r.AgentID)
	}
	if r.EmbeddedBytes != len(fakeReceiptBytes) {
		t.Errorf("EmbeddedBytes: got %d, want %d", r.EmbeddedBytes, len(fakeReceiptBytes))
	}
	if r.LiveBytes != len(fakeReceiptBytes) {
		t.Errorf("LiveBytes: got %d", r.LiveBytes)
	}
}

func TestRunVerifyTrustCard_NoStapledReceipt(t *testing.T) {
	body := trustCardFixture("ag-1", nil) // no transparencyReceipt
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusFail {
		t.Errorf("overall: got %q, want FAIL", r.Overall)
	}
	if r.StapledReceiptPresent != statusFail {
		t.Errorf("StapledReceiptPresent: %q", r.StapledReceiptPresent)
	}
	if !strings.Contains(r.Reason, "no transparencyReceipt") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_StapleStaleVsLive(t *testing.T) {
	// Stapled receipt does not byte-match the TL's live receipt: the
	// agent's hosted card has not been refreshed since the TL re-anchored.
	staleStaple := append([]byte{0x00}, fakeReceiptBytes...)
	body := trustCardFixture("ag-stale", staleStaple)
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusFail {
		t.Errorf("overall: got %q, want FAIL", r.Overall)
	}
	if r.ReceiptMatchesTL != statusFail {
		t.Errorf("ReceiptMatchesTL: %q", r.ReceiptMatchesTL)
	}
	if !strings.Contains(r.Reason, "byte-match") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_TLNotFound(t *testing.T) {
	body := trustCardFixture("ag-missing", fakeReceiptBytes)
	cardURL, tlURL, td := dualServer(t, body, nil, http.StatusNotFound)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "fetch live receipt") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_NoAgentID(t *testing.T) {
	body := trustCardFixture("", fakeReceiptBytes) // no agentId, no nested ansId
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "no agentId") {
		t.Errorf("reason should mention agentId: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_NoTransparencyURL(t *testing.T) {
	body := trustCardFixture("ag-1", fakeReceiptBytes)
	cardURL, _, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	t.Setenv("ANS_TRANSPARENCY_URL", "")
	r := runVerifyTrustCard(cardURL, "")
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "no transparency URL") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_TransparencyURLFromEnv(t *testing.T) {
	body := trustCardFixture("ag-env", fakeReceiptBytes)
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	t.Setenv("ANS_TRANSPARENCY_URL", tlURL)
	r := runVerifyTrustCard(cardURL, "") // no flag, env carries it
	if r.Overall != statusPass {
		t.Errorf("overall: got %q, reason=%s", r.Overall, r.Reason)
	}
}

func TestRunVerifyTrustCard_AgentIDFromNestedPayload(t *testing.T) {
	// No top-level agentId; agentId reachable via transparencyPayload.producer.event.ansId
	body := map[string]any{
		"agentName": "ans://v1.0.0.x.acme.com",
		"transparencyReceipt": base64.StdEncoding.EncodeToString(fakeReceiptBytes),
		"transparencyPayload": map[string]any{
			"producer": map[string]any{
				"event": map[string]any{
					"ansId": "ag-from-nested",
				},
			},
		},
	}
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusPass {
		t.Errorf("overall: got %q, reason=%s", r.Overall, r.Reason)
	}
	if r.AgentID != "ag-from-nested" {
		t.Errorf("AgentID: %q", r.AgentID)
	}
}

func TestRunVerifyTrustCard_BadBase64(t *testing.T) {
	body := map[string]any{
		"agentId":             "ag-1",
		"transparencyReceipt": "not-base64-!!!",
	}
	cardURL, tlURL, td := dualServer(t, body, fakeReceiptBytes, http.StatusOK)
	defer td()

	r := runVerifyTrustCard(cardURL, tlURL)
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "base64") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_CardFetchError(t *testing.T) {
	r := runVerifyTrustCard("http://127.0.0.1:1/no-such-host", "http://127.0.0.1:1")
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "fetch trust card") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_BadCardJSON(t *testing.T) {
	cardSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json {"))
	}))
	defer cardSrv.Close()

	r := runVerifyTrustCard(cardSrv.URL, "http://unused")
	if r.Overall != statusFail {
		t.Errorf("overall: got %q", r.Overall)
	}
	if !strings.Contains(r.Reason, "decode trust card") {
		t.Errorf("reason: %q", r.Reason)
	}
}

func TestRunVerifyTrustCard_BuildVerifyTrustCardCmd(t *testing.T) {
	c := buildVerifyTrustCardCmd()
	if c.Use == "" || !strings.HasPrefix(c.Use, "verify-trust-card") {
		t.Errorf("Use: %q", c.Use)
	}
	if c.Args == nil {
		t.Error("Args validator missing")
	}
	if c.Flags().Lookup("transparency-url") == nil {
		t.Error("--transparency-url flag missing")
	}
	if c.Flags().Lookup("json") == nil {
		t.Error("--json flag missing")
	}
}

func TestAgentIDFromTrustCard(t *testing.T) {
	cases := []struct {
		name    string
		body    map[string]any
		want    string
		wantErr bool
	}{
		{
			name: "top-level agentId wins",
			body: map[string]any{"agentId": "primary"},
			want: "primary",
		},
		{
			name: "nested ansId fallback",
			body: map[string]any{
				"transparencyPayload": map[string]any{
					"producer": map[string]any{
						"event": map[string]any{"ansId": "nested"},
					},
				},
			},
			want: "nested",
		},
		{
			name:    "neither present",
			body:    map[string]any{"agentName": "only"},
			wantErr: true,
		},
		{
			name:    "agentId empty string falls through to nested",
			body:    map[string]any{"agentId": ""},
			wantErr: true, // and no nested either
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := agentIDFromTrustCard(c.body)
			if (err != nil) != c.wantErr {
				t.Fatalf("err: got %v, wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte("abc"), []byte("abc")) {
		t.Error("equal slices should compare equal")
	}
	if bytesEqual([]byte("abc"), []byte("abd")) {
		t.Error("different slices should compare unequal")
	}
	if bytesEqual([]byte("ab"), []byte("abc")) {
		t.Error("different-length slices should compare unequal")
	}
	if !bytesEqual(nil, nil) {
		t.Error("nil slices should compare equal")
	}
	if !bytesEqual([]byte{}, nil) {
		t.Error("empty and nil should compare equal")
	}
}
