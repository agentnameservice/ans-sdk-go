package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/viper"
)

func TestPrintDNSVerificationError(t *testing.T) {
	missing := []models.DNSRecord{
		{Name: "_ans.example.com", Type: "TXT", Value: "v=ans1; mode=direct", TTL: 3600, Required: true},
		{Name: "example.com", Type: "HTTPS", Value: "1 . alpn=h2", TTL: 3600, Priority: 1},
	}
	incorrect := []models.IncorrectDNSRecord{
		{
			Record:   models.DNSRecord{Name: "_443._tcp.example.com", Type: "TLSA", Value: "3 0 1 expected-cert-hash"},
			Expected: "3 0 1 expected-cert-hash",
			Found:    "3 0 1 actual-cert-hash",
		},
	}
	incorrectEmptyRecord := []models.IncorrectDNSRecord{
		{Record: models.DNSRecord{}, Expected: "expected-val", Found: "actual-val"},
	}

	tests := []struct {
		name     string
		err      *models.DNSVerificationError
		asJSON   bool
		wantSubs []string // substrings expected in output
	}{
		{
			name:   "text mode - missing only",
			err:    &models.DNSVerificationError{MissingRecords: missing},
			asJSON: false,
			wantSubs: []string{
				"Missing",
				"_ans.example.com",
				"TXT",
				"v=ans1",
				"example.com",
				"HTTPS",
			},
		},
		{
			name:   "text mode - incorrect only",
			err:    &models.DNSVerificationError{IncorrectRecords: incorrect},
			asJSON: false,
			wantSubs: []string{
				"Incorrect",
				"EXPECTED",
				"FOUND",
				"_443._tcp.example.com",
				"TLSA",
				"actual-cert-hash",
				"expected-cert-hash",
			},
		},
		{
			name:   "text mode - incorrect with empty Record renders <unknown> placeholder",
			err:    &models.DNSVerificationError{IncorrectRecords: incorrectEmptyRecord},
			asJSON: false,
			wantSubs: []string{
				"Incorrect",
				"<unknown>",
				"expected-val",
				"actual-val",
			},
		},
		{
			name:   "text mode - both",
			err:    &models.DNSVerificationError{MissingRecords: missing, IncorrectRecords: incorrect},
			asJSON: false,
			wantSubs: []string{
				"Missing",
				"Incorrect",
				"_ans.example.com",
				"_443._tcp.example.com",
			},
		},
		{
			name:   "json mode - both",
			err:    &models.DNSVerificationError{MissingRecords: missing, IncorrectRecords: incorrect},
			asJSON: true,
			wantSubs: []string{
				`"missingRecords"`,
				`"incorrectRecords"`,
				`"_ans.example.com"`,
				`"_443._tcp.example.com"`,
				`"expected"`,
				`"found"`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printDNSVerificationError(&buf, tt.err, tt.asJSON)
			out := buf.String()
			if out == "" {
				t.Fatal("printDNSVerificationError produced empty output")
			}
			for _, sub := range tt.wantSubs {
				if !strings.Contains(out, sub) {
					t.Errorf("output missing %q\nfull output:\n%s", sub, out)
				}
			}
			if tt.asJSON {
				var probe map[string]any
				if err := json.Unmarshal(buf.Bytes(), &probe); err != nil {
					t.Fatalf("JSON output not parseable: %v\noutput:\n%s", err, out)
				}
			}
		})
	}
}

func TestRunVerifyDNS_422_RendersDNSVerificationError(t *testing.T) {
	body := `{
		"status": "ERROR",
		"missingRecords": [
			{"name":"_ans.example.com","type":"TXT","value":"v=ans1","required":true}
		],
		"incorrectRecords": []
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected non-nil error so CLI exits non-zero on 422")
	}
	// Error chain must surface the typed error so callers can inspect.
	var dnsErr *models.DNSVerificationError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected error chain to contain *DNSVerificationError, got: %v", err)
	}
	if len(dnsErr.MissingRecords) != 1 {
		t.Errorf("MissingRecords len = %d, want 1", len(dnsErr.MissingRecords))
	}
}

func TestRunVerifyDNS_422_MalformedBody_FallsBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	var dnsErr *models.DNSVerificationError
	if errors.As(err, &dnsErr) {
		t.Fatal("malformed body should NOT produce typed DNSVerificationError")
	}
	var respErr *models.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatal("expected *ResponseError fallback")
	}
}

func TestRunVerifyDNS_422_JSONMode(t *testing.T) {
	body := `{
		"status": "ERROR",
		"missingRecords": [{"name":"a","type":"TXT","value":"x"}],
		"incorrectRecords": []
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	var dnsErr *models.DNSVerificationError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected typed error, got: %v", err)
	}
}
