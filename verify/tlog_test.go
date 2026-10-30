package verify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestMockTransparencyLogClient(t *testing.T) {
	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test-log-id",
			Producer: models.Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: models.AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://v1.0.0.agent.example.com",
					Agent: models.AgentInfo{
						Host:    "agent.example.com",
						Name:    "Test Agent",
						Version: "v1.0.0",
					},
					Attestations: models.Attestations{
						DomainValidation: "ACME-DNS-01",
						ServerCert: &models.CertAttestationV1{
							Fingerprint: "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
							Type:        "X509-DV-SERVER",
						},
						IdentityCert: &models.CertAttestationV1{
							Fingerprint: "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496",
							Type:        "X509-OV-CLIENT",
						},
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	t.Run("FetchBadge success", func(t *testing.T) {
		client := NewMockTransparencyLogClient().
			WithBadge("https://tlog.example.com/badge", badge)

		result, err := client.FetchBadge(context.Background(), "https://tlog.example.com/badge")
		if err != nil {
			t.Fatalf("FetchBadge() error = %v", err)
		}
		if result == nil {
			t.Fatal("FetchBadge() returned nil")
		}
		if result.Status != models.BadgeStatusActive {
			t.Errorf("Status = %v, want ACTIVE", result.Status)
		}
		if result.AgentHost() != "agent.example.com" {
			t.Errorf("AgentHost() = %q, want agent.example.com", result.AgentHost())
		}
	})

	t.Run("FetchBadge not found", func(t *testing.T) {
		client := NewMockTransparencyLogClient()

		_, err := client.FetchBadge(context.Background(), "https://tlog.example.com/unknown")
		if err == nil {
			t.Fatal("FetchBadge() expected error, got nil")
		}
		var tlogErr *TlogError
		if !errors.As(err, &tlogErr) {
			t.Fatalf("expected *TlogError, got %T", err)
		}
		if tlogErr.Type != TlogErrorNotFound {
			t.Errorf("error type = %v, want TlogErrorNotFound", tlogErr.Type)
		}
	})

	t.Run("FetchBadge error", func(t *testing.T) {
		client := NewMockTransparencyLogClient().
			WithError("https://tlog.example.com/error", &TlogError{
				Type: TlogErrorServiceUnavailable,
				URL:  "https://tlog.example.com/error",
			})

		_, err := client.FetchBadge(context.Background(), "https://tlog.example.com/error")
		if err == nil {
			t.Fatal("FetchBadge() expected error, got nil")
		}
		var tlogErr *TlogError
		if !errors.As(err, &tlogErr) {
			t.Fatalf("expected *TlogError, got %T", err)
		}
		if tlogErr.Type != TlogErrorServiceUnavailable {
			t.Errorf("error type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
		}
	})
}

func TestHTTPTransparencyLogClient_FetchBadge_Success(t *testing.T) {
	badge := &models.Badge{
		Status: models.BadgeStatusActive,
		Payload: models.BadgePayload{
			LogID: "test-log",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(badge)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	result, err := client.FetchBadge(context.Background(), server.URL+"/badge/123")
	if err != nil {
		t.Fatalf("FetchBadge() error = %v", err)
	}
	if result.Status != models.BadgeStatusActive {
		t.Errorf("Status = %v, want %v", result.Status, models.BadgeStatusActive)
	}
}

func TestHTTPTransparencyLogClient_FetchBadge_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchBadge(context.Background(), server.URL+"/badge/missing")
	if err == nil {
		t.Fatal("FetchBadge() expected error for 404")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorNotFound {
		t.Errorf("Type = %v, want TlogErrorNotFound", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchBadge_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchBadge(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchBadge() expected error for 500")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorServiceUnavailable {
		t.Errorf("Type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchBadge_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchBadge(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchBadge() expected error for 400")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorInvalidResponse {
		t.Errorf("Type = %v, want TlogErrorInvalidResponse", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchBadge_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchBadge(context.Background(), server.URL+"/badge/123")
	if err == nil {
		t.Fatal("FetchBadge() expected error for invalid JSON")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorInvalidResponse {
		t.Errorf("Type = %v, want TlogErrorInvalidResponse", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_FetchBadge_ConnectionError(t *testing.T) {
	client := NewHTTPTransparencyLogClient()
	_, err := client.FetchBadge(context.Background(), "http://localhost:1/badge/123")
	if err == nil {
		t.Fatal("FetchBadge() expected error for connection refused")
	}

	var tlogErr *TlogError
	if !errors.As(err, &tlogErr) {
		t.Fatalf("expected *TlogError, got %T", err)
	}
	if tlogErr.Type != TlogErrorServiceUnavailable {
		t.Errorf("Type = %v, want TlogErrorServiceUnavailable", tlogErr.Type)
	}
}

func TestHTTPTransparencyLogClient_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	client := NewHTTPTransparencyLogClient().WithHTTPClient(customClient)
	if client.httpClient != customClient {
		t.Error("WithHTTPClient() did not set custom client")
	}
}

func TestHTTPTransparencyLogClient_WithTimeout(t *testing.T) {
	client := NewHTTPTransparencyLogClient().WithTimeout(10 * time.Second)
	if client.httpClient.Timeout != 10*time.Second {
		t.Errorf("WithTimeout() timeout = %v, want 10s", client.httpClient.Timeout)
	}
}
