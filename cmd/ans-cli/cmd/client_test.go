package cmd

import (
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
)

func TestCreateClient(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid API key",
			cfg: &config.Config{
				BaseURL: "https://api.example.com",
				APIKey:  "mykey:mysecret",
			},
			wantErr: false,
		},
		{
			name: "invalid API key format - no colon",
			cfg: &config.Config{
				BaseURL: "https://api.example.com",
				APIKey:  "invalidkey",
			},
			wantErr:   true,
			errSubstr: "invalid API key format",
		},
		{
			name: "invalid API key format - empty",
			cfg: &config.Config{
				BaseURL: "https://api.example.com",
				APIKey:  "",
			},
			wantErr:   true,
			errSubstr: "invalid API key format",
		},
		{
			name: "valid API key with verbose",
			cfg: &config.Config{
				BaseURL: "https://api.example.com",
				APIKey:  "key:secret",
				Verbose: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createClient(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client == nil {
				t.Fatal("expected non-nil client")
			}
		})
	}
}
