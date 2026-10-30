package verify

import (
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestParseAnsBadgeRecord(t *testing.T) {
	tests := []struct {
		name        string
		txt         string
		wantErr     bool
		wantFormat  string
		wantVersion *models.Version
		wantURL     string
	}{
		{
			name:        "valid with version",
			txt:         "v=ans-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: ptr(models.NewVersion(1, 0, 0)),
			wantURL:     "https://transparency.ans.godaddy.com/v1/agents/7b93c61c-e261-488c-89a3-f948119be0a0",
		},
		{
			name:        "valid without version",
			txt:         "v=ans-badge1; url=https://transparency.ans.ote-godaddy.com/v1/agents/835a27a8-6b20-4439-915e-668a9d36e469",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: nil,
			wantURL:     "https://transparency.ans.ote-godaddy.com/v1/agents/835a27a8-6b20-4439-915e-668a9d36e469",
		},
		{
			name:        "valid different order",
			txt:         "url=https://example.com/badge; v=ans-badge1; version=v2.1.3",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: ptr(models.NewVersion(2, 1, 3)),
			wantURL:     "https://example.com/badge",
		},
		{
			name:        "valid no spaces between parts",
			txt:         "v=ans-badge1;url=https://example.com/badge",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: nil,
			wantURL:     "https://example.com/badge",
		},
		{
			name:        "valid mixed spacing",
			txt:         "v=ans-badge1;version=v1.2.3; url=https://example.com/badge",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: ptr(models.NewVersion(1, 2, 3)),
			wantURL:     "https://example.com/badge",
		},
		{
			name:    "missing format version",
			txt:     "version=v1.0.0; url=https://example.com",
			wantErr: true,
		},
		{
			name:    "missing url",
			txt:     "v=ans-badge1; version=v1.0.0",
			wantErr: true,
		},
		{
			name:    "invalid url",
			txt:     "v=ans-badge1; url=not-a-url",
			wantErr: true,
		},
		{
			name:    "empty string",
			txt:     "",
			wantErr: true,
		},
		{
			name:        "ra-badge1 format version",
			txt:         "v=ra-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/test-id",
			wantErr:     false,
			wantFormat:  "ra-badge1",
			wantVersion: ptr(models.NewVersion(1, 0, 0)),
			wantURL:     "https://transparency.ans.godaddy.com/v1/agents/test-id",
		},
		{
			name:        "ra-badge1 without version",
			txt:         "v=ra-badge1; url=https://transparency.ans.godaddy.com/v1/agents/test-id",
			wantErr:     false,
			wantFormat:  "ra-badge1",
			wantVersion: nil,
			wantURL:     "https://transparency.ans.godaddy.com/v1/agents/test-id",
		},
		{
			name:        "bare semver without v prefix",
			txt:         "v=ra-badge1; version=1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/test-id",
			wantErr:     false,
			wantFormat:  "ra-badge1",
			wantVersion: ptr(models.NewVersion(1, 0, 0)),
			wantURL:     "https://transparency.ans.godaddy.com/v1/agents/test-id",
		},
		{
			name:    "unsupported format version",
			txt:     "v=unknown-badge1; url=https://example.com/badge",
			wantErr: true,
		},
		{
			name:    "URL with userinfo",
			txt:     "v=ans-badge1; url=https://user:pass@example.com/badge",
			wantErr: true,
		},
		{
			name:    "URL with fragment",
			txt:     "v=ans-badge1; url=https://example.com/badge#section",
			wantErr: true,
		},
		{
			name:    "URL with http scheme",
			txt:     "v=ans-badge1; url=http://example.com/badge",
			wantErr: true,
		},
		{
			name:    "URL without host",
			txt:     "v=ans-badge1; url=https:///path",
			wantErr: true,
		},
		{
			name:        "invalid version silently ignored",
			txt:         "v=ans-badge1; version=not-a-version; url=https://example.com/badge",
			wantErr:     false,
			wantFormat:  "ans-badge1",
			wantVersion: nil,
			wantURL:     "https://example.com/badge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := ParseAnsBadgeRecord(tt.txt)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseAnsBadgeRecord(%q) expected error, got nil", tt.txt)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAnsBadgeRecord(%q) unexpected error: %v", tt.txt, err)
			}

			if record.FormatVersion != tt.wantFormat {
				t.Errorf("FormatVersion = %q, want %q", record.FormatVersion, tt.wantFormat)
			}

			if tt.wantVersion == nil {
				if record.Version != nil {
					t.Errorf("Version = %v, want nil", record.Version)
				}
			} else {
				if record.Version == nil {
					t.Errorf("Version = nil, want %v", tt.wantVersion)
				} else if !record.Version.Equal(*tt.wantVersion) {
					t.Errorf("Version = %v, want %v", record.Version, tt.wantVersion)
				}
			}

			if record.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", record.URL, tt.wantURL)
			}
		})
	}
}

// ptr returns a pointer to the given value
func ptr[T any](v T) *T {
	return &v
}
