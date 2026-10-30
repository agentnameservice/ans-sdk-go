package cmd

import (
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestParseFunctionFlag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      *models.AgentFunction
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "valid id and name only",
			input: "domain_suggest:Domain Suggest",
			want: &models.AgentFunction{
				ID:   "domain_suggest",
				Name: "Domain Suggest",
			},
		},
		{
			name:  "valid with single tag",
			input: "check:Check:domain",
			want: &models.AgentFunction{
				ID:   "check",
				Name: "Check",
				Tags: []string{"domain"},
			},
		},
		{
			name:  "valid with multiple tags",
			input: "check:Check:domain,suggest,premium",
			want: &models.AgentFunction{
				ID:   "check",
				Name: "Check",
				Tags: []string{"domain", "suggest", "premium"},
			},
		},
		{
			name:  "whitespace trimmed",
			input: "  id  :  name  :  tag1  ,  tag2  ",
			want: &models.AgentFunction{
				ID:   "id",
				Name: "name",
				Tags: []string{"tag1", "tag2"},
			},
		},
		{
			name:  "empty tags section results in nil tags",
			input: "id:name:",
			want: &models.AgentFunction{
				ID:   "id",
				Name: "name",
				Tags: nil,
			},
		},
		{
			name:  "filters empty tags from comma-separated list",
			input: "id:name:tag1,,tag2",
			want: &models.AgentFunction{
				ID:   "id",
				Name: "name",
				Tags: []string{"tag1", "tag2"},
			},
		},
		{
			name:  "colon in name allowed",
			input: "id:Name: with colon",
			want: &models.AgentFunction{
				ID:   "id",
				Name: "Name",
				Tags: []string{"with colon"},
			},
		},
		{
			name:      "missing name - single part",
			input:     "check",
			wantErr:   true,
			errSubstr: "invalid function format",
		},
		{
			name:      "empty ID",
			input:     ":Check",
			wantErr:   true,
			errSubstr: "ID is required",
		},
		{
			name:      "empty name",
			input:     "check:",
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name:      "empty string",
			input:     "",
			wantErr:   true,
			errSubstr: "invalid function format",
		},
		{
			name:      "whitespace only",
			input:     "   ",
			wantErr:   true,
			errSubstr: "invalid function format",
		},
		{
			name:      "whitespace ID",
			input:     "   :name",
			wantErr:   true,
			errSubstr: "ID is required",
		},
		{
			name:      "whitespace name",
			input:     "id:   ",
			wantErr:   true,
			errSubstr: "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFunctionFlag(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFunctionFlag() expected error containing %q, got nil", tt.errSubstr)
					return
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ParseFunctionFlag() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseFunctionFlag() unexpected error: %v", err)
				return
			}

			if got.ID != tt.want.ID {
				t.Errorf("ParseFunctionFlag() ID = %q, want %q", got.ID, tt.want.ID)
			}
			if got.Name != tt.want.Name {
				t.Errorf("ParseFunctionFlag() Name = %q, want %q", got.Name, tt.want.Name)
			}
			if len(got.Tags) != len(tt.want.Tags) {
				t.Errorf("ParseFunctionFlag() Tags len = %d, want %d", len(got.Tags), len(tt.want.Tags))
			} else {
				for i := range got.Tags {
					if got.Tags[i] != tt.want.Tags[i] {
						t.Errorf("ParseFunctionFlag() Tags[%d] = %q, want %q", i, got.Tags[i], tt.want.Tags[i])
					}
				}
			}
		})
	}
}

func TestValidateFunction(t *testing.T) {
	tests := []struct {
		name      string
		fn        *models.AgentFunction
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid function",
			fn: &models.AgentFunction{
				ID:   "test_func",
				Name: "Test Function",
				Tags: []string{"test", "example"},
			},
		},
		{
			name: "valid function without tags",
			fn: &models.AgentFunction{
				ID:   "test_func",
				Name: "Test Function",
			},
		},
		{
			name: "valid function with max allowed tags",
			fn: &models.AgentFunction{
				ID:   "test_func",
				Name: "Test Function",
				Tags: []string{"tag1", "tag2", "tag3", "tag4", "tag5"},
			},
		},
		{
			name: "valid function with max length ID",
			fn: &models.AgentFunction{
				ID:   strings.Repeat("a", MaxFunctionIDLength),
				Name: "Test",
			},
		},
		{
			name: "valid function with max length name",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: strings.Repeat("a", MaxFunctionNameLength),
			},
		},
		{
			name: "valid function with max length tag",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: "Test",
				Tags: []string{strings.Repeat("a", MaxFunctionTagLength)},
			},
		},
		{
			name:      "nil function",
			fn:        nil,
			wantErr:   true,
			errSubstr: "cannot be nil",
		},
		{
			name: "empty ID",
			fn: &models.AgentFunction{
				ID:   "",
				Name: "Test",
			},
			wantErr:   true,
			errSubstr: "ID is required",
		},
		{
			name: "empty name",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: "",
			},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name: "ID exceeds max length",
			fn: &models.AgentFunction{
				ID:   strings.Repeat("a", MaxFunctionIDLength+1),
				Name: "Test",
			},
			wantErr:   true,
			errSubstr: "ID exceeds maximum length",
		},
		{
			name: "name exceeds max length",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: strings.Repeat("a", MaxFunctionNameLength+1),
			},
			wantErr:   true,
			errSubstr: "name exceeds maximum length",
		},
		{
			name: "too many tags",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: "Test",
				Tags: []string{"t1", "t2", "t3", "t4", "t5", "t6"},
			},
			wantErr:   true,
			errSubstr: "tags exceed maximum count",
		},
		{
			name: "tag exceeds max length",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: "Test",
				Tags: []string{strings.Repeat("a", MaxFunctionTagLength+1)},
			},
			wantErr:   true,
			errSubstr: "tag at index 0 exceeds maximum length",
		},
		{
			name: "second tag exceeds max length",
			fn: &models.AgentFunction{
				ID:   "test",
				Name: "Test",
				Tags: []string{"valid", strings.Repeat("b", MaxFunctionTagLength+1)},
			},
			wantErr:   true,
			errSubstr: "tag at index 1 exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFunction(tt.fn)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateFunction() expected error containing %q, got nil", tt.errSubstr)
					return
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ValidateFunction() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateFunction() unexpected error: %v", err)
			}
		})
	}
}

func TestParseFunctionFlags(t *testing.T) {
	tests := []struct {
		name      string
		flags     []string
		want      []models.AgentFunction
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "empty flags returns nil",
			flags: []string{},
			want:  nil,
		},
		{
			name:  "nil flags returns nil",
			flags: nil,
			want:  nil,
		},
		{
			name:  "single function",
			flags: []string{"domain_suggest:Domain Suggest"},
			want: []models.AgentFunction{
				{ID: "domain_suggest", Name: "Domain Suggest"},
			},
		},
		{
			name: "multiple functions",
			flags: []string{
				"domain_suggest:Domain Suggest:domain,suggestion",
				"domain_check:Domain Check",
			},
			want: []models.AgentFunction{
				{ID: "domain_suggest", Name: "Domain Suggest", Tags: []string{"domain", "suggestion"}},
				{ID: "domain_check", Name: "Domain Check"},
			},
		},
		{
			name:  "preserves order",
			flags: []string{"c:C", "a:A", "b:B"},
			want: []models.AgentFunction{
				{ID: "c", Name: "C"},
				{ID: "a", Name: "A"},
				{ID: "b", Name: "B"},
			},
		},
		{
			name:      "duplicate ID error",
			flags:     []string{"same_id:First", "same_id:Second"},
			wantErr:   true,
			errSubstr: "duplicate function ID",
		},
		{
			name:      "invalid format error",
			flags:     []string{"valid_id:Valid Name", "invalid"},
			wantErr:   true,
			errSubstr: "invalid function format",
		},
		{
			name:      "validation error propagates",
			flags:     []string{strings.Repeat("a", MaxFunctionIDLength+1) + ":Name"},
			wantErr:   true,
			errSubstr: "ID exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFunctionFlags(tt.flags)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFunctionFlags() expected error containing %q, got nil", tt.errSubstr)
					return
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("ParseFunctionFlags() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseFunctionFlags() unexpected error: %v", err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ParseFunctionFlags() returned %d functions, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i].ID != tt.want[i].ID {
					t.Errorf("ParseFunctionFlags()[%d].ID = %q, want %q", i, got[i].ID, tt.want[i].ID)
				}
				if got[i].Name != tt.want[i].Name {
					t.Errorf("ParseFunctionFlags()[%d].Name = %q, want %q", i, got[i].Name, tt.want[i].Name)
				}
				if len(got[i].Tags) != len(tt.want[i].Tags) {
					t.Errorf("ParseFunctionFlags()[%d].Tags len = %d, want %d", i, len(got[i].Tags), len(tt.want[i].Tags))
				} else {
					for j := range got[i].Tags {
						if got[i].Tags[j] != tt.want[i].Tags[j] {
							t.Errorf("ParseFunctionFlags()[%d].Tags[%d] = %q, want %q", i, j, got[i].Tags[j], tt.want[i].Tags[j])
						}
					}
				}
			}
		})
	}
}
