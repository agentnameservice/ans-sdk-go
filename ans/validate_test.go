package ans

import (
	"errors"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestValidateRequired(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		value     string
		wantErr   bool
	}{
		{
			name:      "non-empty value returns no error",
			paramName: "agentID",
			value:     "agent-123",
			wantErr:   false,
		},
		{
			name:      "empty value returns ErrBadRequest",
			paramName: "agentID",
			value:     "",
			wantErr:   true,
		},
		{
			name:      "whitespace-only value is accepted",
			paramName: "host",
			value:     "  ",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequired(tt.paramName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !errors.Is(err, models.ErrBadRequest) {
				t.Errorf("validateRequired() error = %v, want ErrBadRequest", err)
			}
		})
	}
}
