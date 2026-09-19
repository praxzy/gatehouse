package auditexport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func TestCreateRequiresExportPermission(t *testing.T) {
	service := &Service{}
	_, err := service.Create(
		context.Background(),
		auth.SessionContext{},
		CreateInput{Format: "csv"},
	)
	if !errors.Is(err, ErrExportForbidden) {
		t.Fatalf("expected export forbidden, got %v", err)
	}
}

func TestValidateCreateInput(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name  string
		input CreateInput
		valid bool
	}{
		{
			name: "CSV with supported filters",
			input: CreateInput{
				Format:    "csv",
				EventType: string(audit.EventLogin),
				Outcome:   "failure",
				TimeFrom:  now.Add(-time.Hour),
				TimeUntil: now,
			},
			valid: true,
		},
		{
			name:  "JSON without filters",
			input: CreateInput{Format: "json"},
			valid: true,
		},
		{
			name:  "unknown format",
			input: CreateInput{Format: "xml"},
		},
		{
			name: "unknown event type",
			input: CreateInput{
				Format:    "csv",
				EventType: "unknown.event",
			},
		},
		{
			name:  "unknown outcome",
			input: CreateInput{Format: "csv", Outcome: "maybe"},
		},
		{
			name: "reversed time range",
			input: CreateInput{
				Format:    "csv",
				TimeFrom:  now,
				TimeUntil: now.Add(-time.Hour),
			},
		},
		{
			name: "empty time range",
			input: CreateInput{
				Format:    "csv",
				TimeFrom:  now,
				TimeUntil: now,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCreateInput(test.input)
			if test.valid && err != nil {
				t.Fatalf("valid input rejected: %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidExportRequest) {
				t.Fatalf("expected invalid export request, got %v", err)
			}
		})
	}
}
