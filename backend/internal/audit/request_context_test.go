package audit_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

func TestRequestDetailsEnrichEvent(t *testing.T) {
	t.Parallel()

	sourceIP := netip.MustParseAddr("192.0.2.10")
	ctx := audit.WithRequestDetails(
		context.Background(),
		audit.NewRequestDetails(
			"request-123",
			&sourceIP,
			"Gatehouse test client",
		),
	)

	event := audit.EnrichFromContext(
		ctx,
		baseEvent(audit.EventLogin),
	)

	if event.RequestID != "request-123" {
		t.Fatalf("unexpected request ID %q", event.RequestID)
	}

	if event.SourceIP == nil || *event.SourceIP != sourceIP {
		t.Fatalf("unexpected source IP %#v", event.SourceIP)
	}

	if event.UserAgent != "Gatehouse test client" {
		t.Fatalf("unexpected user agent %q", event.UserAgent)
	}
}

func TestExplicitEventContextIsNotOverwritten(t *testing.T) {
	t.Parallel()

	contextIP := netip.MustParseAddr("192.0.2.10")
	eventIP := netip.MustParseAddr("198.51.100.20")

	ctx := audit.WithRequestDetails(
		context.Background(),
		audit.NewRequestDetails(
			"context-request",
			&contextIP,
			"context agent",
		),
	)

	event := baseEvent(audit.EventLogin)
	event.RequestID = "event-request"
	event.SourceIP = &eventIP
	event.UserAgent = "event agent"

	event = audit.EnrichFromContext(ctx, event)

	if event.RequestID != "event-request" {
		t.Fatalf("request ID was overwritten: %q", event.RequestID)
	}

	if event.SourceIP == nil || *event.SourceIP != eventIP {
		t.Fatalf("source IP was overwritten: %#v", event.SourceIP)
	}

	if event.UserAgent != "event agent" {
		t.Fatalf("user agent was overwritten: %q", event.UserAgent)
	}
}

func TestRequestDetailsSanitizeUntrustedFields(t *testing.T) {
	t.Parallel()

	invalidIP := netip.Addr{}
	details := audit.NewRequestDetails(
		"  "+strings.Repeat("r", 120)+"  ",
		&invalidIP,
		"  "+strings.Repeat("u", 600)+"  ",
	)

	if len(details.RequestID) != 100 {
		t.Fatalf(
			"expected 100-byte request ID, got %d",
			len(details.RequestID),
		)
	}

	if details.SourceIP != nil {
		t.Fatalf("expected invalid source IP to be removed")
	}

	if len(details.UserAgent) != 512 {
		t.Fatalf(
			"expected 512-byte user agent, got %d",
			len(details.UserAgent),
		)
	}
}

func TestRequestDetailsPreserveValidUTF8WhenTruncated(
	t *testing.T,
) {
	t.Parallel()

	details := audit.NewRequestDetails(
		"",
		nil,
		strings.Repeat("界", 200),
	)

	if !utf8.ValidString(details.UserAgent) {
		t.Fatal("truncated user agent is not valid UTF-8")
	}

	if len(details.UserAgent) > 512 {
		t.Fatalf(
			"user agent exceeds limit: %d",
			len(details.UserAgent),
		)
	}
}
