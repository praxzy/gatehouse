package auth

import (
	"net/url"
	"testing"
	"time"
)

func TestGenerateTOTPCodeRFCVector(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(59, 0)

	code, err := GenerateTOTPCode(secret, at)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	if code != "287082" {
		t.Fatalf("expected RFC code 287082, got %q", code)
	}
}

func TestMatchTOTPCodeAcceptsClockWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1_700_000_000, 0)

	previousCode, err := GenerateTOTPCode(
		secret,
		now.Add(-30*time.Second),
	)
	if err != nil {
		t.Fatalf("generate previous code: %v", err)
	}

	expectedStep := now.Add(-30*time.Second).Unix() / totpPeriod

	step, matches := MatchTOTPCode(secret, previousCode, now)
	if !matches {
		t.Fatal("expected previous-window code to match")
	}

	if step != expectedStep {
		t.Fatalf("expected timestep %d, got %d", expectedStep, step)
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	secret := []byte("12345678901234567890")

	rawURI, err := TOTPProvisioningURI(
		"Gatehouse",
		"owner@example.test",
		secret,
	)
	if err != nil {
		t.Fatalf("create provisioning URI: %v", err)
	}

	parsed, err := url.Parse(rawURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}

	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatalf("unexpected provisioning URI %q", rawURI)
	}

	query := parsed.Query()

	if query.Get("issuer") != "Gatehouse" {
		t.Fatalf("unexpected issuer %q", query.Get("issuer"))
	}

	if query.Get("secret") == "" {
		t.Fatal("expected encoded TOTP secret")
	}

	if query.Get("digits") != "6" ||
		query.Get("period") != "30" ||
		query.Get("algorithm") != "SHA1" {
		t.Fatalf("unexpected TOTP parameters: %v", query)
	}
}
