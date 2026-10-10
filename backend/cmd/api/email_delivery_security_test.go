package main

import (
	"strings"
	"testing"
)

func TestDevelopmentEmailDeliveryRequiresExplicitSecretLoggingOptIn(
	t *testing.T,
) {
	t.Setenv("EMAIL_DELIVERY_MODE", "log")
	t.Setenv("WEB_APP_URL", "http://localhost:5173")
	t.Setenv("ALLOW_INSECURE_EMAIL_LOGGING", "")

	_, err := emailVerificationSenderFromEnvironment()
	if err == nil || !strings.Contains(
		err.Error(),
		"ALLOW_INSECURE_EMAIL_LOGGING=true",
	) {
		t.Fatalf("expected fail-closed delivery configuration, got %v", err)
	}
}

func TestDevelopmentEmailDeliveryAllowsExplicitLocalOptIn(
	t *testing.T,
) {
	t.Setenv("EMAIL_DELIVERY_MODE", "log")
	t.Setenv("WEB_APP_URL", "http://localhost:5173")
	t.Setenv("ALLOW_INSECURE_EMAIL_LOGGING", "true")

	verificationSender, err :=
		emailVerificationSenderFromEnvironment()
	if err != nil {
		t.Fatalf("configure verification sender: %v", err)
	}
	if verificationSender == nil {
		t.Fatal("expected verification sender")
	}

	invitationSender, err :=
		membershipInvitationSenderFromEnvironment()
	if err != nil {
		t.Fatalf("configure invitation sender: %v", err)
	}
	if invitationSender == nil {
		t.Fatal("expected invitation sender")
	}
}
