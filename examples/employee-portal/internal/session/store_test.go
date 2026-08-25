package session

import (
	"testing"
	"time"

	"github.com/praxzy/gatehouse/examples/employee-portal/internal/oidcclient"
)

func TestAuthorizationFlowIsBoundAndSingleUse(t *testing.T) {
	store := NewStore()
	flow := oidcclient.AuthorizationFlow{
		State:        "expected-state",
		Nonce:        "expected-nonce",
		CodeVerifier: "expected-verifier",
	}

	token, err := store.BeginAuthorization(flow)
	if err != nil {
		t.Fatalf("begin authorization: %v", err)
	}

	if _, ok := store.ConsumeAuthorization(
		token,
		"wrong-state",
	); ok {
		t.Fatal("accepted mismatched state")
	}

	if _, ok := store.ConsumeAuthorization(
		token,
		flow.State,
	); ok {
		t.Fatal("reused consumed authorization flow")
	}
}

func TestLocalSessionExpiresAndCanBeRevoked(t *testing.T) {
	now := time.Date(
		2026,
		time.August,
		25,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	store := NewStore()
	store.now = func() time.Time { return now }

	token, csrfToken, err := store.CreateSession(oidcclient.Identity{
		Subject:   "user-123",
		Name:      "Alice",
		Email:     "alice@example.test",
		Roles:     []string{"Admin"},
		ExpiresAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	localSession, ok := store.GetSession(token)
	if !ok ||
		localSession.Identity.Subject != "user-123" ||
		localSession.CSRFToken != csrfToken ||
		csrfToken == "" {
		t.Fatalf("session was not available: %#v", localSession)
	}

	store.DeleteSession(token)
	if _, ok := store.GetSession(token); ok {
		t.Fatal("revoked session remained available")
	}
}
