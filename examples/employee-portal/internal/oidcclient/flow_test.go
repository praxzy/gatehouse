package oidcclient

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizationURLBindsStateNonceAndPKCE(t *testing.T) {
	client, err := New(
		"https://id.example.test",
		"employee-client",
		"employee-secret",
		"https://portal.example.test/oauth/callback",
		http.DefaultClient,
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	flow, err := newAuthorizationFlow(
		bytes.NewReader(make([]byte, 96)),
	)
	if err != nil {
		t.Fatalf("generate flow: %v", err)
	}

	authorizationURL, err := client.AuthorizationURL(
		Provider{
			AuthorizationEndpoint: "https://id.example.test/oauth/authorize",
		},
		flow,
	)
	if err != nil {
		t.Fatalf("build authorization URL: %v", err)
	}

	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}

	query := parsed.Query()
	if query.Get("response_type") != "code" ||
		query.Get("client_id") != "employee-client" ||
		query.Get("redirect_uri") !=
			"https://portal.example.test/oauth/callback" ||
		query.Get("scope") != "openid profile email" ||
		query.Get("state") != flow.State ||
		query.Get("nonce") != flow.Nonce ||
		query.Get("code_challenge_method") != "S256" ||
		query.Get("code_challenge") == "" ||
		len(flow.CodeVerifier) != 43 {
		t.Fatalf("unexpected authorization query: %v", query)
	}
}
