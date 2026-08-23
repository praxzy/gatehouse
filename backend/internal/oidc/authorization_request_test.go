package oidc

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

const (
	testAuthorizationClientID    = "ghc_0123456789abcdefghijklmnopqrstuv"
	testAuthorizationRedirectURI = "https://portal.example.test/callback"
	testAuthorizationChallenge   = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestParseAuthorizationRequest(
	t *testing.T,
) {
	values := validAuthorizationValues()

	request, err := ParseAuthorizationRequest(values)
	if err != nil {
		t.Fatalf(
			"parse authorization request: %v",
			err,
		)
	}

	if request.ClientID !=
		testAuthorizationClientID {
		t.Fatalf(
			"unexpected client ID %q",
			request.ClientID,
		)
	}

	if request.RedirectURI !=
		testAuthorizationRedirectURI {
		t.Fatalf(
			"unexpected redirect URI %q",
			request.RedirectURI,
		)
	}

	if !reflect.DeepEqual(
		request.Scope,
		[]string{"openid", "profile", "email"},
	) {
		t.Fatalf(
			"unexpected scope %v",
			request.Scope,
		)
	}

	if request.State !=
		"state-0123456789abcdef" {
		t.Fatalf(
			"unexpected state %q",
			request.State,
		)
	}

	if request.Nonce !=
		"nonce-0123456789abcdef" {
		t.Fatalf(
			"unexpected nonce %q",
			request.Nonce,
		)
	}

	if request.CodeChallenge !=
		testAuthorizationChallenge ||
		request.CodeChallengeMethod != "S256" {
		t.Fatalf(
			"unexpected PKCE configuration: %+v",
			request,
		)
	}
}

func TestParseAuthorizationRequestRejectsUnsupportedFlow(
	t *testing.T,
) {
	values := validAuthorizationValues()
	values.Set("response_type", "token")

	_, err := ParseAuthorizationRequest(values)
	if !errors.Is(
		err,
		ErrUnsupportedResponseType,
	) {
		t.Fatalf(
			"expected unsupported response type, got %v",
			err,
		)
	}
}

func TestParseAuthorizationRequestRequiresS256PKCE(
	t *testing.T,
) {
	t.Run(
		"missing challenge",
		func(t *testing.T) {
			values := validAuthorizationValues()
			values.Del("code_challenge")

			_, err := ParseAuthorizationRequest(
				values,
			)
			if !errors.Is(err, ErrPKCERequired) {
				t.Fatalf(
					"expected PKCE rejection, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"plain method",
		func(t *testing.T) {
			values := validAuthorizationValues()
			values.Set(
				"code_challenge_method",
				"plain",
			)

			_, err := ParseAuthorizationRequest(
				values,
			)
			if !errors.Is(err, ErrPKCERequired) {
				t.Fatalf(
					"expected PKCE rejection, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"malformed challenge",
		func(t *testing.T) {
			values := validAuthorizationValues()
			values.Set(
				"code_challenge",
				"not-a-valid-S256-challenge",
			)

			_, err := ParseAuthorizationRequest(
				values,
			)
			if !errors.Is(err, ErrPKCERequired) {
				t.Fatalf(
					"expected PKCE rejection, got %v",
					err,
				)
			}
		},
	)
}

func TestParseAuthorizationRequestRejectsInvalidScope(
	t *testing.T,
) {
	testCases := []string{
		"profile email",
		"openid offline_access",
		"openid openid",
		" openid",
		"openid  profile",
	}

	for _, scope := range testCases {
		t.Run(scope, func(t *testing.T) {
			values := validAuthorizationValues()
			values.Set("scope", scope)

			_, err := ParseAuthorizationRequest(
				values,
			)
			if !errors.Is(
				err,
				ErrInvalidAuthorizationScope,
			) {
				t.Fatalf(
					"expected scope rejection for %q, got %v",
					scope,
					err,
				)
			}
		})
	}
}

func TestParseAuthorizationRequestRejectsRepeatedParameters(
	t *testing.T,
) {
	values := validAuthorizationValues()
	values.Add(
		"redirect_uri",
		"https://attacker.example/callback",
	)

	_, err := ParseAuthorizationRequest(values)
	if !errors.Is(
		err,
		ErrInvalidAuthorizationTarget,
	) {
		t.Fatalf(
			"expected repeated target rejection, got %v",
			err,
		)
	}
}

func validAuthorizationValues() url.Values {
	return url.Values{
		"response_type": {
			"code",
		},
		"client_id": {
			testAuthorizationClientID,
		},
		"redirect_uri": {
			testAuthorizationRedirectURI,
		},
		"scope": {
			"openid profile email",
		},
		"state": {
			"state-0123456789abcdef",
		},
		"nonce": {
			"nonce-0123456789abcdef",
		},
		"code_challenge": {
			testAuthorizationChallenge,
		},
		"code_challenge_method": {
			"S256",
		},
	}
}
