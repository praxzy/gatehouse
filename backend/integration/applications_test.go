package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

func TestOIDCApplicationRegistrationLifecycle(
	t *testing.T,
) {
	ctx := context.Background()

	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Application Company",
			TenantSlug:  "application-company",
			Email:       "owner@applications.test",
			DisplayName: "Application Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register application tenant: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	applications, err := application.NewService(pool)
	if err != nil {
		t.Fatalf("create application service: %v", err)
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: authentication,
			Applications:   applications,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	ownerCookie := loginLifecycleUser(
		t,
		router,
		"application-company",
		"owner@applications.test",
		"correct horse battery staple",
	)

	t.Run(
		"invalid redirect URI is rejected",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPost,
				"/api/v1/applications",
				map[string]any{
					"name":        "Invalid Redirect",
					"client_type": "public",
					"redirect_uris": []string{
						"https://portal.example.test/callback#fragment",
					},
					"access_mode":      "all_active_members",
					"allowed_role_ids": []string{},
				},
				ownerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusBadRequest,
			)

			assertDatabaseCount(
				t,
				ctx,
				pool,
				`
					SELECT count(*)
					FROM applications
					WHERE tenant_id = $1
					  AND name = $2
				`,
				0,
				registration.TenantID,
				"Invalid Redirect",
			)
		},
	)

	const redirectURI = "https://portal.example.test/oauth/callback?source=gatehouse"

	createResponse := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/applications",
		map[string]any{
			"name":        "Employee Portal",
			"description": "Internal employee application",
			"client_type": "confidential",
			"redirect_uris": []string{
				redirectURI,
			},
			"access_mode":      "all_active_members",
			"allowed_role_ids": []string{},
		},
		ownerCookie,
	)

	createBody := requireResponseStatus(
		t,
		createResponse,
		http.StatusCreated,
	)

	var created struct {
		Application struct {
			ApplicationID string `json:"application_id"`
			ClientID      string `json:"client_id"`
			ClientType    string `json:"client_type"`
			RedirectURIs  []struct {
				URI string `json:"uri"`
			} `json:"redirect_uris"`
		} `json:"application"`
		ClientSecret string `json:"client_secret"`
	}

	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatalf(
			"decode created application: %v",
			err,
		)
	}

	if created.Application.ApplicationID == "" {
		t.Fatal("created application did not include an ID")
	}

	if !strings.HasPrefix(
		created.Application.ClientID,
		"ghc_",
	) {
		t.Fatalf(
			"unexpected client ID %q",
			created.Application.ClientID,
		)
	}

	if !strings.HasPrefix(created.ClientSecret, "ghs_") {
		t.Fatal("confidential client secret was not returned")
	}

	if len(created.Application.RedirectURIs) != 1 ||
		created.Application.RedirectURIs[0].URI !=
			redirectURI {
		t.Fatalf(
			"redirect URI was not preserved exactly: %+v",
			created.Application.RedirectURIs,
		)
	}

	var (
		storedSecretHash []byte
		hasSecretDate    bool
	)

	if err := pool.QueryRow(
		ctx,
		`
			SELECT
				client_secret_hash,
				client_secret_created_at IS NOT NULL
			FROM applications
			WHERE tenant_id = $1
			  AND id = $2
		`,
		registration.TenantID,
		created.Application.ApplicationID,
	).Scan(
		&storedSecretHash,
		&hasSecretDate,
	); err != nil {
		t.Fatalf("load stored client secret: %v", err)
	}

	expectedSecretHash := application.HashClientSecret(
		created.ClientSecret,
	)

	if !bytes.Equal(
		storedSecretHash,
		expectedSecretHash,
	) {
		t.Fatal("database did not store the expected secret hash")
	}

	if !hasSecretDate {
		t.Fatal("client secret creation time was not stored")
	}

	t.Run(
		"normal detail response never returns secret",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				"/api/v1/applications/"+
					created.Application.ApplicationID,
				nil,
				ownerCookie,
			)

			body := requireResponseStatus(
				t,
				response,
				http.StatusOK,
			)

			assertNoClientSecret(
				t,
				body,
				created.ClientSecret,
			)

			var detail struct {
				ApplicationID string `json:"application_id"`
				ClientID      string `json:"client_id"`
				RedirectURIs  []struct {
					URI string `json:"uri"`
				} `json:"redirect_uris"`
			}

			if err := json.Unmarshal(body, &detail); err != nil {
				t.Fatalf(
					"decode application detail: %v",
					err,
				)
			}

			if detail.ApplicationID !=
				created.Application.ApplicationID {
				t.Fatal("detail returned the wrong application")
			}

			if detail.ClientID !=
				created.Application.ClientID {
				t.Fatal("detail returned the wrong client ID")
			}

			if len(detail.RedirectURIs) != 1 ||
				detail.RedirectURIs[0].URI !=
					redirectURI {
				t.Fatal(
					"detail did not preserve the exact redirect URI",
				)
			}
		},
	)

	t.Run(
		"normal list response never returns secret",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				"/api/v1/applications",
				nil,
				ownerCookie,
			)

			body := requireResponseStatus(
				t,
				response,
				http.StatusOK,
			)

			assertNoClientSecret(
				t,
				body,
				created.ClientSecret,
			)

			var list struct {
				Applications []struct {
					ApplicationID string `json:"application_id"`
					ClientID      string `json:"client_id"`
				} `json:"applications"`
			}

			if err := json.Unmarshal(body, &list); err != nil {
				t.Fatalf(
					"decode application list: %v",
					err,
				)
			}

			if len(list.Applications) != 1 {
				t.Fatalf(
					"expected one application, got %d",
					len(list.Applications),
				)
			}
		},
	)
}

func assertNoClientSecret(
	t *testing.T,
	body []byte,
	rawSecret string,
) {
	t.Helper()

	if bytes.Contains(body, []byte(rawSecret)) {
		t.Fatal("response exposed the raw client secret")
	}

	if bytes.Contains(
		body,
		[]byte(`"client_secret"`),
	) {
		t.Fatal("normal response included client_secret")
	}

	if bytes.Contains(
		body,
		[]byte(`"client_secret_hash"`),
	) {
		t.Fatal("normal response included client_secret_hash")
	}
}
