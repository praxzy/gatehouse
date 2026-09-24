package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSAllowsConfiguredPreflight(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)
	nextCalled := false

	request := httptest.NewRequest(
		http.MethodOptions,
		"/api/v1/roles",
		nil,
	)
	request.Header.Set(
		"Origin",
		"http://localhost:5173",
	)
	request.Header.Set(
		"Access-Control-Request-Method",
		http.MethodPost,
	)
	request.Header.Set(
		"Access-Control-Request-Headers",
		"Content-Type, X-CSRF-Token",
	)

	response := httptest.NewRecorder()

	protector.CORS(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			nextCalled = true
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}

	if nextCalled {
		t.Fatal("preflight reached application handler")
	}

	if response.Header().Get(
		"Access-Control-Allow-Origin",
	) != "http://localhost:5173" {
		t.Fatalf(
			"unexpected allowed origin %q",
			response.Header().Get(
				"Access-Control-Allow-Origin",
			),
		)
	}

	if response.Header().Get(
		"Access-Control-Allow-Credentials",
	) != "true" {
		t.Fatal("expected credentialed CORS response")
	}
}

func TestCORSRejectsUnknownOrigin(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/login",
		nil,
	)
	request.Header.Set(
		"Origin",
		"https://attacker.example",
	)

	response := httptest.NewRecorder()

	protector.CORS(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			t.Fatal("unknown origin reached handler")
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}

	if response.Header().Get(
		"Access-Control-Allow-Origin",
	) != "" {
		t.Fatal("rejected origin received CORS permission")
	}
}

func TestCORSRejectsUnknownRequestHeader(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodOptions,
		"/api/v1/roles",
		nil,
	)
	request.Header.Set(
		"Origin",
		"http://localhost:5173",
	)
	request.Header.Set(
		"Access-Control-Request-Method",
		http.MethodPost,
	)
	request.Header.Set(
		"Access-Control-Request-Headers",
		"X-Admin-Override",
	)

	response := httptest.NewRecorder()

	protector.CORS(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			t.Fatal("invalid preflight reached handler")
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}
}

func TestCORSAllowsConfiguredActualRequest(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/current-user",
		nil,
	)
	request.Header.Set(
		"Origin",
		"http://localhost:5173",
	)

	response := httptest.NewRecorder()

	protector.CORS(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}

	if response.Header().Get(
		"Access-Control-Allow-Origin",
	) != "http://localhost:5173" {
		t.Fatal("configured origin was not exposed")
	}
}

func TestCORSAllowsRequestWithoutBrowserOrigin(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/oauth/token",
		nil,
	)
	response := httptest.NewRecorder()

	protector.CORS(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}

	if response.Header().Get(
		"Access-Control-Allow-Origin",
	) != "" {
		t.Fatal("non-browser request received CORS headers")
	}
}
