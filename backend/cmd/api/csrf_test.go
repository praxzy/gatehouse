package main

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func setValidCSRFEnvironment(
	t *testing.T,
) {
	t.Helper()

	t.Setenv(
		"CSRF_HMAC_KEY_BASE64",
		base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x42}, 32),
		),
	)
	t.Setenv(
		"ADMIN_ALLOWED_ORIGINS",
		"http://localhost:5173",
	)
}

func TestCSRFProtectorConfiguration(
	t *testing.T,
) {
	setValidCSRFEnvironment(t)

	protector, err :=
		csrfProtectorFromEnvironment()
	if err != nil {
		t.Fatalf(
			"configure CSRF protector: %v",
			err,
		)
	}

	if protector == nil {
		t.Fatal(
			"expected configured CSRF protector",
		)
	}
}

func TestCSRFProtectorRejectsMissingKey(
	t *testing.T,
) {
	setValidCSRFEnvironment(t)
	t.Setenv(
		"CSRF_HMAC_KEY_BASE64",
		"",
	)

	if _, err :=
		csrfProtectorFromEnvironment(); err == nil {
		t.Fatal(
			"expected missing CSRF key error",
		)
	}
}

func TestCSRFProtectorRejectsShortKey(
	t *testing.T,
) {
	setValidCSRFEnvironment(t)
	t.Setenv(
		"CSRF_HMAC_KEY_BASE64",
		base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x42}, 16),
		),
	)

	if _, err :=
		csrfProtectorFromEnvironment(); err == nil {
		t.Fatal(
			"expected short CSRF key error",
		)
	}
}

func TestCSRFProtectorRejectsInvalidOrigin(
	t *testing.T,
) {
	setValidCSRFEnvironment(t)
	t.Setenv(
		"ADMIN_ALLOWED_ORIGINS",
		"https://admin.example.com/path",
	)

	if _, err :=
		csrfProtectorFromEnvironment(); err == nil {
		t.Fatal(
			"expected invalid admin origin error",
		)
	}
}
