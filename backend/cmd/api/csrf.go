package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

func csrfProtectorFromEnvironment() (*httpapi.CSRFProtector, error) {
	encodedKey := strings.TrimSpace(
		os.Getenv("CSRF_HMAC_KEY_BASE64"),
	)
	if encodedKey == "" {
		return nil, errors.New(
			"CSRF_HMAC_KEY_BASE64 is required",
		)
	}

	key, err := base64.StdEncoding.DecodeString(
		encodedKey,
	)
	if err != nil {
		return nil, errors.New(
			"CSRF_HMAC_KEY_BASE64 must be valid base64",
		)
	}
	defer clear(key)

	rawOrigins := strings.TrimSpace(
		os.Getenv("ADMIN_ALLOWED_ORIGINS"),
	)
	if rawOrigins == "" {
		return nil, errors.New(
			"ADMIN_ALLOWED_ORIGINS is required",
		)
	}

	origins := make([]string, 0)

	for _, value := range strings.Split(
		rawOrigins,
		",",
	) {
		origin := strings.TrimSpace(value)
		if origin != "" {
			origins = append(
				origins,
				origin,
			)
		}
	}

	protector, err := httpapi.NewCSRFProtector(
		key,
		origins,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"configure CSRF protection: %w",
			err,
		)
	}

	return protector, nil
}
