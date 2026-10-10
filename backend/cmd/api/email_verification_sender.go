package main

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type developmentEmailVerificationSender struct {
	webAppURL *url.URL
}

func emailVerificationSenderFromEnvironment() (
	auth.EmailVerificationSender,
	error,
) {
	webAppURL, err := deliveryWebAppURLFromEnvironment()
	if err != nil {
		return nil, err
	}

	return &developmentEmailVerificationSender{
		webAppURL: webAppURL,
	}, nil
}

func deliveryWebAppURLFromEnvironment() (
	*url.URL,
	error,
) {
	mode := strings.TrimSpace(
		os.Getenv("EMAIL_DELIVERY_MODE"),
	)

	if mode != "log" {
		return nil, errors.New(
			"EMAIL_DELIVERY_MODE must be log during local development",
		)
	}

	allowInsecureLogging, err := booleanEnvironment(
		"ALLOW_INSECURE_EMAIL_LOGGING",
		false,
	)
	if err != nil {
		return nil, err
	}
	if !allowInsecureLogging {
		return nil, errors.New(
			"EMAIL_DELIVERY_MODE=log requires ALLOW_INSECURE_EMAIL_LOGGING=true and must not be used in production",
		)
	}

	rawWebAppURL := strings.TrimSpace(
		os.Getenv("WEB_APP_URL"),
	)

	webAppURL, err := url.Parse(rawWebAppURL)
	if err != nil ||
		webAppURL.Host == "" ||
		(webAppURL.Scheme != "http" &&
			webAppURL.Scheme != "https") {
		return nil, errors.New(
			"WEB_APP_URL must be a valid HTTP or HTTPS URL",
		)
	}

	webAppURL.RawQuery = ""
	webAppURL.Fragment = ""

	return webAppURL, nil
}

func (sender *developmentEmailVerificationSender) SendEmailVerification(
	ctx context.Context,
	delivery auth.EmailVerificationDelivery,
) error {
	verificationURL := sender.webAppURL.JoinPath(
		"verify-email",
	)

	fragment := url.Values{}
	fragment.Set("token", delivery.Token)
	verificationURL.Fragment = fragment.Encode()

	slog.InfoContext(
		ctx,
		"development email verification",
		"recipient",
		delivery.RecipientEmail,
		"expires_at",
		delivery.ExpiresAt,
		"verification_url",
		verificationURL.String(),
	)

	return nil
}
