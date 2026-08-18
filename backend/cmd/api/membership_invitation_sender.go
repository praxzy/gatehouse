package main

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type developmentMembershipInvitationSender struct {
	webAppURL *url.URL
}

func membershipInvitationSenderFromEnvironment() (
	auth.MembershipInvitationSender,
	error,
) {
	webAppURL, err := deliveryWebAppURLFromEnvironment()
	if err != nil {
		return nil, err
	}

	return &developmentMembershipInvitationSender{
		webAppURL: webAppURL,
	}, nil
}

func (
	sender *developmentMembershipInvitationSender,
) SendMembershipInvitation(
	ctx context.Context,
	delivery auth.MembershipInvitationDelivery,
) error {
	invitationURL := sender.webAppURL.JoinPath(
		"accept-invitation",
	)

	fragment := url.Values{}
	fragment.Set("token", delivery.Token)
	invitationURL.Fragment = fragment.Encode()

	slog.InfoContext(
		ctx,
		"development membership invitation",
		"recipient",
		delivery.RecipientEmail,
		"tenant",
		delivery.TenantName,
		"role",
		delivery.RoleName,
		"expires_at",
		delivery.ExpiresAt,
		"invitation_url",
		invitationURL.String(),
	)

	return nil
}
