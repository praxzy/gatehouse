package auth

import (
	"context"
	"errors"
	"time"
)

const membershipInvitationLifetimeSeconds = 7 * 24 * 60 * 60

var ErrMembershipInvitationDelivery = errors.New(
	"membership invitation delivery failed",
)

type MembershipInvitationDelivery struct {
	RecipientEmail string
	TenantName     string
	RoleName       string
	Token          string
	ExpiresAt      time.Time
}

type MembershipInvitationSender interface {
	SendMembershipInvitation(
		ctx context.Context,
		delivery MembershipInvitationDelivery,
	) error
}
