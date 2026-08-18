package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidMemberInvitation = errors.New(
		"invalid member invitation",
	)
	ErrMemberManagementForbidden = errors.New(
		"member management forbidden",
	)
	ErrMemberAlreadyExists = errors.New(
		"tenant membership already exists",
	)
	ErrInvitationRoleNotFound = errors.New(
		"invitation role not found",
	)
	ErrMembershipInvitationExpired = errors.New(
		"membership invitation expired",
	)
	ErrMembershipInvitationAccepted = errors.New(
		"membership invitation already accepted",
	)
	ErrInvitationAccountSetupRequired = errors.New(
		"invitation account setup required",
	)
	ErrInvalidInvitationAccountSetup = errors.New(
		"invalid invitation account setup",
	)
	ErrInvitedUserUnavailable = errors.New(
		"invited user is unavailable",
	)
)

type InviteMemberInput struct {
	Email  string
	RoleID pgtype.UUID
}

type InviteMemberResult struct {
	InvitationID pgtype.UUID
	Email        string
	RoleID       pgtype.UUID
	RoleName     string
	ExpiresAt    time.Time
}

type MembershipInvitationPreview struct {
	TenantName           string
	TenantSlug           string
	Email                string
	RoleName             string
	ExpiresAt            time.Time
	AccountSetupRequired bool
}

type AcceptMembershipInvitationInput struct {
	Token       string
	DisplayName string
	Password    string
}

type AcceptMembershipInvitationResult struct {
	TenantID     pgtype.UUID
	MembershipID pgtype.UUID
	UserID       pgtype.UUID
	Email        string
}

func (service *Service) InviteMember(
	ctx context.Context,
	session SessionContext,
	input InviteMemberInput,
) (InviteMemberResult, error) {
	if !session.HasPermission(PermissionMemberManage) {
		return InviteMemberResult{},
			ErrMemberManagementForbidden
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))

	if !validEmail(email) || !input.RoleID.Valid {
		return InviteMemberResult{}, ErrInvalidMemberInvitation
	}

	rawToken, tokenHash, err :=
		generateMembershipInvitationToken()
	if err != nil {
		return InviteMemberResult{}, fmt.Errorf(
			"generate membership invitation token: %w",
			err,
		)
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return InviteMemberResult{}, fmt.Errorf(
			"begin membership invitation transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	role, err := queries.GetRoleByID(
		ctx,
		store.GetRoleByIDParams{
			TenantID: session.TenantID,
			RoleID:   input.RoleID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return InviteMemberResult{},
			ErrInvitationRoleNotFound
	}
	if err != nil {
		return InviteMemberResult{}, fmt.Errorf(
			"load invitation role: %w",
			err,
		)
	}

	_, err = queries.GetTenantMembershipByEmail(
		ctx,
		store.GetTenantMembershipByEmailParams{
			TenantID: session.TenantID,
			Email:    email,
		},
	)
	if err == nil {
		return InviteMemberResult{}, ErrMemberAlreadyExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return InviteMemberResult{}, fmt.Errorf(
			"check existing tenant membership: %w",
			err,
		)
	}

	invitation, err := queries.UpsertMembershipInvitation(
		ctx,
		store.UpsertMembershipInvitationParams{
			TenantID:              session.TenantID,
			Email:                 email,
			RoleID:                role.ID,
			InvitedByMembershipID: session.MembershipID,
			TokenHash:             tokenHash,
			LifetimeSeconds: int32(
				membershipInvitationLifetimeSeconds,
			),
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return InviteMemberResult{}, ErrMemberAlreadyExists
	}
	if err != nil {
		return InviteMemberResult{}, fmt.Errorf(
			"store membership invitation: %w",
			err,
		)
	}

	if !invitation.ExpiresAt.Valid {
		return InviteMemberResult{}, errors.New(
			"stored membership invitation has no expiry",
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return InviteMemberResult{}, fmt.Errorf(
			"commit membership invitation: %w",
			err,
		)
	}

	result := InviteMemberResult{
		InvitationID: invitation.ID,
		Email:        invitation.Email,
		RoleID:       invitation.RoleID,
		RoleName:     role.Name,
		ExpiresAt:    invitation.ExpiresAt.Time,
	}

	delivery := MembershipInvitationDelivery{
		RecipientEmail: invitation.Email,
		TenantName:     session.TenantName,
		RoleName:       role.Name,
		Token:          rawToken,
		ExpiresAt:      invitation.ExpiresAt.Time,
	}

	if err := service.membershipInvitationSender.
		SendMembershipInvitation(ctx, delivery); err != nil {
		return result, fmt.Errorf(
			"%w: %v",
			ErrMembershipInvitationDelivery,
			err,
		)
	}

	return result, nil
}

func (service *Service) PreviewMembershipInvitation(
	ctx context.Context,
	rawToken string,
) (MembershipInvitationPreview, error) {
	tokenHash, err := hashMembershipInvitationToken(
		rawToken,
	)
	if err != nil {
		return MembershipInvitationPreview{},
			ErrInvalidMembershipInvitationToken
	}

	invitation, err :=
		service.queries.GetMembershipInvitationPreview(
			ctx,
			tokenHash,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return MembershipInvitationPreview{},
			ErrInvalidMembershipInvitationToken
	}
	if err != nil {
		return MembershipInvitationPreview{}, fmt.Errorf(
			"load membership invitation preview: %w",
			err,
		)
	}

	if invitation.AcceptedAt.Valid {
		return MembershipInvitationPreview{},
			ErrMembershipInvitationAccepted
	}

	if !invitation.ExpiresAt.Valid ||
		!invitation.ExpiresAt.Time.After(time.Now()) {
		return MembershipInvitationPreview{},
			ErrMembershipInvitationExpired
	}

	if invitation.AccountSetupRequired == nil {
		return MembershipInvitationPreview{}, errors.New(
			"membership invitation has invalid account state",
		)
	}

	return MembershipInvitationPreview{
		TenantName:           invitation.TenantName,
		TenantSlug:           invitation.TenantSlug,
		Email:                invitation.Email,
		RoleName:             invitation.RoleName,
		ExpiresAt:            invitation.ExpiresAt.Time,
		AccountSetupRequired: *invitation.AccountSetupRequired,
	}, nil
}

func (service *Service) AcceptMembershipInvitation(
	ctx context.Context,
	input AcceptMembershipInvitationInput,
) (AcceptMembershipInvitationResult, error) {
	tokenHash, err := hashMembershipInvitationToken(
		input.Token,
	)
	if err != nil {
		return AcceptMembershipInvitationResult{},
			ErrInvalidMembershipInvitationToken
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return AcceptMembershipInvitationResult{}, fmt.Errorf(
			"begin invitation acceptance transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	invitation, err :=
		queries.GetMembershipInvitationForUpdate(
			ctx,
			tokenHash,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return AcceptMembershipInvitationResult{},
			ErrInvalidMembershipInvitationToken
	}
	if err != nil {
		return AcceptMembershipInvitationResult{}, fmt.Errorf(
			"lock membership invitation: %w",
			err,
		)
	}

	if invitation.AcceptedAt.Valid {
		return AcceptMembershipInvitationResult{},
			ErrMembershipInvitationAccepted
	}

	if !invitation.ExpiresAt.Valid ||
		!invitation.ExpiresAt.Time.After(time.Now()) {
		return AcceptMembershipInvitationResult{},
			ErrMembershipInvitationExpired
	}

	displayName, passwordHash, accountSetupProvided, err :=
		prepareInvitationAccountSetup(input)
	if err != nil {
		return AcceptMembershipInvitationResult{}, err
	}

	_, err = queries.GetTenantMembershipByEmail(
		ctx,
		store.GetTenantMembershipByEmailParams{
			TenantID: invitation.TenantID,
			Email:    invitation.Email,
		},
	)
	if err == nil {
		return AcceptMembershipInvitationResult{},
			ErrMemberAlreadyExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return AcceptMembershipInvitationResult{}, fmt.Errorf(
			"check accepted tenant membership: %w",
			err,
		)
	}

	var userID pgtype.UUID
	hasPassword := false

	if accountSetupProvided {
		createdUser, createErr :=
			queries.CreateUserForInvitation(
				ctx,
				store.CreateUserForInvitationParams{
					Email:       invitation.Email,
					DisplayName: displayName,
				},
			)

		switch {
		case createErr == nil:
			userID = createdUser.ID

		case errors.Is(createErr, pgx.ErrNoRows):
			// Another account already owns this global email.
			// Reload it below while remaining in this transaction.

		default:
			return AcceptMembershipInvitationResult{},
				fmt.Errorf(
					"create invited user: %w",
					createErr,
				)
		}
	}

	if !userID.Valid {
		existingUser, loadErr :=
			queries.GetUserForInvitationAcceptance(
				ctx,
				invitation.Email,
			)
		if errors.Is(loadErr, pgx.ErrNoRows) {
			return AcceptMembershipInvitationResult{},
				ErrInvitationAccountSetupRequired
		}
		if loadErr != nil {
			return AcceptMembershipInvitationResult{},
				fmt.Errorf(
					"load invited user: %w",
					loadErr,
				)
		}

		if existingUser.Status != "active" {
			return AcceptMembershipInvitationResult{},
				ErrInvitedUserUnavailable
		}

		userID = existingUser.ID
		hasPassword = existingUser.HasPassword
	}

	if !hasPassword {
		if !accountSetupProvided {
			return AcceptMembershipInvitationResult{},
				ErrInvitationAccountSetupRequired
		}

		err = queries.CreatePasswordCredential(
			ctx,
			store.CreatePasswordCredentialParams{
				UserID:       userID,
				PasswordHash: passwordHash,
			},
		)
		if err != nil {
			return AcceptMembershipInvitationResult{},
				fmt.Errorf(
					"create invited user password: %w",
					err,
				)
		}
	}

	verifiedRows, err :=
		queries.MarkUserEmailVerifiedFromInvitation(
			ctx,
			userID,
		)
	if err != nil {
		return AcceptMembershipInvitationResult{},
			fmt.Errorf(
				"verify invited user email: %w",
				err,
			)
	}
	if verifiedRows != 1 {
		return AcceptMembershipInvitationResult{},
			ErrInvitedUserUnavailable
	}

	membership, err := queries.CreateActiveMembership(
		ctx,
		store.CreateActiveMembershipParams{
			TenantID: invitation.TenantID,
			UserID:   userID,
		},
	)
	if err != nil {
		return AcceptMembershipInvitationResult{},
			fmt.Errorf(
				"create accepted membership: %w",
				err,
			)
	}

	err = queries.AssignRoleToMembership(
		ctx,
		store.AssignRoleToMembershipParams{
			TenantID:     invitation.TenantID,
			MembershipID: membership.ID,
			RoleID:       invitation.RoleID,
		},
	)
	if err != nil {
		return AcceptMembershipInvitationResult{},
			fmt.Errorf(
				"assign invited membership role: %w",
				err,
			)
	}

	acceptedInvitation, err :=
		queries.MarkMembershipInvitationAccepted(
			ctx,
			store.MarkMembershipInvitationAcceptedParams{
				UserID:       userID,
				InvitationID: invitation.ID,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return AcceptMembershipInvitationResult{},
			ErrMembershipInvitationExpired
	}
	if err != nil {
		return AcceptMembershipInvitationResult{},
			fmt.Errorf(
				"consume membership invitation: %w",
				err,
			)
	}

	if !acceptedInvitation.AcceptedAt.Valid {
		return AcceptMembershipInvitationResult{}, errors.New(
			"accepted membership invitation has no timestamp",
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return AcceptMembershipInvitationResult{},
			fmt.Errorf(
				"commit invitation acceptance: %w",
				err,
			)
	}

	return AcceptMembershipInvitationResult{
		TenantID:     invitation.TenantID,
		MembershipID: membership.ID,
		UserID:       userID,
		Email:        invitation.Email,
	}, nil
}

func prepareInvitationAccountSetup(
	input AcceptMembershipInvitationInput,
) (
	displayName string,
	passwordHash string,
	provided bool,
	err error,
) {
	displayName = strings.TrimSpace(input.DisplayName)
	provided = displayName != "" || input.Password != ""

	if !provided {
		return "", "", false, nil
	}

	if !validName(displayName) ||
		len(input.Password) < minPasswordLength ||
		len(input.Password) > maxPasswordLength {
		return "", "", false,
			ErrInvalidInvitationAccountSetup
	}

	passwordHash, err = HashPassword(input.Password)
	if err != nil {
		return "", "", false, fmt.Errorf(
			"hash invited user password: %w",
			err,
		)
	}

	return displayName, passwordHash, true, nil
}
