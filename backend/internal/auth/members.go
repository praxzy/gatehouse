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
	ErrInvalidMemberUpdate = errors.New(
		"invalid member update",
	)
	ErrMemberNotFound = errors.New(
		"member not found",
	)
	ErrMemberRoleNotFound = errors.New(
		"member role not found",
	)
	ErrFinalOwnerRequired = errors.New(
		"tenant must retain an active owner",
	)
)

type MemberSummary struct {
	MembershipID pgtype.UUID
	UserID       pgtype.UUID
	Email        string
	DisplayName  string
	Status       string
	RoleID       pgtype.UUID
	RoleKey      string
	RoleName     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type OpenInvitationSummary struct {
	InvitationID pgtype.UUID
	Email        string
	RoleID       pgtype.UUID
	RoleName     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Expired      bool
}

type MembershipRoleSummary struct {
	RoleID   pgtype.UUID
	RoleKey  string
	RoleName string
}

type MemberListResult struct {
	Members     []MemberSummary
	Invitations []OpenInvitationSummary
	Roles       []MembershipRoleSummary
}

type UpdateMemberInput struct {
	MembershipID pgtype.UUID
	RoleID       pgtype.UUID
	Status       string
}

func (service *Service) ListMembers(
	ctx context.Context,
	session SessionContext,
) (MemberListResult, error) {
	isOwner, err := service.queries.IsOwnerMembership(
		ctx,
		store.IsOwnerMembershipParams{
			TenantID:     session.TenantID,
			MembershipID: session.MembershipID,
		},
	)
	if err != nil {
		return MemberListResult{}, fmt.Errorf(
			"authorize member listing: %w",
			err,
		)
	}
	if !isOwner {
		return MemberListResult{},
			ErrMemberManagementForbidden
	}

	memberRows, err := service.queries.ListTenantMembers(
		ctx,
		session.TenantID,
	)
	if err != nil {
		return MemberListResult{}, fmt.Errorf(
			"list tenant members: %w",
			err,
		)
	}

	invitationRows, err :=
		service.queries.ListOpenMembershipInvitations(
			ctx,
			session.TenantID,
		)
	if err != nil {
		return MemberListResult{}, fmt.Errorf(
			"list membership invitations: %w",
			err,
		)
	}

	roleRows, err := service.queries.ListRoles(
		ctx,
		session.TenantID,
	)
	if err != nil {
		return MemberListResult{}, fmt.Errorf(
			"list tenant roles: %w",
			err,
		)
	}

	members := make(
		[]MemberSummary,
		0,
		len(memberRows),
	)
	for _, row := range memberRows {
		roleKey := ""
		if row.RoleKey != nil {
			roleKey = *row.RoleKey
		}

		members = append(members, MemberSummary{
			MembershipID: row.MembershipID,
			UserID:       row.UserID,
			Email:        row.Email,
			DisplayName:  row.DisplayName,
			Status:       row.Status,
			RoleID:       row.RoleID,
			RoleKey:      roleKey,
			RoleName:     row.RoleName,
			CreatedAt:    row.CreatedAt.Time,
			UpdatedAt:    row.UpdatedAt.Time,
		})
	}

	invitations := make(
		[]OpenInvitationSummary,
		0,
		len(invitationRows),
	)
	for _, row := range invitationRows {
		invitations = append(
			invitations,
			OpenInvitationSummary{
				InvitationID: row.ID,
				Email:        row.Email,
				RoleID:       row.RoleID,
				RoleName:     row.RoleName,
				CreatedAt:    row.CreatedAt.Time,
				ExpiresAt:    row.ExpiresAt.Time,
				Expired:      row.Expired,
			},
		)
	}

	roles := make(
		[]MembershipRoleSummary,
		0,
		len(roleRows),
	)
	for _, row := range roleRows {
		roleKey := ""
		if row.RoleKey != nil {
			roleKey = *row.RoleKey
		}

		roles = append(roles, MembershipRoleSummary{
			RoleID:   row.ID,
			RoleKey:  roleKey,
			RoleName: row.Name,
		})
	}

	return MemberListResult{
		Members:     members,
		Invitations: invitations,
		Roles:       roles,
	}, nil
}

func (service *Service) UpdateMember(
	ctx context.Context,
	session SessionContext,
	input UpdateMemberInput,
) error {
	status := strings.ToLower(
		strings.TrimSpace(input.Status),
	)
	roleChanging := input.RoleID.Valid

	if !input.MembershipID.Valid ||
		(!roleChanging && status == "") ||
		(status != "" &&
			status != "active" &&
			status != "disabled") {
		return ErrInvalidMemberUpdate
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return fmt.Errorf(
			"begin member update transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	_, err = queries.LockOwnerRoleForUpdate(
		ctx,
		session.TenantID,
	)
	if err != nil {
		return fmt.Errorf("lock owner role: %w", err)
	}

	isOwner, err := queries.IsOwnerMembership(
		ctx,
		store.IsOwnerMembershipParams{
			TenantID:     session.TenantID,
			MembershipID: session.MembershipID,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"authorize member update: %w",
			err,
		)
	}
	if !isOwner {
		return ErrMemberManagementForbidden
	}

	target, err := queries.GetMembershipForUpdate(
		ctx,
		store.GetMembershipForUpdateParams{
			TenantID:     session.TenantID,
			MembershipID: input.MembershipID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrMemberNotFound
	}
	if err != nil {
		return fmt.Errorf(
			"lock target membership: %w",
			err,
		)
	}

	currentlyOwner, err :=
		queries.MembershipHasOwnerRole(
			ctx,
			store.MembershipHasOwnerRoleParams{
				TenantID:     session.TenantID,
				MembershipID: target.ID,
			},
		)
	if err != nil {
		return fmt.Errorf(
			"load target owner state: %w",
			err,
		)
	}

	resultingOwner := currentlyOwner
	var replacementRole store.Role

	if roleChanging {
		replacementRole, err = queries.GetRoleByID(
			ctx,
			store.GetRoleByIDParams{
				TenantID: session.TenantID,
				RoleID:   input.RoleID,
			},
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMemberRoleNotFound
		}
		if err != nil {
			return fmt.Errorf(
				"load replacement member role: %w",
				err,
			)
		}

		resultingOwner =
			replacementRole.RoleKey != nil &&
				*replacementRole.RoleKey == "owner"
	}

	resultingActive := target.Status == "active"
	if status != "" {
		resultingActive = status == "active"
	}

	if target.Status == "active" &&
		currentlyOwner &&
		(!resultingActive || !resultingOwner) {
		activeOwners, err := queries.CountActiveOwners(
			ctx,
			session.TenantID,
		)
		if err != nil {
			return fmt.Errorf(
				"count active owners: %w",
				err,
			)
		}

		if activeOwners <= 1 {
			return ErrFinalOwnerRequired
		}
	}

	if roleChanging {
		err = queries.DeleteMembershipRoles(
			ctx,
			store.DeleteMembershipRolesParams{
				TenantID:     session.TenantID,
				MembershipID: target.ID,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"remove existing member roles: %w",
				err,
			)
		}

		err = queries.AssignRoleToMembership(
			ctx,
			store.AssignRoleToMembershipParams{
				TenantID:     session.TenantID,
				MembershipID: target.ID,
				RoleID:       replacementRole.ID,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"assign replacement member role: %w",
				err,
			)
		}
	}

	if status != "" {
		_, err = queries.UpdateMembershipStatus(
			ctx,
			store.UpdateMembershipStatusParams{
				Status:       status,
				TenantID:     session.TenantID,
				MembershipID: target.ID,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"update membership status: %w",
				err,
			)
		}
	}

	if status == "disabled" {
		_, err = queries.RevokeSessionsForMembership(
			ctx,
			store.RevokeSessionsForMembershipParams{
				TenantID:     session.TenantID,
				MembershipID: target.ID,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"revoke disabled member sessions: %w",
				err,
			)
		}
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit member update: %w",
			err,
		)
	}

	return nil
}
