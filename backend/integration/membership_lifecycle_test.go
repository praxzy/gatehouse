package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

type recordingMembershipInvitationSender struct {
	deliveries []auth.MembershipInvitationDelivery
}

func (
	sender *recordingMembershipInvitationSender,
) SendMembershipInvitation(
	_ context.Context,
	delivery auth.MembershipInvitationDelivery,
) error {
	sender.deliveries = append(
		sender.deliveries,
		delivery,
	)

	return nil
}

func TestMembershipInvitationAndOffboardingLifecycle(
	t *testing.T,
) {
	ctx := context.Background()
	invitationSender :=
		&recordingMembershipInvitationSender{}

	authentication, pool :=
		newAuthenticationTestServiceWithSenders(
			t,
			ctx,
			discardEmailVerificationSender{},
			invitationSender,
		)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Lifecycle Company",
			TenantSlug:  "lifecycle-company",
			Email:       "owner@lifecycle.test",
			DisplayName: "Lifecycle Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register lifecycle tenant: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: authentication,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	ownerCookie := loginLifecycleUser(
		t,
		router,
		"lifecycle-company",
		"owner@lifecycle.test",
		"correct horse battery staple",
	)

	memberRoleID := loadLifecycleRoleID(
		t,
		ctx,
		pool,
		registration.TenantID,
		"member",
	)

	inviteResponse := performMFAJSONRequest(
		t,
		router,
		"/api/v1/members",
		map[string]string{
			"email":   "member@lifecycle.test",
			"role_id": lifecycleUUID(t, memberRoleID),
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		inviteResponse,
		http.StatusCreated,
	)

	if len(invitationSender.deliveries) != 1 {
		t.Fatalf(
			"expected one invitation delivery, got %d",
			len(invitationSender.deliveries),
		)
	}

	expiredDelivery := invitationSender.deliveries[0]
	if expiredDelivery.Token == "" {
		t.Fatal("expected a raw invitation token")
	}
	if !expiredDelivery.ExpiresAt.After(time.Now()) {
		t.Fatal("expected invitation expiry in the future")
	}

	assertInvitationTokenStoredAsHash(
		t,
		ctx,
		pool,
		expiredDelivery,
	)

	previewResponse := performMFAJSONRequest(
		t,
		router,
		"/api/v1/invitations/preview",
		map[string]string{
			"token": expiredDelivery.Token,
		},
		nil,
	)

	previewBody := requireResponseStatus(
		t,
		previewResponse,
		http.StatusOK,
	)

	var preview struct {
		TenantSlug           string `json:"tenant_slug"`
		Email                string `json:"email"`
		RoleName             string `json:"role_name"`
		AccountSetupRequired bool   `json:"account_setup_required"`
	}
	if err := json.Unmarshal(previewBody, &preview); err != nil {
		t.Fatalf("decode invitation preview: %v", err)
	}

	if preview.TenantSlug != "lifecycle-company" ||
		preview.Email != "member@lifecycle.test" ||
		preview.RoleName != "Member" ||
		!preview.AccountSetupRequired {
		t.Fatalf(
			"unexpected invitation preview: %+v",
			preview,
		)
	}

	commandTag, err := pool.Exec(
		ctx,
		`
			UPDATE membership_invitations
			SET
				created_at = 
					now() - interval '3 seconds',
				updated_at =
					now() - interval '2 seconds',
				expires_at =
					now() - interval '1 second'
			WHERE tenant_id = $1
			  AND email = $2
			  AND accepted_at IS NULL
		`,
		registration.TenantID,
		"member@lifecycle.test",
	)
	if err != nil {
		t.Fatalf("expire membership invitation: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatal("expected one expired invitation")
	}

	expiredAcceptance := performMFAJSONRequest(
		t,
		router,
		"/api/v1/invitations/accept",
		map[string]string{
			"token":        expiredDelivery.Token,
			"display_name": "Lifecycle Member",
			"password":     "another secure password",
		},
		nil,
	)
	requireResponseStatus(
		t,
		expiredAcceptance,
		http.StatusGone,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`SELECT count(*) FROM users WHERE email = $1`,
		0,
		"member@lifecycle.test",
	)

	reinviteResponse := performMFAJSONRequest(
		t,
		router,
		"/api/v1/members",
		map[string]string{
			"email":   "member@lifecycle.test",
			"role_id": lifecycleUUID(t, memberRoleID),
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		reinviteResponse,
		http.StatusCreated,
	)

	if len(invitationSender.deliveries) != 2 {
		t.Fatalf(
			"expected two invitation deliveries, got %d",
			len(invitationSender.deliveries),
		)
	}

	activeDelivery := invitationSender.deliveries[1]
	if activeDelivery.Token == expiredDelivery.Token {
		t.Fatal("reinvitation reused the expired raw token")
	}

	acceptanceResponse := performMFAJSONRequest(
		t,
		router,
		"/api/v1/invitations/accept",
		map[string]string{
			"token":        activeDelivery.Token,
			"display_name": "Lifecycle Member",
			"password":     "another secure password",
		},
		nil,
	)

	acceptanceBody := requireResponseStatus(
		t,
		acceptanceResponse,
		http.StatusOK,
	)

	var acceptance struct {
		MembershipID string `json:"membership_id"`
		UserID       string `json:"user_id"`
		Email        string `json:"email"`
	}
	if err := json.Unmarshal(
		acceptanceBody,
		&acceptance,
	); err != nil {
		t.Fatalf("decode invitation acceptance: %v", err)
	}

	if acceptance.MembershipID == "" ||
		acceptance.UserID == "" ||
		acceptance.Email != "member@lifecycle.test" {
		t.Fatalf(
			"unexpected acceptance response: %+v",
			acceptance,
		)
	}

	reusedAcceptance := performMFAJSONRequest(
		t,
		router,
		"/api/v1/invitations/accept",
		map[string]string{
			"token": activeDelivery.Token,
		},
		nil,
	)
	requireResponseStatus(
		t,
		reusedAcceptance,
		http.StatusConflict,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM memberships AS membership
			JOIN users
			  ON users.id = membership.user_id
			JOIN membership_roles AS membership_role
			  ON membership_role.tenant_id =
			     membership.tenant_id
			 AND membership_role.membership_id =
			     membership.id
			JOIN roles
			  ON roles.tenant_id =
			     membership_role.tenant_id
			 AND roles.id = membership_role.role_id
			WHERE membership.id = $1
			  AND membership.tenant_id = $2
			  AND membership.status = 'active'
			  AND users.email = $3
			  AND users.email_verified_at IS NOT NULL
			  AND roles.role_key = 'member'
		`,
		1,
		acceptance.MembershipID,
		registration.TenantID,
		"member@lifecycle.test",
	)

	memberCookie := loginLifecycleUser(
		t,
		router,
		"lifecycle-company",
		"member@lifecycle.test",
		"another secure password",
	)

	memberListing := performRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/members",
		nil,
		memberCookie,
	)
	requireResponseStatus(
		t,
		memberListing,
		http.StatusOK,
	)

	ownerListing := performRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/members",
		nil,
		ownerCookie,
	)

	listingBody := requireResponseStatus(
		t,
		ownerListing,
		http.StatusOK,
	)

	var listing struct {
		Members []struct {
			Email   string `json:"email"`
			Status  string `json:"status"`
			RoleKey string `json:"role_key"`
		} `json:"members"`
		Invitations []struct {
			Email string `json:"email"`
		} `json:"invitations"`
	}
	if err := json.Unmarshal(listingBody, &listing); err != nil {
		t.Fatalf("decode member listing: %v", err)
	}

	if len(listing.Members) != 2 {
		t.Fatalf(
			"expected two members, got %d",
			len(listing.Members),
		)
	}
	if len(listing.Invitations) != 0 {
		t.Fatalf(
			"expected no open invitations, got %d",
			len(listing.Invitations),
		)
	}

	finalOwnerDisable := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPatch,
		"/api/v1/members/"+
			lifecycleUUID(
				t,
				registration.MembershipID,
			),
		map[string]string{
			"status": "disabled",
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		finalOwnerDisable,
		http.StatusConflict,
	)

	promoteMember := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPatch,
		"/api/v1/members/"+acceptance.MembershipID,
		map[string]string{
			"role_id": lifecycleUUID(
				t,
				registration.OwnerRoleID,
			),
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		promoteMember,
		http.StatusNoContent,
	)

	demoteMember := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPatch,
		"/api/v1/members/"+acceptance.MembershipID,
		map[string]string{
			"role_id": lifecycleUUID(
				t,
				memberRoleID,
			),
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		demoteMember,
		http.StatusNoContent,
	)

	disableMember := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPatch,
		"/api/v1/members/"+acceptance.MembershipID,
		map[string]string{
			"status": "disabled",
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		disableMember,
		http.StatusNoContent,
	)

	assertUnauthorizedCurrentUser(
		t,
		router,
		memberCookie,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM sessions
			WHERE membership_id = $1
			  AND revoked_at IS NOT NULL
			  AND revocation_reason =
			      'membership_disabled'
		`,
		1,
		acceptance.MembershipID,
	)
}

func performLifecycleJSONRequest(
	t *testing.T,
	router http.Handler,
	method string,
	target string,
	value any,
	sessionCookie *http.Cookie,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode lifecycle request: %v", err)
	}

	return performRequest(
		t,
		router,
		method,
		target,
		bytes.NewReader(body),
		sessionCookie,
	)
}

func loginLifecycleUser(
	t *testing.T,
	router http.Handler,
	tenantSlug string,
	email string,
	password string,
) *http.Cookie {
	t.Helper()

	response := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/login",
		map[string]string{
			"tenant_slug": tenantSlug,
			"email":       email,
			"password":    password,
		},
		nil,
	)

	requireResponseStatus(t, response, http.StatusOK)
	return requireSessionCookie(t, response)
}

func loadLifecycleRoleID(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID pgtype.UUID,
	roleKey string,
) pgtype.UUID {
	t.Helper()

	var roleID pgtype.UUID
	if err := pool.QueryRow(
		ctx,
		`
			SELECT id
			FROM roles
			WHERE tenant_id = $1
			  AND role_key = $2
		`,
		tenantID,
		roleKey,
	).Scan(&roleID); err != nil {
		t.Fatalf("load lifecycle role: %v", err)
	}

	return roleID
}

func lifecycleUUID(
	t *testing.T,
	value pgtype.UUID,
) string {
	t.Helper()

	if !value.Valid {
		t.Fatal("expected valid UUID")
	}

	return uuid.UUID(value.Bytes).String()
}

func assertInvitationTokenStoredAsHash(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	delivery auth.MembershipInvitationDelivery,
) {
	t.Helper()

	tokenBytes, err := base64.RawURLEncoding.DecodeString(
		delivery.Token,
	)
	if err != nil {
		t.Fatalf("decode delivered invitation token: %v", err)
	}

	expectedHash := sha256.Sum256(tokenBytes)

	var storedHash []byte
	if err := pool.QueryRow(
		ctx,
		`
			SELECT token_hash
			FROM membership_invitations
			WHERE email = $1
		`,
		delivery.RecipientEmail,
	).Scan(&storedHash); err != nil {
		t.Fatalf("load stored invitation hash: %v", err)
	}

	if !bytes.Equal(storedHash, expectedHash[:]) {
		t.Fatal("database did not store the invitation token hash")
	}

	if bytes.Contains(storedHash, []byte(delivery.Token)) {
		t.Fatal("database exposed the raw invitation token")
	}
}
