package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

const maxAuthenticationBodyBytes = 64 * 1024
const timeFormat = time.RFC3339

type AuthenticationService interface {
	Register(
		ctx context.Context,
		input auth.RegisterInput,
	) (auth.RegisterResult, error)

	AuthenticateAndCreateSession(
		ctx context.Context,
		input auth.AuthenticateInput,
	) (auth.AuthenticateResult, error)

	ResolveSession(
		ctx context.Context,
		rawToken string,
	) (auth.SessionContext, error)

	RevokeSession(
		ctx context.Context,
		session auth.SessionContext,
		reason string,
	) error

	VerifyEmail(
		ctx context.Context,
		rawToken string,
	) (auth.VerifyEmailResult, error)

	BeginTOTPEnrollment(
		ctx context.Context,
		session auth.SessionContext,
	) (auth.TOTPEnrollmentResult, error)

	ConfirmTOTPEnrollment(
		ctx context.Context,
		session auth.SessionContext,
		code string,
	) (auth.MFAEnrollmentConfirmation, error)

	CompleteMFAWithTOTP(
		ctx context.Context,
		session auth.SessionContext,
		code string,
	) (auth.MFAChallengeResult, error)

	CompleteMFAWithRecoveryCode(
		ctx context.Context,
		session auth.SessionContext,
		code string,
	) (auth.MFAChallengeResult, error)

	PreviewMembershipInvitation(
		ctx context.Context,
		rawToken string,
	) (auth.MembershipInvitationPreview, error)

	AcceptMembershipInvitation(
		ctx context.Context,
		input auth.AcceptMembershipInvitationInput,
	) (auth.AcceptMembershipInvitationResult, error)

	ListMembers(
		ctx context.Context,
		session auth.SessionContext,
	) (auth.MemberListResult, error)

	InviteMember(
		ctx context.Context,
		session auth.SessionContext,
		input auth.InviteMemberInput,
	) (auth.InviteMemberResult, error)

	UpdateMember(
		ctx context.Context,
		session auth.SessionContext,
		input auth.UpdateMemberInput,
	) error

	ListRoles(
		ctx context.Context,
		session auth.SessionContext,
	) (auth.RoleListResult, error)

	CreateRole(
		ctx context.Context,
		session auth.SessionContext,
		input auth.CreateRoleInput,
	) (auth.RoleSummary, error)

	UpdateRole(
		ctx context.Context,
		session auth.SessionContext,
		input auth.UpdateRoleInput,
	) (auth.RoleSummary, error)
}

type authHandler struct {
	authentication AuthenticationService
	sessionCookie  SessionCookie
}

type registerRequest struct {
	TenantName  string `json:"tenant_name"`
	TenantSlug  string `json:"tenant_slug"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type registerResponse struct {
	TenantID     string `json:"tenant_id"`
	UserID       string `json:"user_id"`
	MembershipID string `json:"membership_id"`
	OwnerRoleID  string `json:"owner_role_id"`
}

type loginRequest struct {
	TenantSlug string `json:"tenant_slug"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type loginResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	ExpiresAt string `json:"expires_at"`
}

type currentUserCapabilitiesResponse struct {
	ManageMembers bool `json:"manage_members"`
}

type currentUserResponse struct {
	UserID              string                          `json:"user_id"`
	Email               string                          `json:"email"`
	DisplayName         string                          `json:"display_name"`
	TenantID            string                          `json:"tenant_id"`
	TenantName          string                          `json:"tenant_name"`
	TenantSlug          string                          `json:"tenant_slug"`
	MembershipID        string                          `json:"membership_id"`
	AuthenticationLevel string                          `json:"authentication_level"`
	SessionExpiresAt    string                          `json:"session_expires_at"`
	MFARequired         bool                            `json:"mfa_required"`
	MFAEnrolled         bool                            `json:"mfa_enrolled"`
	FullyAuthenticated  bool                            `json:"fully_authenticated"`
	Capabilities        currentUserCapabilitiesResponse `json:"capabilities"`
	Permissions         []string                        `json:"permissions"`
}

type errorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

func (handler authHandler) register(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var body registerRequest

	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err := handler.authentication.Register(
		request.Context(),
		auth.RegisterInput{
			TenantName:  body.TenantName,
			TenantSlug:  body.TenantSlug,
			Email:       body.Email,
			DisplayName: body.DisplayName,
			Password:    body.Password,
		},
	)

	switch {
	case errors.Is(err, auth.ErrInvalidRegistration):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid registration",
		)
		return

	case errors.Is(err, auth.ErrEmailAlreadyExists):
		writeError(
			writer,
			http.StatusConflict,
			"email is already registered",
		)
		return

	case errors.Is(err, auth.ErrTenantSlugUnavailable):
		writeError(
			writer,
			http.StatusConflict,
			"tenant slug is unavailable",
		)
		return

	case err != nil:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	writeJSON(
		writer,
		http.StatusCreated,
		registerResponse{
			TenantID:     formatUUID(result.TenantID),
			UserID:       formatUUID(result.UserID),
			MembershipID: formatUUID(result.MembershipID),
			OwnerRoleID:  formatUUID(result.OwnerRoleID),
		},
	)
}

func (handler authHandler) login(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var body loginRequest

	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}

	clientIP, err := directClientIP(request)
	if err != nil {
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	previousSession := ""
	if rawToken, err := handler.sessionCookie.Read(request); err == nil {
		previousSession = rawToken
	}

	result, err := handler.authentication.AuthenticateAndCreateSession(
		request.Context(),
		auth.AuthenticateInput{
			TenantSlug:      body.TenantSlug,
			Email:           body.Email,
			Password:        body.Password,
			ClientIP:        clientIP,
			PreviousSession: previousSession,
		},
	)
	if errors.Is(err, auth.ErrInvalidCredentials) {
		writeError(
			writer,
			http.StatusUnauthorized,
			"invalid email or password",
		)
		return
	}
	if errors.Is(
		err,
		auth.ErrEmailVerificationRequired,
	) {
		writeError(
			writer,
			http.StatusForbidden,
			"email verification required",
		)
		return
	}

	var rateLimitError *auth.LoginRateLimitedError
	if errors.As(err, &rateLimitError) {
		retryAfter := int(math.Ceil(
			rateLimitError.RetryAfter.Seconds(),
		))
		if retryAfter < 1 {
			retryAfter = 1
		}

		writer.Header().Set(
			"Retry-After",
			strconv.Itoa(retryAfter),
		)
		writeError(
			writer,
			http.StatusTooManyRequests,
			"too many login attempts",
		)
		return
	}

	if err != nil {
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	handler.sessionCookie.Set(
		writer,
		result.Session.Token,
		result.Session.ExpiresAt,
	)

	writeJSON(
		writer,
		http.StatusOK,
		loginResponse{
			UserID: formatUUID(result.UserID),
			Email:  result.Email,
			ExpiresAt: result.Session.ExpiresAt.UTC().Format(
				timeFormat,
			),
		},
	)
}

func (handler authHandler) verifyEmail(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var body verifyEmailRequest

	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	_, err := handler.authentication.VerifyEmail(
		request.Context(),
		strings.TrimSpace(body.Token),
	)

	switch {
	case errors.Is(
		err,
		auth.ErrInvalidEmailVerificationToken,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid or expired verification link",
		)
		return

	case err != nil:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func (handler authHandler) currentUser(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		currentUserResponse{
			UserID:              formatUUID(session.UserID),
			Email:               session.Email,
			DisplayName:         session.DisplayName,
			TenantID:            formatUUID(session.TenantID),
			TenantName:          session.TenantName,
			TenantSlug:          session.TenantSlug,
			MembershipID:        formatUUID(session.MembershipID),
			AuthenticationLevel: session.AuthenticationLevel,
			SessionExpiresAt: session.ExpiresAt.UTC().Format(
				timeFormat,
			),
			MFARequired:        session.MFARequired,
			MFAEnrolled:        session.MFAEnrolled,
			FullyAuthenticated: !session.MFARequired || session.AuthenticationLevel == "mfa",
			Capabilities: currentUserCapabilitiesResponse{
				ManageMembers: session.HasPermission(
					auth.PermissionMemberManage,
				),
			},
			Permissions: session.Permissions,
		},
	)
}

func (handler authHandler) logout(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	if err := handler.authentication.RevokeSession(
		request.Context(),
		session,
		"logout",
	); err != nil {
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	handler.sessionCookie.Clear(writer)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func decodeJSON(
	writer http.ResponseWriter,
	request *http.Request,
	target any,
) error {
	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxAuthenticationBodyBytes,
	)

	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain one JSON value")
	}

	return nil
}

func directClientIP(request *http.Request) (string, error) {
	remoteAddress := strings.TrimSpace(request.RemoteAddr)

	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}

	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}

	return address.Unmap().String(), nil
}

func formatUUID(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}

	return uuid.UUID(value.Bytes).String()
}

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(
	writer http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(
		writer,
		status,
		errorResponse{
			Error:     message,
			RequestID: writer.Header().Get(requestIDHeader),
		},
	)
}
