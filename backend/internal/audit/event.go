package audit

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
)

type EventType string
type ActorKind string
type Outcome string
type Metadata map[string]any

const (
	ActorUser        ActorKind = "user"
	ActorApplication ActorKind = "application"
	ActorSystem      ActorKind = "system"
	ActorAnonymous   ActorKind = "anonymous"
)

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

const (
	EventRegistration                      EventType = "auth.registration"
	EventEmailVerification                 EventType = "auth.email_verification"
	EventLogin                             EventType = "auth.login"
	EventMFAEnrollmentStarted              EventType = "mfa.enrollment_started"
	EventMFAEnrollmentConfirmed            EventType = "mfa.enrollment_confirmed"
	EventMFAChallenge                      EventType = "mfa.challenge"
	EventMFARecoveryCode                   EventType = "mfa.recovery_code"
	EventInvitationCreated                 EventType = "member.invitation_created"
	EventInvitationAccepted                EventType = "member.invitation_accepted"
	EventMemberRoleChanged                 EventType = "member.role_changed"
	EventMemberStatusChanged               EventType = "member.status_changed"
	EventRoleCreated                       EventType = "rbac.role_created"
	EventRoleUpdated                       EventType = "rbac.role_updated"
	EventApplicationCreated                EventType = "application.created"
	EventApplicationPolicyUpdated          EventType = "application.access_policy_updated"
	EventAuthorizationRequest              EventType = "authorization.request"
	EventAuthorizationDecision             EventType = "authorization.decision"
	EventAuthorizationCodeIssued           EventType = "authorization.code_issued"
	EventTokenExchange                     EventType = "token.exchange"
	EventSessionCreated                    EventType = "session.created"
	EventSessionRevoked                    EventType = "session.revoked"
	EventAuditExportRequested              EventType = "audit.export_requested"
	EventFederationConnectionSaved         EventType = "federation.connection_saved"
	EventFederationConnectionStatusChanged EventType = "federation.connection_status_changed"
	EventFederationIdentityMapped          EventType = "federation.identity_mapped"
	EventFederationIdentityUnmapped        EventType = "federation.identity_unmapped"
)

var (
	ErrInvalidEvent         = errors.New("invalid audit event")
	ErrUnknownEventType     = errors.New("unknown audit event type")
	ErrMetadataKeyForbidden = errors.New("audit metadata key is not allowed")
	ErrInvalidMetadataValue = errors.New("invalid audit metadata value")
)

type Event struct {
	TenantID          pgtype.UUID
	ActorKind         ActorKind
	ActorUserID       pgtype.UUID
	ActorMembershipID pgtype.UUID
	ApplicationID     pgtype.UUID
	SessionID         pgtype.UUID
	Type              EventType
	Outcome           Outcome
	SubjectType       string
	SubjectID         pgtype.UUID
	RequestID         string
	SourceIP          *netip.Addr
	UserAgent         string
	Metadata          Metadata
}

var metadataAllowlists = map[EventType]map[string]struct{}{
	EventRegistration: {
		"tenant_slug": {},
	},
	EventEmailVerification: {
		"verification_method": {},
		"failure_reason":      {},
	},
	EventLogin: {
		"authentication_method": {},
		"failure_reason":        {},
	},
	EventMFAEnrollmentStarted: {
		"expires_in_seconds": {},
	},
	EventMFAEnrollmentConfirmed: {
		"recovery_code_count": {},
		"failure_reason":      {},
	},
	EventMFAChallenge: {
		"challenge_method": {},
		"failure_reason":   {},
	},
	EventMFARecoveryCode: {
		"remaining_code_count": {},
		"failure_reason":       {},
	},
	EventInvitationCreated: {
		"role_id":            {},
		"expires_in_seconds": {},
	},
	EventInvitationAccepted: {
		"role_id": {},
	},
	EventMemberRoleChanged: {
		"previous_role_id": {},
		"new_role_id":      {},
	},
	EventMemberStatusChanged: {
		"previous_status":       {},
		"new_status":            {},
		"revoked_session_count": {},
	},
	EventRoleCreated: {
		"role_name":        {},
		"permission_count": {},
	},
	EventRoleUpdated: {
		"role_name":                 {},
		"previous_permission_count": {},
		"permission_count":          {},
	},
	EventApplicationCreated: {
		"client_type":        {},
		"access_mode":        {},
		"redirect_uri_count": {},
		"allowed_role_count": {},
	},
	EventApplicationPolicyUpdated: {
		"previous_access_mode": {},
		"new_access_mode":      {},
		"allowed_role_count":   {},
	},
	EventAuthorizationRequest: {
		"response_type":  {},
		"scope_count":    {},
		"has_nonce":      {},
		"failure_reason": {},
	},
	EventAuthorizationDecision: {
		"authentication_level": {},
		"decision_reason":      {},
	},
	EventAuthorizationCodeIssued: {
		"expires_in_seconds": {},
	},
	EventTokenExchange: {
		"grant_type":     {},
		"scope_count":    {},
		"failure_reason": {},
	},
	EventSessionCreated: {
		"authentication_level":     {},
		"rotated_previous_session": {},
	},
	EventSessionRevoked: {
		"revocation_reason": {},
	},
	EventAuditExportRequested: {
		"format": {},
	},
	EventFederationConnectionSaved: {
		"connection_status": {},
	},
	EventFederationConnectionStatusChanged: {
		"previous_status": {},
		"new_status":      {},
	},
	EventFederationIdentityMapped: {
		"membership_id": {},
	},
	EventFederationIdentityUnmapped: {
		"membership_id": {},
	},
}

func EventTypes() []EventType {
	eventTypes := make([]EventType, 0, len(metadataAllowlists))

	for eventType := range metadataAllowlists {
		eventTypes = append(eventTypes, eventType)
	}

	sort.Slice(eventTypes, func(left, right int) bool {
		return eventTypes[left] < eventTypes[right]
	})

	return eventTypes
}

func Validate(event Event) error {
	if _, exists := metadataAllowlists[event.Type]; !exists {
		return fmt.Errorf(
			"%w: %s",
			ErrUnknownEventType,
			event.Type,
		)
	}

	switch event.ActorKind {
	case ActorUser:
		if !event.ActorUserID.Valid || !event.TenantID.Valid {
			return fmt.Errorf(
				"%w: user actor requires tenant and user",
				ErrInvalidEvent,
			)
		}
	case ActorApplication:
		if !event.ApplicationID.Valid || !event.TenantID.Valid {
			return fmt.Errorf(
				"%w: application actor requires tenant and application",
				ErrInvalidEvent,
			)
		}
	case ActorSystem, ActorAnonymous:
		if event.ActorUserID.Valid {
			return fmt.Errorf(
				"%w: %s actor cannot have a user ID",
				ErrInvalidEvent,
				event.ActorKind,
			)
		}
	default:
		return fmt.Errorf(
			"%w: unknown actor kind %q",
			ErrInvalidEvent,
			event.ActorKind,
		)
	}

	switch event.Outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeDenied:
	default:
		return fmt.Errorf(
			"%w: unknown outcome %q",
			ErrInvalidEvent,
			event.Outcome,
		)
	}

	if event.ActorMembershipID.Valid && !event.ActorUserID.Valid {
		return fmt.Errorf(
			"%w: actor membership requires actor user",
			ErrInvalidEvent,
		)
	}

	if event.ApplicationID.Valid && !event.TenantID.Valid {
		return fmt.Errorf(
			"%w: application requires tenant",
			ErrInvalidEvent,
		)
	}

	if (event.SubjectType == "") != !event.SubjectID.Valid {
		return fmt.Errorf(
			"%w: subject type and ID must be provided together",
			ErrInvalidEvent,
		)
	}

	if event.SubjectType != "" {
		if len(event.SubjectType) > 100 ||
			strings.TrimSpace(event.SubjectType) != event.SubjectType {
			return fmt.Errorf(
				"%w: invalid subject type",
				ErrInvalidEvent,
			)
		}
	}

	if len(event.RequestID) > 100 {
		return fmt.Errorf(
			"%w: request ID is too long",
			ErrInvalidEvent,
		)
	}

	if !utf8.ValidString(event.UserAgent) ||
		len(event.UserAgent) > 512 {
		return fmt.Errorf(
			"%w: invalid user agent",
			ErrInvalidEvent,
		)
	}

	return validateMetadata(event.Type, event.Metadata)
}

func validateMetadata(
	eventType EventType,
	metadata Metadata,
) error {
	allowedKeys := metadataAllowlists[eventType]

	for key, value := range metadata {
		if _, allowed := allowedKeys[key]; !allowed {
			return fmt.Errorf(
				"%w: %s does not allow %q",
				ErrMetadataKeyForbidden,
				eventType,
				key,
			)
		}

		if err := validateMetadataValue(value); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}

	return nil
}

func validateMetadataValue(value any) error {
	switch typedValue := value.(type) {
	case string:
		if !utf8.ValidString(typedValue) ||
			len(typedValue) > 256 {
			return ErrInvalidMetadataValue
		}
	case bool:
		return nil
	case int:
		return nil
	case int32:
		return nil
	case int64:
		return nil
	case uint:
		return nil
	case uint32:
		return nil
	case uint64:
		return nil
	case []string:
		if len(typedValue) > 50 {
			return ErrInvalidMetadataValue
		}

		for _, item := range typedValue {
			if !utf8.ValidString(item) || len(item) > 100 {
				return ErrInvalidMetadataValue
			}
		}
	default:
		return ErrInvalidMetadataValue
	}

	return nil
}
