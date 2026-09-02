package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func TestWriterCreatesStructuredEvent(t *testing.T) {
	t.Parallel()

	sourceIP := netip.MustParseAddr("192.0.2.10")
	creator := &recordingEventCreator{
		result: store.AuditEvent{
			ID: testUUID(9),
		},
	}

	event := audit.Event{
		TenantID:          testUUID(1),
		ActorKind:         audit.ActorUser,
		ActorUserID:       testUUID(2),
		ActorMembershipID: testUUID(3),
		ApplicationID:     testUUID(4),
		SessionID:         testUUID(5),
		Type:              audit.EventAuthorizationDecision,
		Outcome:           audit.OutcomeSuccess,
		SubjectType:       "application",
		SubjectID:         testUUID(4),
		RequestID:         "request-123",
		SourceIP:          &sourceIP,
		UserAgent:         "Gatehouse test client",
		Metadata: audit.Metadata{
			"authentication_level": "mfa",
			"decision_reason":      "role_allowed",
		},
	}

	created, err := audit.NewWriter().Write(
		context.Background(),
		creator,
		event,
	)
	if err != nil {
		t.Fatalf("write audit event: %v", err)
	}

	if created.ID != testUUID(9) {
		t.Fatalf("unexpected created event ID: %#v", created.ID)
	}

	if creator.calls != 1 {
		t.Fatalf("expected one insert, got %d", creator.calls)
	}

	params := creator.params

	if params.TenantID != event.TenantID {
		t.Fatal("tenant ID was not preserved")
	}

	if params.ActorKind != string(audit.ActorUser) {
		t.Fatalf("unexpected actor kind %q", params.ActorKind)
	}

	if params.ActorUserID != event.ActorUserID {
		t.Fatal("actor user ID was not preserved")
	}

	if params.ActorMembershipID != event.ActorMembershipID {
		t.Fatal("actor membership ID was not preserved")
	}

	if params.ApplicationID != event.ApplicationID {
		t.Fatal("application ID was not preserved")
	}

	if params.SessionID != event.SessionID {
		t.Fatal("session ID was not preserved")
	}

	if params.EventType != string(event.Type) {
		t.Fatalf("unexpected event type %q", params.EventType)
	}

	if params.Outcome != string(event.Outcome) {
		t.Fatalf("unexpected outcome %q", params.Outcome)
	}

	if params.SubjectType == nil ||
		*params.SubjectType != event.SubjectType {
		t.Fatalf(
			"unexpected subject type %#v",
			params.SubjectType,
		)
	}

	if params.SubjectID != event.SubjectID {
		t.Fatal("subject ID was not preserved")
	}

	if params.RequestID == nil ||
		*params.RequestID != event.RequestID {
		t.Fatalf("unexpected request ID %#v", params.RequestID)
	}

	if params.SourceIp == nil ||
		*params.SourceIp != sourceIP {
		t.Fatalf("unexpected source IP %#v", params.SourceIp)
	}

	if params.UserAgent == nil ||
		*params.UserAgent != event.UserAgent {
		t.Fatalf("unexpected user agent %#v", params.UserAgent)
	}

	var metadata map[string]any
	if err := json.Unmarshal(params.Metadata, &metadata); err != nil {
		t.Fatalf("decode stored metadata: %v", err)
	}

	if metadata["authentication_level"] != "mfa" {
		t.Fatalf("unexpected metadata %#v", metadata)
	}

	if metadata["decision_reason"] != "role_allowed" {
		t.Fatalf("unexpected metadata %#v", metadata)
	}
}

func TestWriterStoresEmptyMetadataAsObject(t *testing.T) {
	t.Parallel()

	creator := &recordingEventCreator{}
	event := baseEvent(audit.EventSessionRevoked)

	_, err := audit.NewWriter().Write(
		context.Background(),
		creator,
		event,
	)
	if err != nil {
		t.Fatalf("write audit event: %v", err)
	}

	if string(creator.params.Metadata) != "{}" {
		t.Fatalf(
			"expected empty JSON object, got %s",
			creator.params.Metadata,
		)
	}
}

func TestWriterOmitsEmptyOptionalStrings(t *testing.T) {
	t.Parallel()

	creator := &recordingEventCreator{}
	event := baseEvent(audit.EventLogin)

	_, err := audit.NewWriter().Write(
		context.Background(),
		creator,
		event,
	)
	if err != nil {
		t.Fatalf("write audit event: %v", err)
	}

	if creator.params.SubjectType != nil {
		t.Fatal("expected nil subject type")
	}

	if creator.params.RequestID != nil {
		t.Fatal("expected nil request ID")
	}

	if creator.params.UserAgent != nil {
		t.Fatal("expected nil user agent")
	}
}

func TestWriterRejectsEventBeforeInsert(t *testing.T) {
	t.Parallel()

	creator := &recordingEventCreator{}
	event := baseEvent(audit.EventLogin)
	event.Metadata = audit.Metadata{
		"password": "do-not-store-this",
	}

	_, err := audit.NewWriter().Write(
		context.Background(),
		creator,
		event,
	)
	if !errors.Is(err, audit.ErrMetadataKeyForbidden) {
		t.Fatalf(
			"expected ErrMetadataKeyForbidden, got %v",
			err,
		)
	}

	if creator.calls != 0 {
		t.Fatalf(
			"expected no database insert, got %d",
			creator.calls,
		)
	}
}

func TestWriterPreservesStoreError(t *testing.T) {
	t.Parallel()

	storeError := errors.New("database unavailable")
	creator := &recordingEventCreator{
		err: storeError,
	}

	_, err := audit.NewWriter().Write(
		context.Background(),
		creator,
		baseEvent(audit.EventLogin),
	)
	if !errors.Is(err, storeError) {
		t.Fatalf("expected wrapped store error, got %v", err)
	}
}

func TestWriterRejectsNilCreator(t *testing.T) {
	t.Parallel()

	_, err := audit.NewWriter().Write(
		context.Background(),
		nil,
		baseEvent(audit.EventLogin),
	)
	if !errors.Is(
		err,
		audit.ErrInvalidWriterConfiguration,
	) {
		t.Fatalf(
			"expected ErrInvalidWriterConfiguration, got %v",
			err,
		)
	}
}

type recordingEventCreator struct {
	params store.CreateAuditEventParams
	result store.AuditEvent
	err    error
	calls  int
}

func (creator *recordingEventCreator) CreateAuditEvent(
	_ context.Context,
	params store.CreateAuditEventParams,
) (store.AuditEvent, error) {
	creator.calls++
	creator.params = params

	return creator.result, creator.err
}
