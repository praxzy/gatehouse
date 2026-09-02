package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var ErrInvalidWriterConfiguration = errors.New(
	"invalid audit writer configuration",
)

type EventCreator interface {
	CreateAuditEvent(
		ctx context.Context,
		arg store.CreateAuditEventParams,
	) (store.AuditEvent, error)
}

type EventWriter interface {
	Write(
		ctx context.Context,
		creator EventCreator,
		event Event,
	) (store.AuditEvent, error)
}

type Writer struct{}

func NewWriter() *Writer {
	return &Writer{}
}

func (writer *Writer) Write(
	ctx context.Context,
	creator EventCreator,
	event Event,
) (store.AuditEvent, error) {
	if creator == nil {
		return store.AuditEvent{}, ErrInvalidWriterConfiguration
	}

	event = EnrichFromContext(ctx, event)

	if err := Validate(event); err != nil {
		return store.AuditEvent{}, err
	}

	metadata := []byte("{}")
	if len(event.Metadata) > 0 {
		encodedMetadata, err := json.Marshal(event.Metadata)
		if err != nil {
			return store.AuditEvent{}, fmt.Errorf(
				"encode audit metadata: %w",
				err,
			)
		}

		metadata = encodedMetadata
	}

	createdEvent, err := creator.CreateAuditEvent(
		ctx,
		store.CreateAuditEventParams{
			TenantID:          event.TenantID,
			ActorKind:         string(event.ActorKind),
			ActorUserID:       event.ActorUserID,
			ActorMembershipID: event.ActorMembershipID,
			ApplicationID:     event.ApplicationID,
			SessionID:         event.SessionID,
			EventType:         string(event.Type),
			Outcome:           string(event.Outcome),
			SubjectType:       optionalString(event.SubjectType),
			SubjectID:         event.SubjectID,
			RequestID:         optionalString(event.RequestID),
			SourceIp:          event.SourceIP,
			UserAgent:         optionalString(event.UserAgent),
			Metadata:          metadata,
		},
	)
	if err != nil {
		return store.AuditEvent{}, fmt.Errorf(
			"write audit event: %w",
			err,
		)
	}

	return createdEvent, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}
