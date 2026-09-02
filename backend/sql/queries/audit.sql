-- name: CreateAuditEvent :one
INSERT INTO audit_events (
    tenant_id,
    actor_kind,
    actor_user_id,
    actor_membership_id,
    application_id,
    session_id,
    event_type,
    outcome,
    subject_type,
    subject_id,
    request_id,
    source_ip,
    user_agent,
    metadata
)
VALUES (
    sqlc.narg(tenant_id),
    sqlc.arg(actor_kind),
    sqlc.narg(actor_user_id),
    sqlc.narg(actor_membership_id),
    sqlc.narg(application_id),
    sqlc.narg(session_id),
    sqlc.arg(event_type),
    sqlc.arg(outcome),
    sqlc.narg(subject_type),
    sqlc.narg(subject_id),
    sqlc.narg(request_id),
    sqlc.narg(source_ip),
    sqlc.narg(user_agent),
    sqlc.arg(metadata)
)
RETURNING
    id,
    tenant_id,
    actor_kind,
    actor_user_id,
    actor_membership_id,
    application_id,
    session_id,
    event_type,
    outcome,
    subject_type,
    subject_id,
    request_id,
    source_ip,
    user_agent,
    metadata,
    occurred_at;


-- name: ListTenantAuditEvents :many
SELECT
    audit_event.id,
    audit_event.tenant_id,
    audit_event.actor_kind,
    audit_event.actor_user_id,
    audit_event.actor_membership_id,
    actor.email AS actor_email,
    actor.display_name AS actor_display_name,
    audit_event.application_id,
    application.name AS application_name,
    audit_event.session_id,
    audit_event.event_type,
    audit_event.outcome,
    audit_event.subject_type,
    audit_event.subject_id,
    audit_event.request_id,
    audit_event.source_ip,
    audit_event.user_agent,
    audit_event.metadata,
    audit_event.occurred_at
FROM audit_events AS audit_event
LEFT JOIN users AS actor
  ON actor.id = audit_event.actor_user_id
LEFT JOIN applications AS application
  ON application.id = audit_event.application_id
WHERE audit_event.tenant_id = sqlc.arg(tenant_id)
  AND (
      sqlc.narg(actor_user_id)::uuid IS NULL
      OR audit_event.actor_user_id =
         sqlc.narg(actor_user_id)::uuid
  )
  AND (
      sqlc.narg(application_id)::uuid IS NULL
      OR audit_event.application_id =
         sqlc.narg(application_id)::uuid
  )
  AND (
      sqlc.narg(event_type)::text IS NULL
      OR audit_event.event_type =
         sqlc.narg(event_type)::text
  )
  AND (
      sqlc.narg(outcome)::text IS NULL
      OR audit_event.outcome =
         sqlc.narg(outcome)::text
  )
  AND (
      sqlc.narg(time_from)::timestamptz IS NULL
      OR audit_event.occurred_at >=
         sqlc.narg(time_from)::timestamptz
  )
  AND (
      sqlc.narg(time_until)::timestamptz IS NULL
      OR audit_event.occurred_at <
         sqlc.narg(time_until)::timestamptz
  )
  AND (
      sqlc.narg(cursor_occurred_at)::timestamptz IS NULL
      OR (
          audit_event.occurred_at,
          audit_event.id
      ) < (
          sqlc.narg(cursor_occurred_at)::timestamptz,
          sqlc.narg(cursor_id)::uuid
      )
  )
ORDER BY
    audit_event.occurred_at DESC,
    audit_event.id DESC
LIMIT sqlc.arg(page_size);
