-- +goose Up

INSERT INTO permission_catalog (
    permission,
    name,
    description
)
VALUES (
    'audit.export',
    'Export audit events',
    'Create and retrieve tenant audit event exports.'
);

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    role.tenant_id,
    role.id,
    'audit.export'
FROM roles AS role
WHERE role.role_key = 'owner'
  AND role.is_system = true
ON CONFLICT DO NOTHING;


CREATE TABLE export_jobs (
    id                         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  uuid        NOT NULL,
    requested_by_membership_id uuid        NOT NULL,
    format                     text        NOT NULL,
    status                     text        NOT NULL DEFAULT 'queued',
    filter_actor_user_id       uuid,
    filter_application_id      uuid,
    filter_event_type          text,
    filter_outcome             text,
    time_from                  timestamptz,
    time_until                 timestamptz,
    snapshot_at                timestamptz NOT NULL DEFAULT now(),
    attempt_count              integer     NOT NULL DEFAULT 0,
    enqueued_at                timestamptz,
    lease_expires_at           timestamptz,
    output_object_key          text,
    last_error_code            text,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    completed_at               timestamptz,
    failed_at                  timestamptz,

    CONSTRAINT export_jobs_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT export_jobs_requester_fk
        FOREIGN KEY (tenant_id, requested_by_membership_id)
        REFERENCES memberships (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT export_jobs_format_valid
        CHECK (format IN ('csv', 'json')),

    CONSTRAINT export_jobs_status_valid
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),

    CONSTRAINT export_jobs_filter_event_type_valid
        CHECK (
            filter_event_type IS NULL
            OR filter_event_type ~
               '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
        ),

    CONSTRAINT export_jobs_filter_outcome_valid
        CHECK (
            filter_outcome IS NULL
            OR filter_outcome IN ('success', 'failure', 'denied')
        ),

    CONSTRAINT export_jobs_time_range_valid
        CHECK (
            time_from IS NULL
            OR time_until IS NULL
            OR time_from < time_until
        ),

    CONSTRAINT export_jobs_attempt_count_valid
        CHECK (attempt_count >= 0),

    CONSTRAINT export_jobs_last_error_code_valid
        CHECK (
            last_error_code IS NULL
            OR last_error_code ~ '^[a-z][a-z0-9_]{0,79}$'
        ),

    CONSTRAINT export_jobs_state_consistent
        CHECK (
            (
                status = 'queued'
                AND lease_expires_at IS NULL
                AND output_object_key IS NULL
                AND completed_at IS NULL
                AND failed_at IS NULL
            )
            OR (
                status = 'running'
                AND lease_expires_at IS NOT NULL
                AND output_object_key IS NULL
                AND completed_at IS NULL
                AND failed_at IS NULL
            )
            OR (
                status = 'completed'
                AND lease_expires_at IS NULL
                AND output_object_key IS NOT NULL
                AND completed_at IS NOT NULL
                AND failed_at IS NULL
            )
            OR (
                status = 'failed'
                AND lease_expires_at IS NULL
                AND output_object_key IS NULL
                AND completed_at IS NULL
                AND failed_at IS NOT NULL
            )
        )
);

CREATE INDEX export_jobs_tenant_created_idx
    ON export_jobs (tenant_id, created_at DESC, id DESC);

CREATE INDEX export_jobs_pending_enqueue_idx
    ON export_jobs (created_at, id)
    WHERE status = 'queued' AND enqueued_at IS NULL;


-- +goose Down

DROP TABLE export_jobs;

DELETE FROM role_permissions
WHERE permission = 'audit.export';

DELETE FROM permission_catalog
WHERE permission = 'audit.export';
