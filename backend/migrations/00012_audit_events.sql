-- +goose Up

INSERT INTO permission_catalog (
    permission,
    name,
    description
)
VALUES (
    'audit.read',
    'View audit events',
    'View the tenant identity and access audit trail.'
);

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    role.tenant_id,
    role.id,
    'audit.read'
FROM roles AS role
WHERE role.role_key = 'owner'
  AND role.is_system = true
ON CONFLICT DO NOTHING;


CREATE TABLE audit_events (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid,
    actor_kind          text        NOT NULL,
    actor_user_id       uuid,
    actor_membership_id uuid,
    application_id      uuid,
    session_id          uuid,
    event_type          text        NOT NULL,
    outcome             text        NOT NULL,
    subject_type        text,
    subject_id          uuid,
    request_id          text,
    source_ip           inet,
    user_agent          text,
    metadata            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT audit_events_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT audit_events_actor_kind_valid
        CHECK (
            actor_kind IN (
                'user',
                'application',
                'system',
                'anonymous'
            )
        ),

    CONSTRAINT audit_events_actor_consistent
        CHECK (
            (
                actor_kind = 'user'
                AND actor_user_id IS NOT NULL
            )
            OR
            (
                actor_kind = 'application'
                AND application_id IS NOT NULL
            )
            OR
            (
                actor_kind IN ('system', 'anonymous')
                AND actor_user_id IS NULL
            )
        ),

    CONSTRAINT audit_events_event_type_valid
        CHECK (
            event_type ~
            '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
        ),

    CONSTRAINT audit_events_outcome_valid
        CHECK (
            outcome IN (
                'success',
                'failure',
                'denied'
            )
        ),

    CONSTRAINT audit_events_subject_consistent
        CHECK (
            (
                subject_type IS NULL
                AND subject_id IS NULL
            )
            OR
            (
                subject_type IS NOT NULL
                AND subject_id IS NOT NULL
                AND subject_type ~ '^[a-z][a-z0-9_]*$'
            )
        ),

    CONSTRAINT audit_events_request_id_valid
        CHECK (
            request_id IS NULL
            OR length(request_id) BETWEEN 1 AND 100
        ),

    CONSTRAINT audit_events_user_agent_valid
        CHECK (
            user_agent IS NULL
            OR length(user_agent) BETWEEN 1 AND 512
        ),

    CONSTRAINT audit_events_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),

    CONSTRAINT audit_events_metadata_size
        CHECK (octet_length(metadata::text) <= 4096)
);

CREATE INDEX audit_events_tenant_time_idx
    ON audit_events (
        tenant_id,
        occurred_at DESC,
        id DESC
    );

CREATE INDEX audit_events_tenant_actor_idx
    ON audit_events (
        tenant_id,
        actor_user_id,
        occurred_at DESC
    )
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX audit_events_tenant_application_idx
    ON audit_events (
        tenant_id,
        application_id,
        occurred_at DESC
    )
    WHERE application_id IS NOT NULL;

CREATE INDEX audit_events_tenant_type_idx
    ON audit_events (
        tenant_id,
        event_type,
        occurred_at DESC
    );

CREATE INDEX audit_events_tenant_outcome_idx
    ON audit_events (
        tenant_id,
        outcome,
        occurred_at DESC
    );


-- +goose Down

DROP TABLE audit_events;

DELETE FROM role_permissions
WHERE permission = 'audit.read';

DELETE FROM permission_catalog
WHERE permission = 'audit.read';