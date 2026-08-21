-- +goose Up

INSERT INTO permission_catalog (
    permission,
    name,
    description
)
VALUES
    (
        'application.read',
        'View applications',
        'View registered applications and their configuration.'
    ),
    (
        'application.manage',
        'Manage applications',
        'Register applications and change their configuration.'
    );

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    role.tenant_id,
    role.id,
    application_permission.permission
FROM roles AS role
CROSS JOIN (
    VALUES
        ('application.read'),
        ('application.manage')
) AS application_permission(permission)
WHERE role.role_key = 'owner'
  AND role.is_system = true
ON CONFLICT DO NOTHING;


CREATE TABLE applications (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                uuid        NOT NULL,
    name                     text        NOT NULL,
    description              text,
    client_id                text        NOT NULL,
    client_type              text        NOT NULL,
    client_secret_hash       bytea,
    client_secret_created_at timestamptz,
    status                   text        NOT NULL DEFAULT 'active',
    access_mode              text        NOT NULL DEFAULT 'all_active_members',
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT applications_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT applications_name_valid
        CHECK (
            name = btrim(name)
            AND length(name) BETWEEN 1 AND 100
        ),

    CONSTRAINT applications_description_valid
        CHECK (
            description IS NULL
            OR (
                description = btrim(description)
                AND length(description) BETWEEN 1 AND 300
            )
        ),

    CONSTRAINT applications_client_id_format
        CHECK (
            client_id ~
            '^ghc_[A-Za-z0-9_-]{32}$'
        ),

    CONSTRAINT applications_client_type_valid
        CHECK (
            client_type IN ('public', 'confidential')
        ),

    CONSTRAINT applications_client_secret_consistent
        CHECK (
            (
                client_type = 'public'
                AND client_secret_hash IS NULL
                AND client_secret_created_at IS NULL
            )
            OR
            (
                client_type = 'confidential'
                AND client_secret_hash IS NOT NULL
                AND octet_length(client_secret_hash) = 32
                AND client_secret_created_at IS NOT NULL
            )
        ),

    CONSTRAINT applications_status_valid
        CHECK (
            status IN ('active', 'disabled')
        ),

    CONSTRAINT applications_access_mode_valid
        CHECK (
            access_mode IN (
                'all_active_members',
                'allowed_roles'
            )
        ),

    CONSTRAINT applications_client_id_unique
        UNIQUE (client_id),

    CONSTRAINT applications_tenant_id_id_unique
        UNIQUE (tenant_id, id)
);

CREATE INDEX applications_tenant_created_idx
    ON applications (
        tenant_id,
        created_at DESC,
        id DESC
    );


CREATE TABLE redirect_uris (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid        NOT NULL,
    application_id uuid        NOT NULL,
    uri            text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT redirect_uris_application_fk
        FOREIGN KEY (tenant_id, application_id)
        REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,

    CONSTRAINT redirect_uris_uri_valid
        CHECK (
            uri = btrim(uri)
            AND length(uri) BETWEEN 1 AND 2048
            AND position('#' IN uri) = 0
        ),

    CONSTRAINT redirect_uris_application_uri_unique
        UNIQUE (tenant_id, application_id, uri),

    CONSTRAINT redirect_uris_tenant_id_id_unique
        UNIQUE (tenant_id, id)
);

CREATE INDEX redirect_uris_application_idx
    ON redirect_uris (
        tenant_id,
        application_id,
        created_at,
        id
    );


CREATE TABLE application_access (
    tenant_id      uuid        NOT NULL,
    application_id uuid        NOT NULL,
    role_id        uuid        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (
        tenant_id,
        application_id,
        role_id
    ),

    CONSTRAINT application_access_application_fk
        FOREIGN KEY (tenant_id, application_id)
        REFERENCES applications (tenant_id, id)
        ON DELETE CASCADE,

    CONSTRAINT application_access_role_fk
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX application_access_role_idx
    ON application_access (
        tenant_id,
        role_id,
        application_id
    );


-- +goose Down

DROP TABLE application_access;
DROP TABLE redirect_uris;
DROP TABLE applications;

DELETE FROM role_permissions
WHERE permission IN (
    'application.read',
    'application.manage'
);

DELETE FROM permission_catalog
WHERE permission IN (
    'application.read',
    'application.manage'
);
