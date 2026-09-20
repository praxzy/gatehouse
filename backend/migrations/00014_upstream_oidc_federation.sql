-- +goose Up

INSERT INTO permission_catalog (
    permission,
    name,
    description
)
VALUES (
    'federation.manage',
    'Manage upstream federation',
    'Configure an upstream OIDC connection and identity mappings.'
);

INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    tenant_id,
    id,
    'federation.manage'
FROM roles
WHERE role_key = 'owner'
  AND is_system = true
ON CONFLICT DO NOTHING;


CREATE TABLE upstream_oidc_connections (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                uuid        NOT NULL,
    display_name             text        NOT NULL,
    issuer                   text        NOT NULL,
    client_id                text        NOT NULL,
    client_secret_ciphertext bytea       NOT NULL,
    client_secret_nonce      bytea       NOT NULL,
    encryption_key_id        text        NOT NULL,
    status                   text        NOT NULL DEFAULT 'enabled',
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT upstream_oidc_connections_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT upstream_oidc_connections_one_per_tenant
        UNIQUE (tenant_id),

    CONSTRAINT upstream_oidc_connections_tenant_id_id_unique
        UNIQUE (tenant_id, id),

    CONSTRAINT upstream_oidc_connections_display_name_valid
        CHECK (
            display_name = btrim(display_name)
            AND length(display_name) BETWEEN 1 AND 100
        ),

    CONSTRAINT upstream_oidc_connections_issuer_valid
        CHECK (
            issuer = btrim(issuer)
            AND length(issuer) BETWEEN 1 AND 2048
        ),

    CONSTRAINT upstream_oidc_connections_client_id_valid
        CHECK (length(btrim(client_id)) BETWEEN 1 AND 512),

    CONSTRAINT upstream_oidc_connections_ciphertext_valid
        CHECK (octet_length(client_secret_ciphertext) >= 16),

    CONSTRAINT upstream_oidc_connections_nonce_valid
        CHECK (octet_length(client_secret_nonce) = 12),

    CONSTRAINT upstream_oidc_connections_key_id_valid
        CHECK (
            encryption_key_id = btrim(encryption_key_id)
            AND length(encryption_key_id) BETWEEN 1 AND 100
        ),

    CONSTRAINT upstream_oidc_connections_status_valid
        CHECK (status IN ('enabled', 'disabled'))
);


CREATE TABLE upstream_oidc_identities (
    tenant_id     uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    subject       text        NOT NULL,
    membership_id uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (connection_id, subject),

    CONSTRAINT upstream_oidc_identities_connection_fk
        FOREIGN KEY (tenant_id, connection_id)
        REFERENCES upstream_oidc_connections (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT upstream_oidc_identities_membership_fk
        FOREIGN KEY (tenant_id, membership_id)
        REFERENCES memberships (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT upstream_oidc_identities_subject_valid
        CHECK (length(subject) BETWEEN 1 AND 512),

    CONSTRAINT upstream_oidc_identities_membership_unique
        UNIQUE (connection_id, membership_id)
);


CREATE TABLE upstream_oidc_transactions (
    state_hash                 bytea       PRIMARY KEY,
    tenant_id                  uuid        NOT NULL,
    connection_id              uuid        NOT NULL,
    nonce_hash                 bytea       NOT NULL,
    pkce_verifier_ciphertext   bytea       NOT NULL,
    pkce_verifier_nonce        bytea       NOT NULL,
    encryption_key_id          text        NOT NULL,
    return_path                text        NOT NULL DEFAULT '/',
    created_at                 timestamptz NOT NULL DEFAULT now(),
    expires_at                 timestamptz NOT NULL,
    consumed_at                timestamptz,

    CONSTRAINT upstream_oidc_transactions_connection_fk
        FOREIGN KEY (tenant_id, connection_id)
        REFERENCES upstream_oidc_connections (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT upstream_oidc_transactions_state_hash_length
        CHECK (octet_length(state_hash) = 32),

    CONSTRAINT upstream_oidc_transactions_nonce_hash_length
        CHECK (octet_length(nonce_hash) = 32),

    CONSTRAINT upstream_oidc_transactions_ciphertext_valid
        CHECK (octet_length(pkce_verifier_ciphertext) >= 16),

    CONSTRAINT upstream_oidc_transactions_nonce_valid
        CHECK (octet_length(pkce_verifier_nonce) = 12),

    CONSTRAINT upstream_oidc_transactions_key_id_valid
        CHECK (
            encryption_key_id = btrim(encryption_key_id)
            AND length(encryption_key_id) BETWEEN 1 AND 100
        ),

    CONSTRAINT upstream_oidc_transactions_return_path_valid
        CHECK (
            length(return_path) BETWEEN 1 AND 2048
            AND left(return_path, 1) = '/'
            AND left(return_path, 2) <> '//'
        ),

    CONSTRAINT upstream_oidc_transactions_expiry_valid
        CHECK (expires_at > created_at),

    CONSTRAINT upstream_oidc_transactions_consumed_at_valid
        CHECK (
            consumed_at IS NULL
            OR consumed_at >= created_at
        )
);

CREATE UNIQUE INDEX upstream_oidc_transactions_nonce_hash_unique
    ON upstream_oidc_transactions (nonce_hash);

CREATE INDEX upstream_oidc_transactions_active_expiry_idx
    ON upstream_oidc_transactions (expires_at)
    WHERE consumed_at IS NULL;


-- +goose Down

DROP TABLE upstream_oidc_transactions;
DROP TABLE upstream_oidc_identities;
DROP TABLE upstream_oidc_connections;

DELETE FROM role_permissions
WHERE permission = 'federation.manage';

DELETE FROM permission_catalog
WHERE permission = 'federation.manage';