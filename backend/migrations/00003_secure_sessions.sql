-- +goose Up

ALTER TABLE memberships
    ADD CONSTRAINT memberships_tenant_id_user_id_unique
    UNIQUE (tenant_id, id, user_id);


CREATE TABLE sessions (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL,
    membership_id        uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    token_hash           bytea       NOT NULL,
    authentication_level text        NOT NULL DEFAULT 'password',
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL,
    revoked_at           timestamptz,
    revocation_reason    text,

    CONSTRAINT sessions_membership_fk
        FOREIGN KEY (tenant_id, membership_id, user_id)
        REFERENCES memberships (tenant_id, id, user_id)
        ON DELETE RESTRICT,

    CONSTRAINT sessions_token_hash_length
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT sessions_authentication_level_valid
        CHECK (
            authentication_level IN (
                'password',
                'mfa',
                'upstream'
            )
        ),

    CONSTRAINT sessions_expiry_valid
        CHECK (expires_at > created_at),

    CONSTRAINT sessions_revocation_consistent
        CHECK (
            (
                revoked_at IS NULL
                AND revocation_reason IS NULL
            )
            OR
            (
                revoked_at IS NOT NULL
                AND revocation_reason IS NOT NULL
                AND length(btrim(revocation_reason)) BETWEEN 1 AND 100
            )
        )
);


CREATE UNIQUE INDEX sessions_token_hash_unique
    ON sessions (token_hash);

CREATE INDEX sessions_active_user_idx
    ON sessions (tenant_id, user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_active_expiry_idx
    ON sessions (expires_at)
    WHERE revoked_at IS NULL;


-- +goose Down

DROP TABLE sessions;

ALTER TABLE memberships
    DROP CONSTRAINT memberships_tenant_id_user_id_unique;