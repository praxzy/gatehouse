-- +goose Up

ALTER TABLE tenants
    ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;


CREATE TABLE totp_credentials (
    user_id                 uuid        PRIMARY KEY,
    secret_ciphertext       bytea       NOT NULL,
    secret_nonce            bytea       NOT NULL,
    encryption_key_id       text        NOT NULL,
    status                  text        NOT NULL DEFAULT 'pending',
    last_accepted_timestep  bigint,
    confirmed_at            timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT totp_credentials_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE,

    CONSTRAINT totp_credentials_nonce_length
        CHECK (octet_length(secret_nonce) = 12),

    CONSTRAINT totp_credentials_ciphertext_length
        CHECK (octet_length(secret_ciphertext) >= 32),

    CONSTRAINT totp_credentials_key_id_valid
        CHECK (
            encryption_key_id = btrim(encryption_key_id)
            AND length(encryption_key_id) BETWEEN 1 AND 100
        ),

    CONSTRAINT totp_credentials_status_valid
        CHECK (status IN ('pending', 'active')),

    CONSTRAINT totp_credentials_state_consistent
        CHECK (
            (
                status = 'pending'
                AND confirmed_at IS NULL
                AND last_accepted_timestep IS NULL
            )
            OR
            (
                status = 'active'
                AND confirmed_at IS NOT NULL
                AND last_accepted_timestep IS NOT NULL
            )
        )
);


CREATE TABLE mfa_recovery_codes (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL,
    code_hash   bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz,

    CONSTRAINT mfa_recovery_codes_credential_fk
        FOREIGN KEY (user_id)
        REFERENCES totp_credentials (user_id)
        ON DELETE CASCADE,

    CONSTRAINT mfa_recovery_codes_hash_length
        CHECK (octet_length(code_hash) = 32),

    CONSTRAINT mfa_recovery_codes_user_hash_unique
        UNIQUE (user_id, code_hash),

    CONSTRAINT mfa_recovery_codes_consumed_at_valid
        CHECK (
            consumed_at IS NULL
            OR consumed_at >= created_at
        )
);


CREATE INDEX mfa_recovery_codes_available_idx
    ON mfa_recovery_codes (user_id)
    WHERE consumed_at IS NULL;


-- +goose Down

DROP TABLE mfa_recovery_codes;
DROP TABLE totp_credentials;

ALTER TABLE tenants
    DROP COLUMN mfa_required;