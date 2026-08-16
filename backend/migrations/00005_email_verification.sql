-- +goose Up

ALTER TABLE users
    ADD COLUMN email_verified_at timestamptz;

UPDATE users
SET email_verified_at = created_at
WHERE email_verified_at IS NULL;

ALTER TABLE users
    ADD CONSTRAINT users_email_verified_at_valid
    CHECK (
        email_verified_at IS NULL
        OR email_verified_at >= created_at
    );


CREATE TABLE email_verification_tokens (
    user_id      uuid        PRIMARY KEY,
    token_hash   bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,

    CONSTRAINT email_verification_tokens_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE,

    CONSTRAINT email_verification_tokens_hash_length
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT email_verification_tokens_expiry_valid
        CHECK (expires_at > created_at),

    CONSTRAINT email_verification_tokens_consumed_at_valid
        CHECK (
            consumed_at IS NULL
            OR consumed_at >= created_at
        )
);

CREATE UNIQUE INDEX email_verification_tokens_hash_unique
    ON email_verification_tokens (token_hash);

CREATE INDEX email_verification_tokens_expiry_idx
    ON email_verification_tokens (expires_at)
    WHERE consumed_at IS NULL;


-- +goose Down

DROP TABLE email_verification_tokens;

ALTER TABLE users
    DROP CONSTRAINT users_email_verified_at_valid;

ALTER TABLE users
    DROP COLUMN email_verified_at;