-- +goose Up

CREATE TABLE password_credentials (
    user_id       uuid        PRIMARY KEY,
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT password_credentials_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE,

    CONSTRAINT password_credentials_hash_format
        CHECK (password_hash LIKE '$argon2id$%')
);


-- +goose Down

DROP TABLE password_credentials;