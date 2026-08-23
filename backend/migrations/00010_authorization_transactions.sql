-- +goose Up

ALTER TABLE applications
ADD CONSTRAINT applications_tenant_id_id_client_id_unique
UNIQUE (
    tenant_id,
    id,
    client_id
);


CREATE TABLE authorization_transactions (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL,
    application_id        uuid        NOT NULL,
    client_id             text        NOT NULL,
    redirect_uri          text        NOT NULL,
    state_hash            bytea       NOT NULL,
    nonce                 text        NOT NULL,
    code_challenge        text        NOT NULL,
    code_challenge_method text        NOT NULL,
    requested_scope       text[]      NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    consumed_at           timestamptz,

    CONSTRAINT authorization_transactions_application_fk
        FOREIGN KEY (
            tenant_id,
            application_id,
            client_id
        )
        REFERENCES applications (
            tenant_id,
            id,
            client_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT authorization_transactions_redirect_uri_fk
        FOREIGN KEY (
            tenant_id,
            application_id,
            redirect_uri
        )
        REFERENCES redirect_uris (
            tenant_id,
            application_id,
            uri
        )
        ON DELETE RESTRICT,

    CONSTRAINT authorization_transactions_client_id_valid
        CHECK (
            client_id ~ '^ghc_[A-Za-z0-9_-]{32}$'
        ),

    CONSTRAINT authorization_transactions_redirect_uri_valid
        CHECK (
            redirect_uri = btrim(redirect_uri)
            AND length(redirect_uri) BETWEEN 1 AND 2048
            AND position('#' IN redirect_uri) = 0
        ),

    CONSTRAINT authorization_transactions_state_hash_valid
        CHECK (
            octet_length(state_hash) = 32
        ),

    CONSTRAINT authorization_transactions_nonce_valid
        CHECK (
            nonce = btrim(nonce)
            AND length(nonce) BETWEEN 16 AND 512
        ),

    CONSTRAINT authorization_transactions_code_challenge_valid
        CHECK (
            code_challenge ~ '^[A-Za-z0-9_-]{43}$'
        ),

    CONSTRAINT authorization_transactions_code_challenge_method_valid
        CHECK (
            code_challenge_method = 'S256'
        ),

    CONSTRAINT authorization_transactions_scope_valid
        CHECK (
            cardinality(requested_scope) BETWEEN 1 AND 3
            AND requested_scope <@
                ARRAY[
                    'openid',
                    'profile',
                    'email'
                ]::text[]
            AND 'openid' = ANY(requested_scope)
        ),

    CONSTRAINT authorization_transactions_expiry_valid
        CHECK (
            expires_at > created_at
            AND expires_at <=
                created_at + interval '10 minutes'
        ),

    CONSTRAINT authorization_transactions_consumed_at_valid
        CHECK (
            consumed_at IS NULL
            OR (
                consumed_at >= created_at
                AND consumed_at <= expires_at
            )
        )
);

CREATE INDEX authorization_transactions_application_idx
    ON authorization_transactions (
        tenant_id,
        application_id,
        created_at DESC,
        id DESC
    );

CREATE INDEX authorization_transactions_pending_expiry_idx
    ON authorization_transactions (
        expires_at,
        id
    )
    WHERE consumed_at IS NULL;


-- +goose Down

DROP TABLE authorization_transactions;

ALTER TABLE applications
DROP CONSTRAINT applications_tenant_id_id_client_id_unique;