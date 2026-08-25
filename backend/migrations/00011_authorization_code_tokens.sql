-- +goose Up

ALTER TABLE authorization_transactions
ADD CONSTRAINT authorization_transactions_binding_unique
UNIQUE (
    tenant_id,
    id,
    application_id,
    client_id
);

ALTER TABLE sessions
ADD CONSTRAINT sessions_authorization_binding_unique
UNIQUE (
    tenant_id,
    id,
    membership_id,
    user_id
);


CREATE TABLE authorization_codes (
    code_hash                   bytea       PRIMARY KEY,
    authorization_transaction_id uuid       NOT NULL UNIQUE,
    tenant_id                   uuid        NOT NULL,
    application_id              uuid        NOT NULL,
    client_id                   text        NOT NULL,
    session_id                  uuid        NOT NULL,
    membership_id               uuid        NOT NULL,
    user_id                     uuid        NOT NULL,
    redirect_uri                text        NOT NULL,
    nonce                       text        NOT NULL,
    code_challenge              text        NOT NULL,
    code_challenge_method       text        NOT NULL,
    requested_scope             text[]      NOT NULL,
    authentication_time         timestamptz NOT NULL,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    expires_at                  timestamptz NOT NULL,
    consumed_at                 timestamptz,

    CONSTRAINT authorization_codes_transaction_fk
        FOREIGN KEY (
            tenant_id,
            authorization_transaction_id,
            application_id,
            client_id
        )
        REFERENCES authorization_transactions (
            tenant_id,
            id,
            application_id,
            client_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT authorization_codes_application_fk
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

    CONSTRAINT authorization_codes_redirect_uri_fk
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

    CONSTRAINT authorization_codes_session_fk
        FOREIGN KEY (
            tenant_id,
            session_id,
            membership_id,
            user_id
        )
        REFERENCES sessions (
            tenant_id,
            id,
            membership_id,
            user_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT authorization_codes_hash_valid
        CHECK (octet_length(code_hash) = 32),

    CONSTRAINT authorization_codes_client_id_valid
        CHECK (
            client_id ~ '^ghc_[A-Za-z0-9_-]{32}$'
        ),

    CONSTRAINT authorization_codes_redirect_uri_valid
        CHECK (
            redirect_uri = btrim(redirect_uri)
            AND length(redirect_uri) BETWEEN 1 AND 2048
            AND position('#' IN redirect_uri) = 0
        ),

    CONSTRAINT authorization_codes_nonce_valid
        CHECK (
            nonce = btrim(nonce)
            AND length(nonce) BETWEEN 16 AND 512
        ),

    CONSTRAINT authorization_codes_challenge_valid
        CHECK (
            code_challenge ~ '^[A-Za-z0-9_-]{43}$'
            AND code_challenge_method = 'S256'
        ),

    CONSTRAINT authorization_codes_scope_valid
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

    CONSTRAINT authorization_codes_authentication_time_valid
        CHECK (authentication_time <= created_at),

    CONSTRAINT authorization_codes_expiry_valid
        CHECK (
            expires_at > created_at
            AND expires_at <=
                created_at + interval '5 minutes'
        ),

    CONSTRAINT authorization_codes_consumption_valid
        CHECK (
            consumed_at IS NULL
            OR (
                consumed_at >= created_at
                AND consumed_at <= expires_at
            )
        ),

    CONSTRAINT authorization_codes_token_binding_unique
        UNIQUE (
            code_hash,
            tenant_id,
            application_id,
            client_id,
            session_id,
            membership_id,
            user_id
        )
);

CREATE INDEX authorization_codes_pending_expiry_idx
    ON authorization_codes (
        expires_at,
        code_hash
    )
    WHERE consumed_at IS NULL;


CREATE TABLE access_tokens (
    token_hash              bytea       PRIMARY KEY,
    authorization_code_hash bytea       NOT NULL UNIQUE,
    tenant_id               uuid        NOT NULL,
    application_id          uuid        NOT NULL,
    client_id               text        NOT NULL,
    session_id              uuid        NOT NULL,
    membership_id           uuid        NOT NULL,
    user_id                  uuid        NOT NULL,
    granted_scope            text[]      NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    expires_at               timestamptz NOT NULL,
    revoked_at               timestamptz,
    revocation_reason        text,

    CONSTRAINT access_tokens_authorization_code_fk
        FOREIGN KEY (
            authorization_code_hash,
            tenant_id,
            application_id,
            client_id,
            session_id,
            membership_id,
            user_id
        )
        REFERENCES authorization_codes (
            code_hash,
            tenant_id,
            application_id,
            client_id,
            session_id,
            membership_id,
            user_id
        )
        ON DELETE RESTRICT,

    CONSTRAINT access_tokens_hash_valid
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT access_tokens_client_id_valid
        CHECK (
            client_id ~ '^ghc_[A-Za-z0-9_-]{32}$'
        ),

    CONSTRAINT access_tokens_scope_valid
        CHECK (
            cardinality(granted_scope) BETWEEN 1 AND 3
            AND granted_scope <@
                ARRAY[
                    'openid',
                    'profile',
                    'email'
                ]::text[]
            AND 'openid' = ANY(granted_scope)
        ),

    CONSTRAINT access_tokens_expiry_valid
        CHECK (
            expires_at > created_at
            AND expires_at <=
                created_at + interval '1 hour'
        ),

    CONSTRAINT access_tokens_revocation_consistent
        CHECK (
            (
                revoked_at IS NULL
                AND revocation_reason IS NULL
            )
            OR
            (
                revoked_at IS NOT NULL
                AND revocation_reason IS NOT NULL
                AND length(btrim(revocation_reason))
                    BETWEEN 1 AND 100
            )
        )
);

CREATE INDEX access_tokens_active_expiry_idx
    ON access_tokens (
        expires_at,
        token_hash
    )
    WHERE revoked_at IS NULL;

CREATE INDEX access_tokens_user_idx
    ON access_tokens (
        tenant_id,
        user_id,
        created_at DESC
    );


-- +goose Down

DROP TABLE access_tokens;
DROP TABLE authorization_codes;

ALTER TABLE sessions
DROP CONSTRAINT sessions_authorization_binding_unique;

ALTER TABLE authorization_transactions
DROP CONSTRAINT authorization_transactions_binding_unique;
