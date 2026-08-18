-- +goose Up

INSERT INTO roles (
    tenant_id,
    role_key,
    name,
    description,
    is_system
)
SELECT
    id,
    'member',
    'Member',
    'Standard tenant member',
    true
FROM tenants
ON CONFLICT (tenant_id, role_key)
    WHERE role_key IS NOT NULL
DO NOTHING;


CREATE TABLE membership_invitations (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                uuid        NOT NULL,
    email                    text        NOT NULL,
    role_id                  uuid        NOT NULL,
    invited_by_membership_id uuid        NOT NULL,
    token_hash               bytea       NOT NULL,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    expires_at               timestamptz NOT NULL,
    accepted_at              timestamptz,
    accepted_by_user_id      uuid,

    CONSTRAINT membership_invitations_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT membership_invitations_role_fk
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT membership_invitations_inviter_fk
        FOREIGN KEY (
            tenant_id,
            invited_by_membership_id
        )
        REFERENCES memberships (tenant_id, id)
        ON DELETE RESTRICT,

    CONSTRAINT membership_invitations_accepted_user_fk
        FOREIGN KEY (accepted_by_user_id)
        REFERENCES users (id)
        ON DELETE RESTRICT,

    CONSTRAINT membership_invitations_email_normalized
        CHECK (
            email = lower(btrim(email))
            AND length(email) BETWEEN 3 AND 254
        ),

    CONSTRAINT membership_invitations_token_hash_length
        CHECK (octet_length(token_hash) = 32),

    CONSTRAINT membership_invitations_expiry_valid
        CHECK (
            expires_at > created_at
            AND expires_at > updated_at
        ),

    CONSTRAINT membership_invitations_acceptance_consistent
        CHECK (
            (
                accepted_at IS NULL
                AND accepted_by_user_id IS NULL
            )
            OR
            (
                accepted_at IS NOT NULL
                AND accepted_by_user_id IS NOT NULL
                AND accepted_at <= expires_at
            )
        ),

    CONSTRAINT membership_invitations_tenant_email_unique
        UNIQUE (tenant_id, email)
);


CREATE UNIQUE INDEX membership_invitations_token_hash_unique
    ON membership_invitations (token_hash);

CREATE INDEX membership_invitations_pending_expiry_idx
    ON membership_invitations (expires_at)
    WHERE accepted_at IS NULL;


-- +goose Down

DROP TABLE membership_invitations;

DELETE FROM roles
WHERE role_key = 'member'
  AND is_system = true;