-- +goose Up

CREATE TABLE tenants (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    slug       text        NOT NULL,
    status     text        NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT tenants_name_not_blank
        CHECK (length(btrim(name)) BETWEEN 1 AND 200),

    CONSTRAINT tenants_slug_format
        CHECK (
            length(slug) BETWEEN 1 AND 63
            AND slug = lower(slug)
            AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
        ),

    CONSTRAINT tenants_status_valid
        CHECK (status IN ('active', 'suspended'))
);

CREATE UNIQUE INDEX tenants_slug_unique
    ON tenants (slug);


CREATE TABLE users (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text        NOT NULL,
    display_name text        NOT NULL,
    status       text        NOT NULL DEFAULT 'active',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_normalized
        CHECK (email = lower(btrim(email))),

    CONSTRAINT users_display_name_not_blank
        CHECK (length(btrim(display_name)) BETWEEN 1 AND 200),

    CONSTRAINT users_status_valid
        CHECK (status IN ('active', 'disabled'))
);

CREATE UNIQUE INDEX users_email_unique
    ON users (email);


CREATE TABLE memberships (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    status     text        NOT NULL DEFAULT 'invited',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT memberships_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT memberships_user_fk
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE RESTRICT,

    CONSTRAINT memberships_status_valid
        CHECK (status IN ('invited', 'active', 'disabled')),

    CONSTRAINT memberships_tenant_user_unique
        UNIQUE (tenant_id, user_id),

    CONSTRAINT memberships_tenant_id_id_unique
        UNIQUE (tenant_id, id)
);

CREATE INDEX memberships_tenant_status_idx
    ON memberships (tenant_id, status);


CREATE TABLE roles (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL,
    role_key    text,
    name        text        NOT NULL,
    description text,
    is_system   boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT roles_tenant_fk
        FOREIGN KEY (tenant_id)
        REFERENCES tenants (id)
        ON DELETE RESTRICT,

    CONSTRAINT roles_name_not_blank
        CHECK (
            name = btrim(name)
            AND length(name) BETWEEN 1 AND 100
        ),

    CONSTRAINT roles_system_key_consistent
        CHECK (
            (is_system = true AND role_key IS NOT NULL)
            OR
            (is_system = false AND role_key IS NULL)
        ),

    CONSTRAINT roles_key_format
        CHECK (
            role_key IS NULL
            OR role_key ~ '^[a-z][a-z0-9_]*$'
        ),

    CONSTRAINT roles_tenant_id_id_unique
        UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX roles_tenant_name_unique
    ON roles (tenant_id, lower(name));

CREATE UNIQUE INDEX roles_tenant_key_unique
    ON roles (tenant_id, role_key)
    WHERE role_key IS NOT NULL;


CREATE TABLE membership_roles (
    tenant_id    uuid        NOT NULL,
    membership_id uuid       NOT NULL,
    role_id      uuid        NOT NULL,
    assigned_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, membership_id, role_id),

    CONSTRAINT membership_roles_membership_fk
        FOREIGN KEY (tenant_id, membership_id)
        REFERENCES memberships (tenant_id, id)
        ON DELETE CASCADE,

    CONSTRAINT membership_roles_role_fk
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE
);


CREATE TABLE role_permissions (
    tenant_id  uuid        NOT NULL,
    role_id    uuid        NOT NULL,
    permission text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, role_id, permission),

    CONSTRAINT role_permissions_role_fk
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE,

    CONSTRAINT role_permissions_name_not_blank
        CHECK (length(btrim(permission)) BETWEEN 1 AND 100)
);


-- +goose Down

DROP TABLE role_permissions;
DROP TABLE membership_roles;
DROP TABLE roles;
DROP TABLE memberships;
DROP TABLE users;
DROP TABLE tenants;