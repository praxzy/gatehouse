-- name: CreateTenant :one
INSERT INTO tenants (name, slug)
VALUES (
    sqlc.arg(name),
    sqlc.arg(slug)
)
RETURNING id, name, slug, status, created_at, updated_at;


-- name: CreateUser :one
INSERT INTO users (email, display_name)
VALUES (
    sqlc.arg(email),
    sqlc.arg(display_name)
)
RETURNING id, email, display_name, status, created_at, updated_at;


-- name: CreatePasswordCredential :exec
INSERT INTO password_credentials (
    user_id,
    password_hash
)
VALUES (
    sqlc.arg(user_id),
    sqlc.arg(password_hash)
);


-- name: CreateOwnerMembership :one
INSERT INTO memberships (
    tenant_id,
    user_id,
    status
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(user_id),
    'active'
)
RETURNING id, tenant_id, user_id, status, created_at, updated_at;


-- name: CreateOwnerRole :one
INSERT INTO roles (
    tenant_id,
    role_key,
    name,
    description,
    is_system
)
VALUES (
    sqlc.arg(tenant_id),
    'owner',
    'Owner',
    'Full administrative access to the tenant',
    true
)
RETURNING id, tenant_id, role_key, name, description, is_system, created_at, updated_at;


-- name: AssignRoleToMembership :exec
INSERT INTO membership_roles (
    tenant_id,
    membership_id,
    role_id
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(membership_id),
    sqlc.arg(role_id)
);


-- name: GetPasswordLoginByEmail :one
SELECT
    u.id AS user_id,
    u.email,
    u.status,
    (u.email_verified_at IS NOT NULL)::boolean
        AS email_verified,
    pc.password_hash
FROM users AS u
JOIN password_credentials AS pc
  ON pc.user_id = u.id
WHERE u.email = sqlc.arg(email);

-- name: CreateMemberRole :one
INSERT INTO roles (
    tenant_id,
    role_key,
    name,
    description,
    is_system
)
VALUES (
    sqlc.arg(tenant_id),
    'member',
    'Member',
    'Standard tenant member',
    true
)
RETURNING
    id,
    tenant_id,
    role_key,
    name,
    description,
    is_system,
    created_at,
    updated_at;

-- name: GrantOwnerRolePermissions :exec
INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    sqlc.arg(tenant_id),
    sqlc.arg(role_id),
    permission
FROM permission_catalog
ON CONFLICT DO NOTHING;


-- name: GrantMemberRolePermissions :exec
INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
SELECT
    sqlc.arg(tenant_id),
    sqlc.arg(role_id),
    permission
FROM permission_catalog
WHERE permission IN (
    'tenant.read',
    'member.read'
)
ON CONFLICT DO NOTHING;