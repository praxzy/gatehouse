-- name: GetRoleByID :one
SELECT id, tenant_id, role_key, name, description, is_system, created_at, updated_at
FROM roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(role_id);

-- name: ListRoles :many
SELECT id, tenant_id, role_key, name, description, is_system, created_at, updated_at
FROM roles
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name, id;

-- name: ListRolesForMembership :many
SELECT
    r.id,
    r.tenant_id,
    r.role_key,
    r.name,
    r.description,
    r.is_system,
    r.created_at,
    r.updated_at
FROM roles AS r
JOIN membership_roles AS mr
  ON mr.tenant_id = r.tenant_id
 AND mr.role_id = r.id
WHERE mr.tenant_id = sqlc.arg(tenant_id)
  AND mr.membership_id = sqlc.arg(membership_id)
ORDER BY r.name, r.id;

-- name: ListRolePermissions :many
SELECT permission
FROM role_permissions
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_id = sqlc.arg(role_id)
ORDER BY permission;

-- name: ListPermissionCatalog :many
SELECT
    permission,
    name,
    description
FROM permission_catalog
ORDER BY permission;


-- name: ListTenantRolesWithPermissions :many
SELECT
    role.id,
    role.tenant_id,
    role.role_key,
    role.name,
    role.description,
    role.is_system,
    role.created_at,
    role.updated_at,
    ARRAY(
        SELECT role_permission.permission
        FROM role_permissions AS role_permission
        WHERE role_permission.tenant_id = role.tenant_id
          AND role_permission.role_id = role.id
        ORDER BY role_permission.permission
    )::text[] AS permissions
FROM roles AS role
WHERE role.tenant_id = sqlc.arg(tenant_id)
ORDER BY
    role.is_system DESC,
    lower(role.name),
    role.id;


-- name: CreateCustomRole :one
INSERT INTO roles (
    tenant_id,
    name,
    description,
    is_system
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(name),
    sqlc.narg(description),
    false
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


-- name: GetCustomRoleForUpdate :one
SELECT
    id,
    tenant_id,
    role_key,
    name,
    description,
    is_system,
    created_at,
    updated_at
FROM roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(role_id)
  AND is_system = false
FOR UPDATE;


-- name: UpdateCustomRole :one
UPDATE roles
SET
    name = sqlc.arg(name),
    description = sqlc.narg(description),
    updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(role_id)
  AND is_system = false
RETURNING
    id,
    tenant_id,
    role_key,
    name,
    description,
    is_system,
    created_at,
    updated_at;


-- name: DeleteRolePermissions :exec
DELETE FROM role_permissions
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_id = sqlc.arg(role_id);


-- name: AddRolePermission :exec
INSERT INTO role_permissions (
    tenant_id,
    role_id,
    permission
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(role_id),
    sqlc.arg(permission)
);