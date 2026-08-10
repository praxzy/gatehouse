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