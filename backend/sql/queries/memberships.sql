-- name: GetMembershipByID :one
SELECT id, tenant_id, user_id, status, created_at, updated_at
FROM memberships
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(membership_id);

-- name: GetMembershipByUserID :one
SELECT id, tenant_id, user_id, status, created_at, updated_at
FROM memberships
WHERE tenant_id = sqlc.arg(tenant_id)
  AND user_id = sqlc.arg(user_id);

-- name: ListMemberships :many
SELECT id, tenant_id, user_id, status, created_at, updated_at
FROM memberships
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at, id;