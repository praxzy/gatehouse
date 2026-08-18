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

-- name: ListTenantMembers :many
SELECT
    membership.id AS membership_id,
    membership.user_id,
    users.email,
    users.display_name,
    membership.status,
    role.id AS role_id,
    role.role_key,
    role.name AS role_name,
    membership.created_at,
    membership.updated_at
FROM memberships AS membership
JOIN users
  ON users.id = membership.user_id
JOIN membership_roles AS membership_role
  ON membership_role.tenant_id = membership.tenant_id
 AND membership_role.membership_id = membership.id
JOIN roles AS role
  ON role.tenant_id = membership_role.tenant_id
 AND role.id = membership_role.role_id
WHERE membership.tenant_id = sqlc.arg(tenant_id)
ORDER BY
    lower(users.display_name),
    membership.id;


-- name: GetTenantMembershipByEmail :one
SELECT
    membership.id,
    membership.tenant_id,
    membership.user_id,
    membership.status,
    membership.created_at,
    membership.updated_at
FROM memberships AS membership
JOIN users
  ON users.id = membership.user_id
WHERE membership.tenant_id = sqlc.arg(tenant_id)
  AND users.email = sqlc.arg(email);


-- name: CreateActiveMembership :one
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
RETURNING
    id,
    tenant_id,
    user_id,
    status,
    created_at,
    updated_at;


-- name: GetMembershipForUpdate :one
SELECT
    id,
    tenant_id,
    user_id,
    status,
    created_at,
    updated_at
FROM memberships
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(membership_id)
FOR UPDATE;


-- name: IsOwnerMembership :one
SELECT EXISTS (
    SELECT 1
    FROM memberships AS membership
    JOIN membership_roles AS membership_role
      ON membership_role.tenant_id = membership.tenant_id
     AND membership_role.membership_id = membership.id
    JOIN roles AS role
      ON role.tenant_id = membership_role.tenant_id
     AND role.id = membership_role.role_id
    WHERE membership.tenant_id = sqlc.arg(tenant_id)
      AND membership.id = sqlc.arg(membership_id)
      AND membership.status = 'active'
      AND role.role_key = 'owner'
)::boolean;


-- name: LockOwnerRoleForUpdate :one
SELECT id
FROM roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND role_key = 'owner'
FOR UPDATE;


-- name: CountActiveOwners :one
SELECT count(DISTINCT membership.id)
FROM memberships AS membership
JOIN membership_roles AS membership_role
  ON membership_role.tenant_id = membership.tenant_id
 AND membership_role.membership_id = membership.id
JOIN roles AS role
  ON role.tenant_id = membership_role.tenant_id
 AND role.id = membership_role.role_id
WHERE membership.tenant_id = sqlc.arg(tenant_id)
  AND membership.status = 'active'
  AND role.role_key = 'owner';


-- name: MembershipHasOwnerRole :one
SELECT EXISTS (
    SELECT 1
    FROM membership_roles AS membership_role
    JOIN roles AS role
      ON role.tenant_id = membership_role.tenant_id
     AND role.id = membership_role.role_id
    WHERE membership_role.tenant_id = sqlc.arg(tenant_id)
      AND membership_role.membership_id =
          sqlc.arg(membership_id)
      AND role.role_key = 'owner'
)::boolean;


-- name: DeleteMembershipRoles :exec
DELETE FROM membership_roles
WHERE tenant_id = sqlc.arg(tenant_id)
  AND membership_id = sqlc.arg(membership_id);


-- name: UpdateMembershipStatus :one
UPDATE memberships
SET
    status = sqlc.arg(status),
    updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(membership_id)
RETURNING
    id,
    tenant_id,
    user_id,
    status,
    created_at,
    updated_at;