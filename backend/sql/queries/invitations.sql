-- name: UpsertMembershipInvitation :one
INSERT INTO membership_invitations (
    tenant_id,
    email,
    role_id,
    invited_by_membership_id,
    token_hash,
    expires_at
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(email),
    sqlc.arg(role_id),
    sqlc.arg(invited_by_membership_id),
    sqlc.arg(token_hash),
    now() + (
        sqlc.arg(lifetime_seconds)::integer
        * interval '1 second'
    )
)
ON CONFLICT (tenant_id, email)
DO UPDATE SET
    role_id = EXCLUDED.role_id,
    invited_by_membership_id =
        EXCLUDED.invited_by_membership_id,
    token_hash = EXCLUDED.token_hash,
    updated_at = now(),
    expires_at = EXCLUDED.expires_at,
    accepted_at = NULL,
    accepted_by_user_id = NULL
WHERE membership_invitations.accepted_at IS NULL
RETURNING
    id,
    tenant_id,
    email,
    role_id,
    invited_by_membership_id,
    token_hash,
    created_at,
    updated_at,
    expires_at,
    accepted_at,
    accepted_by_user_id;


-- name: GetMembershipInvitationPreview :one
SELECT
    invitation.id,
    invitation.tenant_id,
    tenant.name AS tenant_name,
    tenant.slug AS tenant_slug,
    invitation.email,
    invitation.role_id,
    role.name AS role_name,
    invitation.expires_at,
    invitation.accepted_at,
    NOT EXISTS (
        SELECT 1
        FROM users
        JOIN password_credentials
          ON password_credentials.user_id = users.id
        WHERE users.email = invitation.email
    )::boolean AS account_setup_required
FROM membership_invitations AS invitation
JOIN tenants AS tenant
  ON tenant.id = invitation.tenant_id
JOIN roles AS role
  ON role.tenant_id = invitation.tenant_id
 AND role.id = invitation.role_id
WHERE invitation.token_hash = sqlc.arg(token_hash);


-- name: GetMembershipInvitationForUpdate :one
SELECT
    id,
    tenant_id,
    email,
    role_id,
    invited_by_membership_id,
    token_hash,
    created_at,
    updated_at,
    expires_at,
    accepted_at,
    accepted_by_user_id
FROM membership_invitations
WHERE token_hash = sqlc.arg(token_hash)
FOR UPDATE;


-- name: GetUserForInvitationAcceptance :one
SELECT
    users.id,
    users.email,
    users.display_name,
    users.status,
    users.email_verified_at,
    EXISTS (
        SELECT 1
        FROM password_credentials
        WHERE password_credentials.user_id = users.id
    )::boolean AS has_password
FROM users
WHERE users.email = sqlc.arg(email)
FOR UPDATE;


-- name: MarkUserEmailVerifiedFromInvitation :execrows
UPDATE users
SET
    email_verified_at = COALESCE(
        email_verified_at,
        now()
    ),
    updated_at = now()
WHERE id = sqlc.arg(user_id)
  AND status = 'active';


-- name: MarkMembershipInvitationAccepted :one
UPDATE membership_invitations
SET
    accepted_at = now(),
    accepted_by_user_id = sqlc.arg(user_id),
    updated_at = now()
WHERE id = sqlc.arg(invitation_id)
  AND accepted_at IS NULL
  AND expires_at > now()
RETURNING
    id,
    tenant_id,
    email,
    role_id,
    invited_by_membership_id,
    token_hash,
    created_at,
    updated_at,
    expires_at,
    accepted_at,
    accepted_by_user_id;


-- name: ListOpenMembershipInvitations :many
SELECT
    invitation.id,
    invitation.email,
    invitation.role_id,
    role.name AS role_name,
    invitation.created_at,
    invitation.expires_at,
    (invitation.expires_at <= now())::boolean AS expired
FROM membership_invitations AS invitation
JOIN roles AS role
  ON role.tenant_id = invitation.tenant_id
 AND role.id = invitation.role_id
WHERE invitation.tenant_id = sqlc.arg(tenant_id)
  AND invitation.accepted_at IS NULL
ORDER BY invitation.created_at, invitation.id;

-- name: CreateUserForInvitation :one
INSERT INTO users (
    email,
    display_name
)
VALUES (
    sqlc.arg(email),
    sqlc.arg(display_name)
)
ON CONFLICT (email)
DO NOTHING
RETURNING
    id,
    email,
    display_name,
    status,
    created_at,
    updated_at,
    email_verified_at;