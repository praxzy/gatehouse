-- name: GetActiveMembershipForSessionCreation :one
SELECT
    m.tenant_id,
    m.id AS membership_id,
    m.user_id
FROM memberships AS m
JOIN tenants AS t
  ON t.id = m.tenant_id
JOIN users AS u
  ON u.id = m.user_id
WHERE m.user_id = sqlc.arg(user_id)
  AND t.slug = sqlc.arg(tenant_slug)
  AND m.status = 'active'
  AND t.status = 'active'
  AND u.status = 'active'
  AND u.email_verified_at IS NOT NULL
FOR SHARE OF m, t, u;


-- name: CreateSession :one
INSERT INTO sessions (
    tenant_id,
    membership_id,
    user_id,
    token_hash,
    authentication_level,
    expires_at
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(membership_id),
    sqlc.arg(user_id),
    sqlc.arg(token_hash),
    sqlc.arg(authentication_level),
    now() + (
        sqlc.arg(lifetime_seconds)::integer
        * interval '1 second'
    )
)
RETURNING
    id,
    tenant_id,
    membership_id,
    user_id,
    token_hash,
    authentication_level,
    created_at,
    expires_at,
    revoked_at,
    revocation_reason;


-- name: GetActiveSessionByTokenHash :one
SELECT
    s.id AS session_id,
    s.tenant_id,
    s.membership_id,
    s.user_id,
    s.authentication_level,
    s.created_at,
    s.expires_at,
    u.email,
    u.display_name,
    t.name AS tenant_name,
    t.slug AS tenant_slug,
    (
        t.mfa_required
        OR EXISTS (
            SELECT 1
            FROM totp_credentials AS active_totp
            WHERE active_totp.user_id = s.user_id
              AND active_totp.status = 'active'
        )
    )::boolean AS mfa_required,
    EXISTS (
        SELECT 1
        FROM totp_credentials AS active_totp
        WHERE active_totp.user_id = s.user_id
          AND active_totp.status = 'active'
    )::boolean AS mfa_enrolled
FROM sessions AS s
JOIN tenants AS t
  ON t.id = s.tenant_id
JOIN users AS u
  ON u.id = s.user_id
JOIN memberships AS m
  ON m.tenant_id = s.tenant_id
 AND m.id = s.membership_id
 AND m.user_id = s.user_id
WHERE s.token_hash = sqlc.arg(token_hash)
  AND s.revoked_at IS NULL
  AND s.expires_at > now()
  AND t.status = 'active'
  AND u.status = 'active'
  AND u.email_verified_at IS NOT NULL
  AND m.status = 'active';


-- name: RevokeSessionByID :execrows
UPDATE sessions
SET
    revoked_at = now(),
    revocation_reason = sqlc.arg(revocation_reason)
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(session_id)
  AND revoked_at IS NULL;


-- name: RevokeSessionByTokenHash :execrows
UPDATE sessions
SET
    revoked_at = now(),
    revocation_reason = sqlc.arg(revocation_reason)
WHERE token_hash = sqlc.arg(token_hash)
  AND revoked_at IS NULL;

-- name: RevokePasswordSessionForMFA :execrows
UPDATE sessions
SET
    revoked_at = now(),
    revocation_reason = 'rotated_after_mfa'
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(session_id)
  AND membership_id = sqlc.arg(membership_id)
  AND user_id = sqlc.arg(user_id)
  AND authentication_level = 'password'
  AND revoked_at IS NULL
  AND expires_at > now();