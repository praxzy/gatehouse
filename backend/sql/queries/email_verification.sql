-- name: UpsertEmailVerificationToken :one
INSERT INTO email_verification_tokens (
    user_id,
    token_hash,
    expires_at
)
VALUES (
    sqlc.arg(user_id),
    sqlc.arg(token_hash),
    now() + (
        sqlc.arg(lifetime_seconds)::integer
        * interval '1 second'
    )
)
ON CONFLICT (user_id)
DO UPDATE SET
    token_hash = EXCLUDED.token_hash,
    created_at = now(),
    expires_at = EXCLUDED.expires_at,
    consumed_at = NULL
RETURNING
    user_id,
    token_hash,
    created_at,
    expires_at,
    consumed_at;


-- name: VerifyEmailByTokenHash :one
WITH consumed_token AS (
    UPDATE email_verification_tokens
    SET consumed_at = now()
    WHERE token_hash = sqlc.arg(token_hash)
      AND consumed_at IS NULL
      AND expires_at > now()
    RETURNING
        user_id,
        consumed_at
)
UPDATE users AS target_user
SET
    email_verified_at = consumed_token.consumed_at,
    updated_at = consumed_token.consumed_at
FROM consumed_token
WHERE target_user.id = consumed_token.user_id
  AND target_user.email_verified_at IS NULL
RETURNING
    target_user.id,
    target_user.email,
    target_user.email_verified_at;


-- name: GetUnverifiedUserByEmail :one
SELECT
    id,
    email
FROM users
WHERE email = sqlc.arg(email)
  AND email_verified_at IS NULL
  AND status = 'active';