-- name: UpsertPendingTOTPCredential :one
INSERT INTO totp_credentials (
    user_id,
    secret_ciphertext,
    secret_nonce,
    encryption_key_id,
    status
)
VALUES (
    sqlc.arg(user_id),
    sqlc.arg(secret_ciphertext),
    sqlc.arg(secret_nonce),
    sqlc.arg(encryption_key_id),
    'pending'
)
ON CONFLICT (user_id)
DO UPDATE SET
    secret_ciphertext = EXCLUDED.secret_ciphertext,
    secret_nonce = EXCLUDED.secret_nonce,
    encryption_key_id = EXCLUDED.encryption_key_id,
    status = 'pending',
    last_accepted_timestep = NULL,
    confirmed_at = NULL,
    updated_at = now()
WHERE totp_credentials.status = 'pending'
RETURNING
    user_id,
    secret_ciphertext,
    secret_nonce,
    encryption_key_id,
    status,
    last_accepted_timestep,
    confirmed_at,
    created_at,
    updated_at;


-- name: GetTOTPCredentialForUpdate :one
SELECT
    user_id,
    secret_ciphertext,
    secret_nonce,
    encryption_key_id,
    status,
    last_accepted_timestep,
    confirmed_at,
    created_at,
    updated_at
FROM totp_credentials
WHERE user_id = sqlc.arg(user_id)
FOR UPDATE;


-- name: ActivateTOTPCredential :execrows
UPDATE totp_credentials
SET
    status = 'active',
    last_accepted_timestep = sqlc.arg(accepted_timestep)::bigint,
    confirmed_at = now(),
    updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND status = 'pending';


-- name: ConsumeTOTPTimeStep :execrows
UPDATE totp_credentials
SET
    last_accepted_timestep = sqlc.arg(accepted_timestep)::bigint,
    updated_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND status = 'active'
  AND last_accepted_timestep < sqlc.arg(accepted_timestep)::bigint;


-- name: CreateMFARecoveryCode :exec
INSERT INTO mfa_recovery_codes (
    user_id,
    code_hash
)
VALUES (
    sqlc.arg(user_id),
    sqlc.arg(code_hash)
);


-- name: ConsumeMFARecoveryCode :execrows
UPDATE mfa_recovery_codes
SET consumed_at = now()
WHERE user_id = sqlc.arg(user_id)
  AND code_hash = sqlc.arg(code_hash)
  AND consumed_at IS NULL;


-- name: CountAvailableMFARecoveryCodes :one
SELECT count(*)
FROM mfa_recovery_codes
WHERE user_id = sqlc.arg(user_id)
  AND consumed_at IS NULL;