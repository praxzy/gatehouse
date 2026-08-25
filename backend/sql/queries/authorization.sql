-- name: GetActiveApplicationForAuthorization :one
SELECT
    application.id AS application_id,
    application.tenant_id,
    tenant.slug AS tenant_slug,
    application.name,
    application.client_id,
    application.client_type,
    application.access_mode
FROM applications AS application
JOIN tenants AS tenant
  ON tenant.id = application.tenant_id
WHERE application.client_id =
      sqlc.arg(client_id)
  AND application.status = 'active'
  AND tenant.status = 'active'
  AND EXISTS (
      SELECT 1
      FROM redirect_uris AS redirect_uri
      WHERE redirect_uri.tenant_id =
            application.tenant_id
        AND redirect_uri.application_id =
            application.id
        AND redirect_uri.uri =
            sqlc.arg(redirect_uri)
  );


-- name: CreateAuthorizationTransaction :one
INSERT INTO authorization_transactions (
    tenant_id,
    application_id,
    client_id,
    redirect_uri,
    state_hash,
    nonce,
    code_challenge,
    code_challenge_method,
    requested_scope,
    expires_at
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(application_id),
    sqlc.arg(client_id),
    sqlc.arg(redirect_uri),
    sqlc.arg(state_hash),
    sqlc.arg(nonce),
    sqlc.arg(code_challenge),
    'S256',
    sqlc.arg(requested_scope),
    sqlc.arg(expires_at)
)
RETURNING
    id,
    tenant_id,
    application_id,
    client_id,
    redirect_uri,
    state_hash,
    nonce,
    code_challenge,
    code_challenge_method,
    requested_scope,
    created_at,
    expires_at,
    consumed_at;


-- name: GetAuthorizationTransactionByIDAndStateHash :one
SELECT
    transaction.id,
    transaction.tenant_id,
    transaction.application_id,
    transaction.client_id,
    transaction.redirect_uri,
    transaction.state_hash,
    transaction.nonce,
    transaction.code_challenge,
    transaction.code_challenge_method,
    transaction.requested_scope,
    transaction.created_at,
    transaction.expires_at,
    transaction.consumed_at,
    tenant.slug AS tenant_slug,
    tenant.status AS tenant_status,
    application.name AS application_name,
    application.status AS application_status,
    application.access_mode
FROM authorization_transactions AS transaction
JOIN applications AS application
  ON application.tenant_id =
     transaction.tenant_id
 AND application.id =
     transaction.application_id
 AND application.client_id =
     transaction.client_id
JOIN tenants AS tenant
  ON tenant.id = transaction.tenant_id
WHERE transaction.id =
      sqlc.arg(transaction_id)
  AND transaction.state_hash =
      sqlc.arg(state_hash);


-- name: EvaluateAuthorizationSession :one
SELECT
    session.authentication_level,
    (
        tenant.mfa_required
        OR EXISTS (
            SELECT 1
            FROM totp_credentials AS active_totp
            WHERE active_totp.user_id = session.user_id
              AND active_totp.status = 'active'
        )
    )::boolean AS mfa_required,
    EXISTS (
        SELECT 1
        FROM totp_credentials AS active_totp
        WHERE active_totp.user_id = session.user_id
          AND active_totp.status = 'active'
    )::boolean AS mfa_enrolled,
    (
        application.access_mode = 'all_active_members'
        OR (
            application.access_mode = 'allowed_roles'
            AND EXISTS (
                SELECT 1
                FROM membership_roles AS membership_role
                JOIN application_access AS access
                  ON access.tenant_id =
                     membership_role.tenant_id
                 AND access.role_id =
                     membership_role.role_id
                 AND access.application_id =
                     application.id
                WHERE membership_role.tenant_id =
                      membership.tenant_id
                  AND membership_role.membership_id =
                      membership.id
            )
        )
    )::boolean AS access_granted
FROM sessions AS session
JOIN tenants AS tenant
  ON tenant.id = session.tenant_id
JOIN users
  ON users.id = session.user_id
JOIN memberships AS membership
  ON membership.tenant_id = session.tenant_id
 AND membership.id = session.membership_id
 AND membership.user_id = session.user_id
JOIN applications AS application
  ON application.tenant_id = session.tenant_id
 AND application.id = sqlc.arg(application_id)
WHERE session.id = sqlc.arg(session_id)
  AND session.tenant_id = sqlc.arg(tenant_id)
  AND session.membership_id = sqlc.arg(membership_id)
  AND session.user_id = sqlc.arg(user_id)
  AND session.revoked_at IS NULL
  AND session.expires_at > now()
  AND tenant.status = 'active'
  AND users.status = 'active'
  AND users.email_verified_at IS NOT NULL
  AND membership.status = 'active'
  AND application.status = 'active';


-- name: ConsumeDeniedAuthorizationTransaction :execrows
UPDATE authorization_transactions
SET consumed_at = now()
WHERE id = sqlc.arg(transaction_id)
  AND tenant_id = sqlc.arg(tenant_id)
  AND application_id = sqlc.arg(application_id)
  AND state_hash = sqlc.arg(state_hash)
  AND consumed_at IS NULL
  AND expires_at > now();


-- name: IssueAuthorizationCode :one
WITH consumed_transaction AS (
    UPDATE authorization_transactions AS transaction
    SET consumed_at = now()
    WHERE transaction.id =
          sqlc.arg(transaction_id)
      AND transaction.tenant_id =
          sqlc.arg(tenant_id)
      AND transaction.application_id =
          sqlc.arg(application_id)
      AND transaction.state_hash =
          sqlc.arg(state_hash)
      AND transaction.consumed_at IS NULL
      AND transaction.expires_at > now()
      AND EXISTS (
          SELECT 1
          FROM sessions AS session
          JOIN tenants AS tenant
            ON tenant.id = session.tenant_id
          JOIN users AS users
            ON users.id = session.user_id
          JOIN memberships AS membership
            ON membership.tenant_id =
               session.tenant_id
           AND membership.id =
               session.membership_id
           AND membership.user_id =
               session.user_id
          JOIN applications AS application
            ON application.tenant_id =
               session.tenant_id
           AND application.id =
               transaction.application_id
           AND application.client_id =
               transaction.client_id
          WHERE session.id =
                sqlc.arg(session_id)
            AND session.tenant_id =
                transaction.tenant_id
            AND session.membership_id =
                sqlc.arg(membership_id)
            AND session.user_id =
                sqlc.arg(user_id)
            AND session.revoked_at IS NULL
            AND session.expires_at > now()
            AND tenant.status = 'active'
            AND users.status = 'active'
            AND users.email_verified_at IS NOT NULL
            AND membership.status = 'active'
            AND application.status = 'active'
            AND (
                session.authentication_level = 'mfa'
                OR (
                    tenant.mfa_required = false
                    AND NOT EXISTS (
                        SELECT 1
                        FROM totp_credentials AS active_totp
                        WHERE active_totp.user_id =
                              session.user_id
                          AND active_totp.status = 'active'
                    )
                )
            )
            AND (
                application.access_mode =
                    'all_active_members'
                OR (
                    application.access_mode =
                        'allowed_roles'
                    AND EXISTS (
                        SELECT 1
                        FROM membership_roles AS membership_role
                        JOIN application_access AS access
                          ON access.tenant_id =
                             membership_role.tenant_id
                         AND access.role_id =
                             membership_role.role_id
                         AND access.application_id =
                             application.id
                        WHERE membership_role.tenant_id =
                              membership.tenant_id
                          AND membership_role.membership_id =
                              membership.id
                    )
                )
            )
      )
    RETURNING
        transaction.id,
        transaction.tenant_id,
        transaction.application_id,
        transaction.client_id,
        transaction.redirect_uri,
        transaction.nonce,
        transaction.code_challenge,
        transaction.code_challenge_method,
        transaction.requested_scope
)
INSERT INTO authorization_codes (
    code_hash,
    authorization_transaction_id,
    tenant_id,
    application_id,
    client_id,
    session_id,
    membership_id,
    user_id,
    redirect_uri,
    nonce,
    code_challenge,
    code_challenge_method,
    requested_scope,
    authentication_time,
    expires_at
)
SELECT
    sqlc.arg(code_hash),
    consumed_transaction.id,
    consumed_transaction.tenant_id,
    consumed_transaction.application_id,
    consumed_transaction.client_id,
    session.id,
    session.membership_id,
    session.user_id,
    consumed_transaction.redirect_uri,
    consumed_transaction.nonce,
    consumed_transaction.code_challenge,
    consumed_transaction.code_challenge_method,
    consumed_transaction.requested_scope,
    session.created_at,
    sqlc.arg(code_expires_at)
FROM consumed_transaction
JOIN sessions AS session
  ON session.tenant_id =
     consumed_transaction.tenant_id
 AND session.id =
     sqlc.arg(session_id)
 AND session.membership_id =
     sqlc.arg(membership_id)
 AND session.user_id =
     sqlc.arg(user_id)
RETURNING
    code_hash,
    authorization_transaction_id,
    tenant_id,
    application_id,
    client_id,
    session_id,
    membership_id,
    user_id,
    redirect_uri,
    nonce,
    code_challenge,
    code_challenge_method,
    requested_scope,
    authentication_time,
    created_at,
    expires_at,
    consumed_at;
