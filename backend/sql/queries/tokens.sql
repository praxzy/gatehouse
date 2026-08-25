-- name: GetActiveTokenClient :one
SELECT
    application.tenant_id,
    application.id AS application_id,
    application.client_id,
    application.client_type,
    application.client_secret_hash
FROM applications AS application
JOIN tenants AS tenant
  ON tenant.id = application.tenant_id
WHERE application.client_id =
      sqlc.arg(client_id)
  AND application.status = 'active'
  AND tenant.status = 'active';


-- name: RedeemAuthorizationCode :one
WITH consumed_code AS (
    UPDATE authorization_codes AS code
    SET consumed_at = now()
    FROM
        applications AS application,
        tenants AS tenant,
        sessions AS session,
        memberships AS membership,
        users AS users
    WHERE code.code_hash =
          sqlc.arg(code_hash)
      AND code.client_id =
          sqlc.arg(client_id)
      AND code.redirect_uri =
          sqlc.arg(redirect_uri)
      AND code.code_challenge =
          sqlc.arg(code_challenge)
      AND code.code_challenge_method = 'S256'
      AND code.consumed_at IS NULL
      AND code.expires_at > now()

      AND application.tenant_id =
          code.tenant_id
      AND application.id =
          code.application_id
      AND application.client_id =
          code.client_id
      AND application.status = 'active'

      AND tenant.id =
          code.tenant_id
      AND tenant.status = 'active'

      AND session.tenant_id =
          code.tenant_id
      AND session.id =
          code.session_id
      AND session.membership_id =
          code.membership_id
      AND session.user_id =
          code.user_id
      AND session.revoked_at IS NULL
      AND session.expires_at > now()

      AND membership.tenant_id =
          code.tenant_id
      AND membership.id =
          code.membership_id
      AND membership.user_id =
          code.user_id
      AND membership.status = 'active'

      AND users.id =
          code.user_id
      AND users.status = 'active'
      AND users.email_verified_at IS NOT NULL

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
    RETURNING
        code.code_hash,
        code.tenant_id,
        code.application_id,
        code.client_id,
        code.session_id,
        code.membership_id,
        code.user_id,
        code.nonce,
        code.requested_scope,
        code.authentication_time
),
issued_access_token AS (
    INSERT INTO access_tokens (
        token_hash,
        authorization_code_hash,
        tenant_id,
        application_id,
        client_id,
        session_id,
        membership_id,
        user_id,
        granted_scope,
        expires_at
    )
    SELECT
        sqlc.arg(token_hash),
        consumed_code.code_hash,
        consumed_code.tenant_id,
        consumed_code.application_id,
        consumed_code.client_id,
        consumed_code.session_id,
        consumed_code.membership_id,
        consumed_code.user_id,
        consumed_code.requested_scope,
        sqlc.arg(access_token_expires_at)
    FROM consumed_code
    RETURNING
        token_hash,
        authorization_code_hash,
        created_at,
        expires_at
)
SELECT
    consumed_code.tenant_id,
    consumed_code.application_id,
    consumed_code.client_id,
    consumed_code.session_id,
    consumed_code.membership_id,
    consumed_code.user_id,
    consumed_code.nonce,
    consumed_code.requested_scope AS granted_scope,
    consumed_code.authentication_time,
    (
        SELECT user_account.display_name
        FROM users AS user_account
        WHERE user_account.id =
              consumed_code.user_id
    ) AS display_name,
    (
        SELECT user_account.email
        FROM users AS user_account
        WHERE user_account.id =
              consumed_code.user_id
    ) AS email,
    ARRAY(
        SELECT role.name
        FROM membership_roles AS membership_role
        JOIN roles AS role
          ON role.tenant_id =
             membership_role.tenant_id
         AND role.id =
             membership_role.role_id
        WHERE membership_role.tenant_id =
              consumed_code.tenant_id
          AND membership_role.membership_id =
              consumed_code.membership_id
        ORDER BY lower(role.name), role.id
    )::text[] AS roles,
    issued_access_token.created_at
        AS access_token_created_at,
    issued_access_token.expires_at
        AS access_token_expires_at
FROM consumed_code
JOIN issued_access_token
  ON issued_access_token.authorization_code_hash =
     consumed_code.code_hash;
