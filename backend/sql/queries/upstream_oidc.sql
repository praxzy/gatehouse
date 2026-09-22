-- name: CreateUpstreamOIDCConnection :one
INSERT INTO upstream_oidc_connections (
    tenant_id,
    display_name,
    issuer,
    client_id,
    client_secret_ciphertext,
    client_secret_nonce,
    encryption_key_id
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(display_name),
    sqlc.arg(issuer),
    sqlc.arg(client_id),
    sqlc.arg(client_secret_ciphertext),
    sqlc.arg(client_secret_nonce),
    sqlc.arg(encryption_key_id)
)
RETURNING *;


-- name: GetTenantUpstreamOIDCConnection :one
SELECT *
FROM upstream_oidc_connections
WHERE tenant_id = sqlc.arg(tenant_id);


-- name: GetEnabledUpstreamOIDCConnectionByID :one
SELECT *
FROM upstream_oidc_connections
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(connection_id)
  AND status = 'enabled';


-- name: GetEnabledUpstreamOIDCConnectionByTenantSlug :one
SELECT connection.*
FROM upstream_oidc_connections AS connection
JOIN tenants AS tenant
  ON tenant.id = connection.tenant_id
WHERE tenant.slug = sqlc.arg(tenant_slug)
  AND tenant.status = 'active'
  AND connection.status = 'enabled';


-- name: UpdateUpstreamOIDCConnection :one
UPDATE upstream_oidc_connections
SET display_name = sqlc.arg(display_name),
    issuer = sqlc.arg(issuer),
    client_id = sqlc.arg(client_id),
    client_secret_ciphertext = sqlc.arg(client_secret_ciphertext),
    client_secret_nonce = sqlc.arg(client_secret_nonce),
    encryption_key_id = sqlc.arg(encryption_key_id),
    updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(connection_id)
RETURNING *;


-- name: SetUpstreamOIDCConnectionStatus :one
UPDATE upstream_oidc_connections
SET status = sqlc.arg(status),
    updated_at = now()
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(connection_id)
RETURNING *;


-- name: CreateUpstreamOIDCIdentity :one
INSERT INTO upstream_oidc_identities (
    tenant_id,
    connection_id,
    subject,
    membership_id
)
SELECT
    connection.tenant_id,
    connection.id,
    sqlc.arg(subject),
    membership.id
FROM upstream_oidc_connections AS connection
JOIN memberships AS membership
  ON membership.tenant_id = connection.tenant_id
 AND membership.id = sqlc.arg(membership_id)
WHERE connection.tenant_id = sqlc.arg(tenant_id)
  AND connection.id = sqlc.arg(connection_id)
  AND connection.status = 'enabled'
  AND membership.status = 'active'
RETURNING *;


-- name: ListTenantUpstreamOIDCIdentities :many
SELECT
    identity.tenant_id,
    identity.connection_id,
    identity.subject,
    identity.membership_id,
    identity.created_at,
    member.user_id,
    member.status AS membership_status,
    app_user.email,
    app_user.display_name
FROM upstream_oidc_identities AS identity
JOIN memberships AS member
  ON member.tenant_id = identity.tenant_id
 AND member.id = identity.membership_id
JOIN users AS app_user
  ON app_user.id = member.user_id
WHERE identity.tenant_id = sqlc.arg(tenant_id)
  AND identity.connection_id = sqlc.arg(connection_id)
ORDER BY app_user.display_name, app_user.email, identity.subject;


-- name: DeleteUpstreamOIDCIdentity :execrows
DELETE FROM upstream_oidc_identities
WHERE tenant_id = sqlc.arg(tenant_id)
  AND connection_id = sqlc.arg(connection_id)
  AND subject = sqlc.arg(subject);


-- name: GetActiveUpstreamOIDCIdentity :one
SELECT
    identity.tenant_id,
    identity.connection_id,
    identity.subject,
    member.id AS membership_id,
    member.user_id
FROM upstream_oidc_identities AS identity
JOIN upstream_oidc_connections AS connection
  ON connection.tenant_id = identity.tenant_id
 AND connection.id = identity.connection_id
JOIN tenants AS tenant
  ON tenant.id = identity.tenant_id
JOIN memberships AS member
  ON member.tenant_id = identity.tenant_id
 AND member.id = identity.membership_id
JOIN users AS app_user
  ON app_user.id = member.user_id
WHERE identity.connection_id = sqlc.arg(connection_id)
  AND identity.subject = sqlc.arg(subject)
  AND connection.status = 'enabled'
  AND tenant.status = 'active'
  AND member.status = 'active'
  AND app_user.status = 'active';


-- name: CreateUpstreamOIDCTransaction :one
INSERT INTO upstream_oidc_transactions (
    state_hash,
    tenant_id,
    connection_id,
    nonce_hash,
    pkce_verifier_ciphertext,
    pkce_verifier_nonce,
    encryption_key_id,
    return_path,
    expires_at
)
VALUES (
    sqlc.arg(state_hash),
    sqlc.arg(tenant_id),
    sqlc.arg(connection_id),
    sqlc.arg(nonce_hash),
    sqlc.arg(pkce_verifier_ciphertext),
    sqlc.arg(pkce_verifier_nonce),
    sqlc.arg(encryption_key_id),
    sqlc.arg(return_path),
    sqlc.arg(expires_at)
)
RETURNING *;


-- name: ConsumeUpstreamOIDCTransaction :one
UPDATE upstream_oidc_transactions
SET consumed_at = now()
WHERE state_hash = sqlc.arg(state_hash)
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING *;


-- name: DeleteExpiredUpstreamOIDCTransactions :execrows
DELETE FROM upstream_oidc_transactions
WHERE expires_at <= now();

-- name: GetActiveUpstreamOIDCIdentityForSessionCreation :one
SELECT
    identity.tenant_id,
    identity.connection_id,
    identity.subject,
    member.id AS membership_id,
    member.user_id
FROM upstream_oidc_identities AS identity
JOIN upstream_oidc_connections AS connection
  ON connection.tenant_id = identity.tenant_id
 AND connection.id = identity.connection_id
JOIN tenants AS tenant
  ON tenant.id = identity.tenant_id
JOIN memberships AS member
  ON member.tenant_id = identity.tenant_id
 AND member.id = identity.membership_id
JOIN users AS app_user
  ON app_user.id = member.user_id
WHERE identity.tenant_id = sqlc.arg(tenant_id)
  AND identity.connection_id = sqlc.arg(connection_id)
  AND identity.subject = sqlc.arg(subject)
  AND connection.status = 'enabled'
  AND tenant.status = 'active'
  AND member.status = 'active'
  AND app_user.status = 'active'
  AND app_user.email_verified_at IS NOT NULL
FOR SHARE OF identity, connection, tenant, member, app_user;
