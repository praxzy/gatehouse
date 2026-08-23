-- name: GetActiveApplicationForAuthorization :one
SELECT
    application.id AS application_id,
    application.tenant_id,
    application.name,
    application.client_id,
    application.client_type,
    application.access_mode
FROM applications AS application
WHERE application.client_id =
      sqlc.arg(client_id)
  AND application.status = 'active'
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
WHERE transaction.id =
      sqlc.arg(transaction_id)
  AND transaction.state_hash =
      sqlc.arg(state_hash);