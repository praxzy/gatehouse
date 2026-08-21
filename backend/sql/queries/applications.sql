-- name: CreateApplication :one
INSERT INTO applications (
    tenant_id,
    name,
    description,
    client_id,
    client_type,
    client_secret_hash,
    client_secret_created_at,
    status,
    access_mode
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(name),
    sqlc.narg(description),
    sqlc.arg(client_id),
    sqlc.arg(client_type),
    sqlc.narg(client_secret_hash),
    sqlc.narg(client_secret_created_at),
    'active',
    sqlc.arg(access_mode)
)
RETURNING
    id,
    tenant_id,
    name,
    description,
    client_id,
    client_type,
    status,
    access_mode,
    created_at,
    updated_at;


-- name: AddApplicationRedirectURI :one
INSERT INTO redirect_uris (
    tenant_id,
    application_id,
    uri
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(application_id),
    sqlc.arg(uri)
)
RETURNING
    id,
    tenant_id,
    application_id,
    uri,
    created_at;


-- name: AddApplicationAccessRole :exec
INSERT INTO application_access (
    tenant_id,
    application_id,
    role_id
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(application_id),
    sqlc.arg(role_id)
);


-- name: ListApplications :many
SELECT
    application.id,
    application.tenant_id,
    application.name,
    application.description,
    application.client_id,
    application.client_type,
    application.status,
    application.access_mode,
    application.created_at,
    application.updated_at,
    (
        SELECT count(*)::int
        FROM redirect_uris AS redirect_uri
        WHERE redirect_uri.tenant_id =
              application.tenant_id
          AND redirect_uri.application_id =
              application.id
    ) AS redirect_uri_count,
    (
        SELECT count(*)::int
        FROM application_access AS access
        WHERE access.tenant_id =
              application.tenant_id
          AND access.application_id =
              application.id
    ) AS allowed_role_count
FROM applications AS application
WHERE application.tenant_id =
      sqlc.arg(tenant_id)
ORDER BY
    lower(application.name),
    application.id;


-- name: GetApplicationByID :one
SELECT
    application.id,
    application.tenant_id,
    application.name,
    application.description,
    application.client_id,
    application.client_type,
    application.status,
    application.access_mode,
    application.created_at,
    application.updated_at
FROM applications AS application
WHERE application.tenant_id =
      sqlc.arg(tenant_id)
  AND application.id =
      sqlc.arg(application_id);


-- name: ListApplicationRedirectURIs :many
SELECT
    redirect_uri.id,
    redirect_uri.tenant_id,
    redirect_uri.application_id,
    redirect_uri.uri,
    redirect_uri.created_at
FROM redirect_uris AS redirect_uri
WHERE redirect_uri.tenant_id =
      sqlc.arg(tenant_id)
  AND redirect_uri.application_id =
      sqlc.arg(application_id)
ORDER BY
    redirect_uri.created_at,
    redirect_uri.id;


-- name: ListApplicationAccessRoles :many
SELECT
    role.id AS role_id,
    role.role_key,
    role.name,
    role.is_system
FROM application_access AS access
JOIN roles AS role
  ON role.tenant_id = access.tenant_id
 AND role.id = access.role_id
WHERE access.tenant_id =
      sqlc.arg(tenant_id)
  AND access.application_id =
      sqlc.arg(application_id)
ORDER BY
    role.is_system DESC,
    lower(role.name),
    role.id;
