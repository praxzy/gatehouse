-- name: CreateAuditExportJob :one
INSERT INTO export_jobs (
    tenant_id,
    requested_by_membership_id,
    format,
    filter_actor_user_id,
    filter_application_id,
    filter_event_type,
    filter_outcome,
    time_from,
    time_until
)
VALUES (
    sqlc.arg(tenant_id),
    sqlc.arg(requested_by_membership_id),
    sqlc.arg(format),
    sqlc.narg(filter_actor_user_id),
    sqlc.narg(filter_application_id),
    sqlc.narg(filter_event_type),
    sqlc.narg(filter_outcome),
    sqlc.narg(time_from),
    sqlc.narg(time_until)
)
RETURNING *;


-- name: GetTenantAuditExportJob :one
SELECT *
FROM export_jobs
WHERE tenant_id = sqlc.arg(tenant_id)
  AND id = sqlc.arg(job_id);


-- name: ListTenantAuditExportJobs :many
SELECT *
FROM export_jobs
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_size);


-- name: ListPendingAuditExportEnqueues :many
SELECT id
FROM export_jobs
WHERE status = 'queued'
  AND enqueued_at IS NULL
ORDER BY created_at, id
LIMIT sqlc.arg(batch_size);


-- name: MarkAuditExportJobEnqueued :execrows
UPDATE export_jobs
SET enqueued_at = now(),
    updated_at = now()
WHERE id = sqlc.arg(job_id)
  AND status = 'queued'
  AND enqueued_at IS NULL;


-- name: GetAuditExportJobByID :one
SELECT *
FROM export_jobs
WHERE id = sqlc.arg(job_id);


-- name: ClaimAuditExportJob :one
UPDATE export_jobs
SET status = 'running',
    attempt_count = attempt_count + 1,
    lease_expires_at = now() +
        sqlc.arg(lease_seconds)::integer * interval '1 second',
    last_error_code = NULL,
    updated_at = now()
WHERE id = sqlc.arg(job_id)
  AND (
      status = 'queued'
      OR (
          status = 'running'
          AND lease_expires_at <= now()
      )
  )
  AND sqlc.arg(lease_seconds)::integer > 0
RETURNING *;


-- name: RenewAuditExportJobLease :execrows
UPDATE export_jobs
SET lease_expires_at = now() +
        sqlc.arg(lease_seconds)::integer * interval '1 second',
    updated_at = now()
WHERE id = sqlc.arg(job_id)
  AND status = 'running'
  AND attempt_count = sqlc.arg(attempt_count)
  AND lease_expires_at > now()
  AND sqlc.arg(lease_seconds)::integer > 0;


-- name: CompleteAuditExportJob :execrows
UPDATE export_jobs
SET status = 'completed',
    lease_expires_at = NULL,
    output_object_key = sqlc.arg(output_object_key),
    last_error_code = NULL,
    completed_at = now(),
    updated_at = now()
WHERE id = sqlc.arg(job_id)
  AND status = 'running'
  AND attempt_count = sqlc.arg(attempt_count)
  AND lease_expires_at > now()
  AND length(btrim(sqlc.arg(output_object_key))) BETWEEN 1 AND 1024;


-- name: FailAuditExportJob :execrows
UPDATE export_jobs
SET status = 'failed',
    lease_expires_at = NULL,
    last_error_code = sqlc.arg(last_error_code),
    failed_at = now(),
    updated_at = now()
WHERE id = sqlc.arg(job_id)
  AND status = 'running'
  AND attempt_count = sqlc.arg(attempt_count)
  AND lease_expires_at > now();


-- name: FailExpiredExhaustedAuditExportJobs :many
UPDATE export_jobs
SET status = 'failed',
    lease_expires_at = NULL,
    last_error_code = 'retry_exhausted',
    failed_at = now(),
    updated_at = now()
WHERE status = 'running'
  AND attempt_count >= sqlc.arg(max_attempts)
  AND lease_expires_at <= now()
RETURNING id;
