# Audit export worker

Day 17 runs audit exports outside the API process. The API creates a tenant-bound
database job and publishes an SQS message containing only `job_id`. The worker
reloads the job from Postgres, renders its recorded filters/snapshot, uploads
CSV or JSON to a private S3 bucket, and marks the job completed.

The AWS resources are defined in `infra/audit-exports.yaml`. Deploy that stack
in your AWS account, then set `AWS_REGION`, `AUDIT_EXPORT_QUEUE_URL` (the source
queue output), and `AUDIT_EXPORT_BUCKET` (the bucket output). The API needs
`sqs:SendMessage` on the source queue. The worker needs `sqs:ReceiveMessage`,
`sqs:ChangeMessageVisibility`, and `sqs:DeleteMessage` on that queue, plus
`s3:PutObject` on `audit-exports/*` in the output bucket. If using AWS-managed
SQS encryption, ensure the principals can use the configured key. Both processes
also need their usual Postgres access. With the repository `.env` configured,
run the worker separately:

```sh
make audit-export-worker
```

The source queue redrives to a DLQ after five receives. A database job is
retried for at most three processing attempts. The worker renews the SQS
visibility timeout and the database lease during a long export. An expired
third-attempt lease is reconciled to `failed` after a worker crash. Completed
messages are safe to redeliver: the processor checks the database status and
deletes them without uploading again. Malformed, unknown, or terminal-failed
messages are not deleted, so operators can inspect them in the DLQ.

The bucket expires exported objects after 30 days. The current API creates
jobs but does not yet provide a download endpoint or presigned URL; do not
expose the S3 bucket publicly to bridge that gap.
