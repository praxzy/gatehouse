mock_provider "aws" {
  override_during = plan
}

override_data {
  target          = data.aws_caller_identity.current
  override_during = plan

  values = {
    account_id = "123456789012"
  }
}

override_resource {
  target          = aws_sqs_queue.dead_letter
  override_during = plan

  values = {
    id  = "https://sqs.ap-south-1.amazonaws.com/123456789012/gatehouse-audit-export-dlq"
    arn = "arn:aws:sqs:ap-south-1:123456789012:gatehouse-audit-export-dlq"
  }
}

override_resource {
  target          = aws_sqs_queue.exports
  override_during = plan

  values = {
    id  = "https://sqs.ap-south-1.amazonaws.com/123456789012/gatehouse-audit-export"
    arn = "arn:aws:sqs:ap-south-1:123456789012:gatehouse-audit-export"
  }
}

run "development_export_security_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "dev"
  }

  assert {
    condition     = aws_sqs_queue.exports.sqs_managed_sse_enabled
    error_message = "The development audit export queue must use server-side encryption."
  }

  assert {
    condition     = aws_sqs_queue.dead_letter.sqs_managed_sse_enabled
    error_message = "The development audit export DLQ must use server-side encryption."
  }

  assert {
    condition = (
      jsondecode(
        aws_sqs_queue.exports.redrive_policy
      ).deadLetterTargetArn ==
      aws_sqs_queue.dead_letter.arn
    )
    error_message = "The source queue must redrive only to the audit export DLQ."
  }

  assert {
    condition = (
      jsondecode(
        aws_sqs_queue.exports.redrive_policy
      ).maxReceiveCount == 5
    )
    error_message = "The source queue must use the configured bounded receive count."
  }

  assert {
    condition = (
      jsondecode(
        aws_sqs_queue_redrive_allow_policy.dead_letter.redrive_allow_policy
      ).redrivePermission == "byQueue"
    )
    error_message = "The DLQ must accept redrive from explicitly named queues only."
  }

  assert {
    condition = contains(
      jsondecode(
        aws_sqs_queue_redrive_allow_policy.dead_letter.redrive_allow_policy
      ).sourceQueueArns,
      aws_sqs_queue.exports.arn,
    )
    error_message = "The DLQ must permit redrive from the audit export source queue."
  }

  assert {
    condition     = aws_s3_bucket.exports.force_destroy
    error_message = "Development must permit disposable export-bucket teardown."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.exports.block_public_acls &&
      aws_s3_bucket_public_access_block.exports.block_public_policy &&
      aws_s3_bucket_public_access_block.exports.ignore_public_acls &&
      aws_s3_bucket_public_access_block.exports.restrict_public_buckets
    )
    error_message = "Every S3 public-access protection must be enabled."
  }

  assert {
    condition = (
      one(
        aws_s3_bucket_ownership_controls.exports.rule
      ).object_ownership == "BucketOwnerEnforced"
    )
    error_message = "The export bucket must disable ACL ownership."
  }

  assert {
    condition = (
      one(
        one(
          aws_s3_bucket_server_side_encryption_configuration.exports.rule
        ).apply_server_side_encryption_by_default
      ).sse_algorithm == "AES256"
    )
    error_message = "The export bucket must encrypt objects at rest."
  }

  assert {
    condition = (
      one(
        one(
          aws_s3_bucket_lifecycle_configuration.exports.rule
        ).expiration
      ).days == 30
    )
    error_message = "Development exports must expire after the configured retention period."
  }

  assert {
    condition = (
      aws_s3_bucket.exports.bucket ==
      "gatehouse-dev-123456789012-audit-exports"
    )
    error_message = "The export bucket name must be environment and account scoped."
  }
}

run "production_export_security_contract" {
  command = plan

  variables {
    project_name          = "gatehouse"
    environment           = "prod"
    max_receive_count     = 5
    export_retention_days = 30
  }

  assert {
    condition     = !aws_s3_bucket.exports.force_destroy
    error_message = "Production must not automatically destroy stored audit exports."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.exports.block_public_acls &&
      aws_s3_bucket_public_access_block.exports.block_public_policy &&
      aws_s3_bucket_public_access_block.exports.ignore_public_acls &&
      aws_s3_bucket_public_access_block.exports.restrict_public_buckets
    )
    error_message = "Production export storage must block every form of public access."
  }

  assert {
    condition     = aws_sqs_queue.exports.sqs_managed_sse_enabled
    error_message = "The production source queue must be encrypted."
  }

  assert {
    condition     = aws_sqs_queue.dead_letter.sqs_managed_sse_enabled
    error_message = "The production DLQ must be encrypted."
  }

  assert {
    condition = (
      jsondecode(
        aws_sqs_queue.exports.redrive_policy
      ).deadLetterTargetArn ==
      aws_sqs_queue.dead_letter.arn
    )
    error_message = "Production failures must redrive to the configured DLQ."
  }

  assert {
    condition = (
      one(
        one(
          aws_s3_bucket_lifecycle_configuration.exports.rule
        ).expiration
      ).days == 30
    )
    error_message = "Production exports must have bounded retention."
  }
}
