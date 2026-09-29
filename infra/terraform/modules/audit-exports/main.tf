data "aws_caller_identity" "current" {}

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(
    var.tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    },
  )

  # One audit export bucket per environment and AWS account.
  # The variable length limits keep this within S3's 63-character limit.
  bucket_name = lower(
    "${var.project_name}-${var.environment}-${data.aws_caller_identity.current.account_id}-audit-exports"
  )
}

resource "aws_sqs_queue" "dead_letter" {
  name = "${local.name_prefix}-audit-export-dlq"

  message_retention_seconds = var.message_retention_seconds
  sqs_managed_sse_enabled   = true

  tags = merge(
    local.common_tags,
    {
      Name    = "${local.name_prefix}-audit-export-dlq"
      Purpose = "audit-export-dead-letter"
    },
  )
}

resource "aws_sqs_queue" "exports" {
  name = "${local.name_prefix}-audit-export"

  message_retention_seconds  = var.message_retention_seconds
  visibility_timeout_seconds = var.visibility_timeout_seconds
  receive_wait_time_seconds  = 20
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = merge(
    local.common_tags,
    {
      Name    = "${local.name_prefix}-audit-export"
      Purpose = "audit-export-processing"
    },
  )
}

resource "aws_sqs_queue_redrive_allow_policy" "dead_letter" {
  queue_url = aws_sqs_queue.dead_letter.id

  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns = [
      aws_sqs_queue.exports.arn,
    ]
  })
}

resource "aws_s3_bucket" "exports" {
  bucket = local.bucket_name

  # Development exports may be destroyed with their environment.
  # Production destruction must first empty the bucket explicitly.
  force_destroy = var.environment == "dev"

  tags = merge(
    local.common_tags,
    {
      Name    = local.bucket_name
      Purpose = "audit-export-storage"
    },
  )
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    id     = "expire-audit-exports"
    status = "Enabled"

    filter {
      prefix = "audit-exports/"
    }

    expiration {
      days = var.export_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "exports_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.exports.arn,
      "${aws_s3_bucket.exports.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "exports" {
  bucket = aws_s3_bucket.exports.id
  policy = data.aws_iam_policy_document.exports_bucket.json

  depends_on = [
    aws_s3_bucket_public_access_block.exports,
    aws_s3_bucket_ownership_controls.exports,
  ]
}