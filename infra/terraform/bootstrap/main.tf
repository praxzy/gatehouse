data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

locals {
  github_oidc_url = "https://token.actions.githubusercontent.com"
  github_subject  = "repo:${var.github_repository}:environment:${var.github_environment}"

  state_key_prefixes = toset([
    for prefix in var.state_key_prefixes : trim(prefix, "/")
  ])

  state_object_arns = [
    for prefix in local.state_key_prefixes :
    "${aws_s3_bucket.terraform_state.arn}/${prefix}/*"
  ]
}

resource "aws_s3_bucket" "terraform_state" {
  bucket        = var.state_bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "terraform_state" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.terraform_state.arn,
      "${aws_s3_bucket.terraform_state.arn}/*",
    ]

    principals {
      type = "*"
      identifiers = [
        "*",
      ]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false",
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  policy = data.aws_iam_policy_document.terraform_state.json
}

resource "aws_iam_openid_connect_provider" "github_actions" {
  count = var.create_github_oidc_provider ? 1 : 0

  url = local.github_oidc_url
  client_id_list = [
    "sts.amazonaws.com",
  ]
}

data "aws_iam_openid_connect_provider" "github_actions" {
  count = var.create_github_oidc_provider ? 0 : 1

  url = local.github_oidc_url
}

locals {
  github_oidc_provider_arn = var.create_github_oidc_provider ? (
    one(aws_iam_openid_connect_provider.github_actions[*].arn)
    ) : (
    one(data.aws_iam_openid_connect_provider.github_actions[*].arn)
  )
}
