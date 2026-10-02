locals {
  github_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubActionsProductionEnvironment"
        Effect = "Allow"
        Principal = {
          Federated = local.github_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
            "token.actions.githubusercontent.com:sub" = local.github_subject
          }
        }
      },
    ]
  })
}

resource "aws_iam_role" "github_deploy" {
  name                 = var.deploy_role_name
  assume_role_policy   = local.github_trust_policy
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    sid    = "ReadTerraformStateBucket"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.terraform_state.arn,
    ]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values = [
        for prefix in local.state_key_prefixes : "${prefix}/*"
      ]
    }
  }

  statement {
    sid    = "ReadWriteTerraformStateObjects"
    effect = "Allow"

    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]

    resources = local.state_object_arns
  }

  statement {
    sid    = "AuthenticateToECR"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid    = "PushGatehouseImages"
    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/gatehouse-*-api",
      "arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/gatehouse-*-audit-export-worker",
    ]
  }

  statement {
    sid    = "PublishTaskDefinitions"
    effect = "Allow"

    actions = [
      "ecs:DeregisterTaskDefinition",
      "ecs:RegisterTaskDefinition",
      "ecs:TagResource",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    sid    = "DeployGatehouseServices"
    effect = "Allow"

    actions = [
      "ecs:UpdateService",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/gatehouse-*/*",
    ]
  }

  statement {
    sid    = "PassGatehouseTaskRoles"
    effect = "Allow"

    actions = [
      "iam:PassRole",
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/gatehouse-*-api-execution",
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/gatehouse-*-api-task",
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/gatehouse-*-worker-execution",
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/gatehouse-*-worker-task",
    ]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "ecs-tasks.amazonaws.com",
      ]
    }
  }

  statement {
    sid    = "ReadDeploymentTopology"
    effect = "Allow"

    actions = [
      "acm:DescribeCertificate",
      "acm:ListCertificates",
      "ec2:Describe*",
      "ecr:Describe*",
      "ecr:GetLifecyclePolicy",
      "ecr:ListTagsForResource",
      "ecs:Describe*",
      "ecs:List*",
      "elasticloadbalancing:Describe*",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "logs:DescribeLogGroups",
      "logs:ListTagsForResource",
      "rds:Describe*",
      "rds:ListTagsForResource",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListAllMyBuckets",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets",
      "sqs:GetQueueAttributes",
      "sqs:ListQueueTags",
    ]

    resources = [
      "*",
    ]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "gatehouse-runtime-deployment"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}
