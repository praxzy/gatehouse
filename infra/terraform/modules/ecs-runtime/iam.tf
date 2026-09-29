data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type = "Service"

      identifiers = [
        "ecs-tasks.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "api_execution" {
  name               = "${local.name}-api-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role" "worker_execution" {
  name               = "${local.name}-worker-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "api_execution" {
  role       = aws_iam_role.api_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "worker_execution" {
  role       = aws_iam_role.worker_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "api_execution_secrets" {
  statement {
    sid    = "ReadRuntimeSecrets"
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
    ]

    resources = [
      for secret in aws_secretsmanager_secret.runtime :
      secret.arn
    ]
  }
}

resource "aws_iam_role_policy" "api_execution_secrets" {
  name   = "read-runtime-secrets"
  role   = aws_iam_role.api_execution.id
  policy = data.aws_iam_policy_document.api_execution_secrets.json
}

data "aws_iam_policy_document" "worker_execution_secrets" {
  statement {
    sid    = "ReadDatabaseSecret"
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
    ]

    resources = [
      aws_secretsmanager_secret.runtime["DATABASE_URL"].arn,
    ]
  }
}

resource "aws_iam_role_policy" "worker_execution_secrets" {
  name   = "read-database-secret"
  role   = aws_iam_role.worker_execution.id
  policy = data.aws_iam_policy_document.worker_execution_secrets.json
}

resource "aws_iam_role" "api_task" {
  name               = "${local.name}-api-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role" "worker_task" {
  name               = "${local.name}-worker-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json

  tags = local.common_tags
}

data "aws_iam_policy_document" "api_task" {
  statement {
    sid    = "EnqueueAuditExports"
    effect = "Allow"

    actions = [
      "sqs:SendMessage",
    ]

    resources = [
      var.audit_export_queue_arn,
    ]
  }
}

resource "aws_iam_role_policy" "api_task" {
  name   = "publish-audit-export-jobs"
  role   = aws_iam_role.api_task.id
  policy = data.aws_iam_policy_document.api_task.json
}

data "aws_iam_policy_document" "worker_task" {
  statement {
    sid    = "ConsumeAuditExportJobs"
    effect = "Allow"

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]

    resources = [
      var.audit_export_queue_arn,
    ]
  }

  statement {
    sid    = "ReadExportBucketMetadata"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]

    resources = [
      var.audit_export_bucket_arn,
    ]
  }

  statement {
    sid    = "WriteAuditExports"
    effect = "Allow"

    actions = [
      "s3:AbortMultipartUpload",
      "s3:PutObject",
    ]

    resources = [
      "${var.audit_export_bucket_arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "worker_task" {
  name   = "process-audit-export-jobs"
  role   = aws_iam_role.worker_task.id
  policy = data.aws_iam_policy_document.worker_task.json
}