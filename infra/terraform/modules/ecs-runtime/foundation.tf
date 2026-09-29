locals {
  name = "${var.project_name}-${var.environment}"

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.tags,
  )

  runtime_secret_names = toset([
    "DATABASE_URL",
    "MFA_ENCRYPTION_KEY_BASE64",
    "UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64",
    "CSRF_HMAC_KEY_BASE64",
    "OIDC_SIGNING_PRIVATE_KEY_BASE64",
  ])
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = local.common_tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name = aws_ecs_cluster.this.name

  capacity_providers = [
    "FARGATE",
    "FARGATE_SPOT",
  ]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_ecr_repository" "api" {
  name                 = "${local.name}-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_delete_ecr_repositories

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Component = "api"
  })
}

resource "aws_ecr_repository" "worker" {
  name                 = "${local.name}-audit-export-worker"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_delete_ecr_repositories

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Component = "audit-export-worker"
  })
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the most recent 20 API images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = {
          type = "expire"
        }
      },
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the most recent 20 worker images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = {
          type = "expire"
        }
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.name}/api"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, {
    Component = "api"
  })
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/ecs/${local.name}/audit-export-worker"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, {
    Component = "audit-export-worker"
  })
}

resource "aws_secretsmanager_secret" "runtime" {
  for_each = local.runtime_secret_names

  name                    = "${local.name}/${lower(replace(each.value, "_", "-"))}"
  recovery_window_in_days = var.secret_recovery_window_days

  tags = merge(local.common_tags, {
    ConfigurationKey = each.value
  })
}