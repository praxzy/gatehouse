resource "aws_ecs_task_definition" "api" {
  family = "${local.name}-api"

  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.api_execution.arn
  task_role_arn            = aws_iam_role.api_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = "${aws_ecr_repository.api.repository_url}:${var.api_image_tag}"
      essential = true

      readonlyRootFilesystem = true

      portMappings = [
        {
          name          = "http"
          containerPort = var.api_container_port
          hostPort      = var.api_container_port
          protocol      = "tcp"
          appProtocol   = "http"
        },
      ]

      environment = [
        {
          name  = "HTTP_ADDR"
          value = ":${var.api_container_port}"
        },
        {
          name  = "AWS_REGION"
          value = var.aws_region
        },
        {
          name  = "AUDIT_EXPORT_QUEUE_URL"
          value = var.audit_export_queue_url
        },
        {
          name  = "WEB_APP_URL"
          value = var.web_app_url
        },
        {
          name  = "OIDC_ISSUER"
          value = var.oidc_issuer
        },
        {
          name  = "ADMIN_ALLOWED_ORIGINS"
          value = join(",", sort(tolist(var.admin_allowed_origins)))
        },
        {
          name  = "EMAIL_DELIVERY_MODE"
          value = var.email_delivery_mode
        },
        {
          name  = "SESSION_COOKIE_SECURE"
          value = tostring(var.certificate_arn != null)
        },
        {
          name  = "MFA_ENCRYPTION_KEY_ID"
          value = var.mfa_encryption_key_id
        },
        {
          name  = "OIDC_SIGNING_KEY_ID"
          value = var.oidc_signing_key_id
        },
        {
          name  = "UPSTREAM_OIDC_ENCRYPTION_KEY_ID"
          value = var.upstream_oidc_encryption_key_id
        },
        {
          name  = "UPSTREAM_OIDC_REDIRECT_URI"
          value = var.upstream_oidc_redirect_uri
        },
        {
          name  = "UPSTREAM_OIDC_ALLOW_HTTP"
          value = "false"
        },
        {
          name  = "UPSTREAM_OIDC_ALLOW_PRIVATE_ADDRESSES"
          value = "false"
        },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.runtime["DATABASE_URL"].arn
        },
        {
          name      = "MFA_ENCRYPTION_KEY_BASE64"
          valueFrom = aws_secretsmanager_secret.runtime["MFA_ENCRYPTION_KEY_BASE64"].arn
        },
        {
          name      = "UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64"
          valueFrom = aws_secretsmanager_secret.runtime["UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64"].arn
        },
        {
          name      = "CSRF_HMAC_KEY_BASE64"
          valueFrom = aws_secretsmanager_secret.runtime["CSRF_HMAC_KEY_BASE64"].arn
        },
        {
          name      = "OIDC_SIGNING_PRIVATE_KEY_BASE64"
          valueFrom = aws_secretsmanager_secret.runtime["OIDC_SIGNING_PRIVATE_KEY_BASE64"].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"

        options = {
          awslogs-region        = var.aws_region
          awslogs-group         = aws_cloudwatch_log_group.api.name
          awslogs-stream-prefix = "api"
        }
      }
    },
  ])

  tags = local.common_tags
}

resource "aws_ecs_task_definition" "worker" {
  family = "${local.name}-audit-export-worker"

  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.worker_cpu
  memory                   = var.worker_memory
  execution_role_arn       = aws_iam_role.worker_execution.arn
  task_role_arn            = aws_iam_role.worker_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "audit-export-worker"
      image     = "${aws_ecr_repository.worker.repository_url}:${var.worker_image_tag}"
      essential = true

      readonlyRootFilesystem = true

      environment = [
        {
          name  = "AWS_REGION"
          value = var.aws_region
        },
        {
          name  = "AUDIT_EXPORT_QUEUE_URL"
          value = var.audit_export_queue_url
        },
        {
          name  = "AUDIT_EXPORT_BUCKET"
          value = var.audit_export_bucket_name
        },
      ]

      secrets = [
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.runtime["DATABASE_URL"].arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"

        options = {
          awslogs-region        = var.aws_region
          awslogs-group         = aws_cloudwatch_log_group.worker.name
          awslogs-stream-prefix = "worker"
        }
      }
    },
  ])

  tags = local.common_tags
}

resource "aws_ecs_service" "api" {
  name    = "${local.name}-api"
  cluster = aws_ecs_cluster.this.id

  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  health_check_grace_period_seconds = 60

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false

    subnets = sort(tolist(var.application_subnet_ids))

    security_groups = [
      var.application_security_group_id,
      aws_security_group.api_service.id,
    ]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = var.api_container_port
  }

  depends_on = [
    aws_lb_listener.http_forward,
    aws_lb_listener.http_redirect,
    aws_lb_listener.https,
  ]

  tags = local.common_tags
}

resource "aws_ecs_service" "worker" {
  name    = "${local.name}-audit-export-worker"
  cluster = aws_ecs_cluster.this.id

  task_definition = aws_ecs_task_definition.worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = false
    subnets          = sort(tolist(var.application_subnet_ids))

    security_groups = [
      var.application_security_group_id,
    ]
  }

  tags = local.common_tags
}