mock_provider "aws" {
  override_during = plan
}

override_data {
  target          = data.aws_iam_policy_document.ecs_task_assume_role
  override_during = plan

  values = {
    json = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = "sts:AssumeRole"
          Principal = {
            Service = "ecs-tasks.amazonaws.com"
          }
        },
      ]
    })
  }
}

override_data {
  target          = data.aws_iam_policy_document.api_execution_secrets
  override_during = plan

  values = {
    json = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = "secretsmanager:GetSecretValue"
          Resource = "*"
        },
      ]
    })
  }
}

override_data {
  target          = data.aws_iam_policy_document.worker_execution_secrets
  override_during = plan

  values = {
    json = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = "secretsmanager:GetSecretValue"
          Resource = "*"
        },
      ]
    })
  }
}

override_data {
  target          = data.aws_iam_policy_document.api_task
  override_during = plan

  values = {
    json = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = "sqs:SendMessage"
          Resource = "*"
        },
      ]
    })
  }
}

override_data {
  target          = data.aws_iam_policy_document.worker_task
  override_during = plan

  values = {
    json = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "s3:PutObject",
          ]
          Resource = "*"
        },
      ]
    })
  }
}

override_resource {
  target          = aws_security_group.load_balancer
  override_during = plan

  values = {
    id = "sg-00000000000000001"
  }
}

override_resource {
  target          = aws_security_group.api_service
  override_during = plan

  values = {
    id = "sg-00000000000000002"
  }
}

run "development_runtime_security_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "dev"
    aws_region   = "ap-south-1"

    vpc_id = "vpc-00000000000000001"

    public_subnet_ids = [
      "subnet-00000000000000001",
      "subnet-00000000000000002",
    ]

    application_subnet_ids = [
      "subnet-00000000000000003",
      "subnet-00000000000000004",
    ]

    application_security_group_id = "sg-00000000000000003"

    audit_export_queue_url   = "https://sqs.ap-south-1.amazonaws.com/123456789012/gatehouse-dev-audit-export"
    audit_export_queue_arn   = "arn:aws:sqs:ap-south-1:123456789012:gatehouse-dev-audit-export"
    audit_export_bucket_name = "gatehouse-dev-123456789012-audit-exports"
    audit_export_bucket_arn  = "arn:aws:s3:::gatehouse-dev-123456789012-audit-exports"

    web_app_url = "http://localhost:5173"
    oidc_issuer = "http://localhost:8080"

    admin_allowed_origins = [
      "http://localhost:5173",
    ]

    certificate_arn = null

    api_desired_count    = 0
    worker_desired_count = 0
  }

  assert {
    condition     = !aws_lb.this.internal
    error_message = "The ALB must be internet-facing."
  }

  assert {
    condition = (
      one(
        aws_ecs_service.api.network_configuration
      ).assign_public_ip == false
    )
    error_message = "API tasks must not receive public IP addresses."
  }

  assert {
    condition = (
      one(
        aws_ecs_service.worker.network_configuration
      ).assign_public_ip == false
    )
    error_message = "Worker tasks must not receive public IP addresses."
  }

  assert {
    condition = contains(
      one(
        aws_ecs_service.api.network_configuration
      ).security_groups,
      aws_security_group.api_service.id,
    )
    error_message = "API tasks must use the ALB-restricted API security group."
  }

  assert {
    condition = (
      length(
        one(
          aws_ecs_service.worker.network_configuration
        ).security_groups
      ) == 1 &&
      contains(
        one(
          aws_ecs_service.worker.network_configuration
        ).security_groups,
        var.application_security_group_id,
      )
    )
    error_message = "Worker tasks must use only the private application security group."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.api_from_load_balancer.referenced_security_group_id ==
      aws_security_group.load_balancer.id
    )
    error_message = "API ingress must originate from the ALB security group."
  }

  assert {
    condition = (
      aws_vpc_security_group_egress_rule.load_balancer_to_api.referenced_security_group_id ==
      aws_security_group.api_service.id
    )
    error_message = "The ALB must send traffic only to the API security group."
  }

  assert {
    condition     = length(aws_ecs_service.api.load_balancer) == 1
    error_message = "The API service must be attached to exactly one target group."
  }

  assert {
    condition     = length(aws_ecs_service.worker.load_balancer) == 0
    error_message = "The worker service must never be attached to a load balancer."
  }

  assert {
    condition     = length(aws_lb_listener.http_forward) == 1
    error_message = "Development without a certificate must expose the HTTP listener."
  }

  assert {
    condition     = length(aws_lb_listener.https) == 0
    error_message = "Development must not plan HTTPS without a certificate."
  }

  assert {
    condition     = aws_ecr_repository.api.image_tag_mutability == "IMMUTABLE"
    error_message = "API image tags must be immutable."
  }

  assert {
    condition     = aws_ecr_repository.worker.image_tag_mutability == "IMMUTABLE"
    error_message = "Worker image tags must be immutable."
  }

  assert {
    condition     = !aws_lb.this.enable_deletion_protection
    error_message = "Disposable development infrastructure must allow ALB teardown."
  }
}

run "production_runtime_security_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "prod"
    aws_region   = "ap-south-1"

    vpc_id = "vpc-00000000000000002"

    public_subnet_ids = [
      "subnet-00000000000000011",
      "subnet-00000000000000012",
    ]

    application_subnet_ids = [
      "subnet-00000000000000013",
      "subnet-00000000000000014",
    ]

    application_security_group_id = "sg-00000000000000013"

    audit_export_queue_url   = "https://sqs.ap-south-1.amazonaws.com/123456789012/gatehouse-prod-audit-export"
    audit_export_queue_arn   = "arn:aws:sqs:ap-south-1:123456789012:gatehouse-prod-audit-export"
    audit_export_bucket_name = "gatehouse-prod-123456789012-audit-exports"
    audit_export_bucket_arn  = "arn:aws:s3:::gatehouse-prod-123456789012-audit-exports"

    web_app_url = "https://admin.example.com"
    oidc_issuer = "https://auth.example.com"

    admin_allowed_origins = [
      "https://admin.example.com",
    ]

    certificate_arn = "arn:aws:acm:ap-south-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"

    api_desired_count    = 0
    worker_desired_count = 0

    enable_load_balancer_deletion_protection = true
    force_delete_ecr_repositories            = false
    secret_recovery_window_days              = 30
  }

  assert {
    condition     = !aws_lb.this.internal
    error_message = "The production ALB must be internet-facing."
  }

  assert {
    condition = (
      one(
        aws_ecs_service.api.network_configuration
      ).assign_public_ip == false
    )
    error_message = "Production API tasks must remain private."
  }

  assert {
    condition = (
      one(
        aws_ecs_service.worker.network_configuration
      ).assign_public_ip == false
    )
    error_message = "Production workers must remain private."
  }

  assert {
    condition     = length(aws_ecs_service.worker.load_balancer) == 0
    error_message = "The production worker must not be reachable through the ALB."
  }

  assert {
    condition     = length(aws_lb_listener.http_redirect) == 1
    error_message = "Production HTTP traffic must redirect to HTTPS."
  }

  assert {
    condition     = length(aws_lb_listener.https) == 1
    error_message = "Production must expose an HTTPS listener."
  }

  assert {
    condition     = aws_lb.this.enable_deletion_protection
    error_message = "Production ALB deletion protection must be enabled."
  }

  assert {
    condition     = !aws_ecr_repository.api.force_delete
    error_message = "Production must not force-delete the API image repository."
  }

  assert {
    condition     = !aws_ecr_repository.worker.force_delete
    error_message = "Production must not force-delete the worker image repository."
  }

  assert {
    condition = alltrue([
      for secret in values(aws_secretsmanager_secret.runtime) :
      secret.recovery_window_in_days == 30
    ])
    error_message = "Production runtime secrets must retain a recovery window."
  }
}
