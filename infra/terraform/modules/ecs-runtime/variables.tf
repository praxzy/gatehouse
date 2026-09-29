variable "project_name" {
  description = "Name used to prefix runtime resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment, such as dev or prod."
  type        = string
}

variable "aws_region" {
  description = "AWS region used in ECS log configuration."
  type        = string
}

variable "vpc_id" {
  description = "VPC containing the ALB and ECS services."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs used by the internet-facing ALB."
  type        = set(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "The ALB requires at least two public subnets."
  }
}

variable "application_subnet_ids" {
  description = "Private subnet IDs used by API and worker tasks."
  type        = set(string)

  validation {
    condition     = length(var.application_subnet_ids) >= 2
    error_message = "ECS requires at least two application subnets."
  }
}

variable "application_security_group_id" {
  description = "Security group attached to private ECS tasks."
  type        = string
}

variable "audit_export_queue_url" {
  description = "Audit export SQS queue URL supplied to the containers."
  type        = string
}

variable "audit_export_queue_arn" {
  description = "Audit export SQS queue ARN used by task IAM policies."
  type        = string
}

variable "audit_export_bucket_name" {
  description = "S3 bucket used for completed audit exports."
  type        = string
}

variable "audit_export_bucket_arn" {
  description = "S3 export bucket ARN used by worker IAM policies."
  type        = string
}

variable "api_container_port" {
  description = "Port exposed by the Gatehouse API container."
  type        = number
  default     = 8080
}

variable "api_desired_count" {
  description = "Desired number of API tasks."
  type        = number
  default     = 0

  validation {
    condition     = var.api_desired_count >= 0
    error_message = "api_desired_count cannot be negative."
  }
}

variable "worker_desired_count" {
  description = "Desired number of audit-export worker tasks."
  type        = number
  default     = 0

  validation {
    condition     = var.worker_desired_count >= 0
    error_message = "worker_desired_count cannot be negative."
  }
}

variable "api_cpu" {
  description = "CPU units reserved for each API task."
  type        = number
  default     = 256
}

variable "api_memory" {
  description = "Memory in MiB reserved for each API task."
  type        = number
  default     = 512
}

variable "worker_cpu" {
  description = "CPU units reserved for each worker task."
  type        = number
  default     = 256
}

variable "worker_memory" {
  description = "Memory in MiB reserved for each worker task."
  type        = number
  default     = 512
}

variable "api_image_tag" {
  description = "ECR image tag deployed by the API service."
  type        = string
  default     = "latest"
}

variable "worker_image_tag" {
  description = "ECR image tag deployed by the worker service."
  type        = string
  default     = "latest"
}

variable "health_check_path" {
  description = "HTTP path used by the API target-group health check."
  type        = string
  default     = "/healthz"
}

variable "certificate_arn" {
  description = "Optional ACM certificate used by the HTTPS listener."
  type        = string
  default     = null
  nullable    = true
}

variable "allowed_ingress_cidrs" {
  description = "CIDR ranges allowed to reach the public ALB."
  type        = set(string)
  default     = ["0.0.0.0/0"]
}

variable "log_retention_days" {
  description = "CloudWatch log retention period."
  type        = number
  default     = 30
}

variable "secret_recovery_window_days" {
  description = "Recovery window for runtime Secrets Manager secrets."
  type        = number
  default     = 7
}

variable "force_delete_ecr_repositories" {
  description = "Allow ECR repositories to be destroyed when they contain images."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags applied to resources."
  type        = map(string)
  default     = {}
}

variable "enable_load_balancer_deletion_protection" {
  description = "Protect the ALB from accidental Terraform deletion."
  type        = bool
  default     = false
}

variable "web_app_url" {
  description = "Public URL of the Gatehouse admin UI."
  type        = string
}

variable "oidc_issuer" {
  description = "Public Gatehouse OIDC issuer URL."
  type        = string
}

variable "admin_allowed_origins" {
  description = "Origins permitted to make credentialed admin API requests."
  type        = set(string)

  validation {
    condition     = length(var.admin_allowed_origins) > 0
    error_message = "At least one admin origin is required."
  }
}

variable "email_delivery_mode" {
  description = "Gatehouse email delivery mode."
  type        = string
  default     = "log"
}

variable "mfa_encryption_key_id" {
  description = "Identifier associated with the active MFA encryption key."
  type        = string
  default     = "primary-v1"
}

variable "oidc_signing_key_id" {
  description = "Identifier published as kid for the active OIDC signing key."
  type        = string
  default     = "primary-rs256-v1"
}

variable "upstream_oidc_encryption_key_id" {
  description = "Identifier for the upstream OIDC secret-encryption key."
  type        = string
  default     = "primary-federation-v1"
}

variable "upstream_oidc_redirect_uri" {
  description = "Optional callback URI for upstream OIDC federation."
  type        = string
  default     = ""
}