variable "aws_region" {
  description = "AWS region used by the production environment."
  type        = string
  default     = "ap-south-1"
  nullable    = false
}

variable "availability_zones" {
  description = "Two availability zones used by the production environment."
  type        = list(string)
  default     = ["ap-south-1a", "ap-south-1b"]
  nullable    = false

  validation {
    condition = (
      length(var.availability_zones) == 2 &&
      length(distinct(var.availability_zones)) == 2
    )
    error_message = "Production requires exactly two distinct availability zones."
  }
}

variable "additional_tags" {
  description = "Optional additional tags applied to production resources."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "web_app_url" {
  description = "Public URL of the Gatehouse admin UI."
  type        = string
  nullable    = false
}

variable "oidc_issuer" {
  description = "Public issuer URL advertised by Gatehouse."
  type        = string
  nullable    = false
}

variable "admin_allowed_origins" {
  description = "Origins permitted to make credentialed admin API requests."
  type        = set(string)
  nullable    = false

  validation {
    condition     = length(var.admin_allowed_origins) > 0
    error_message = "At least one admin origin is required."
  }
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the public HTTPS listener."
  type        = string
  default     = null
  nullable    = true
}

variable "api_desired_count" {
  description = "Number of Gatehouse API tasks to run."
  type        = number
  default     = 0
  nullable    = false

  validation {
    condition     = var.api_desired_count >= 0
    error_message = "api_desired_count cannot be negative."
  }
}

variable "worker_desired_count" {
  description = "Number of audit-export worker tasks to run."
  type        = number
  default     = 0
  nullable    = false

  validation {
    condition     = var.worker_desired_count >= 0
    error_message = "worker_desired_count cannot be negative."
  }
}

variable "api_image_tag" {
  description = "Immutable API image tag deployed to ECS."
  type        = string
  default     = "bootstrap"
  nullable    = false
}

variable "worker_image_tag" {
  description = "Immutable worker image tag deployed to ECS."
  type        = string
  default     = "bootstrap"
  nullable    = false
}

variable "alarm_action_arns" {
  description = "SNS topic or incident-action ARNs for CloudWatch alarms."
  type        = set(string)
  default     = []
  nullable    = false
}
