variable "aws_region" {
  description = "AWS region used by the Gatehouse deployment workflow."
  type        = string
  default     = "ap-south-1"
}

variable "state_bucket_name" {
  description = "Globally unique S3 bucket name for Terraform state."
  type        = string

  validation {
    condition = (
      length(var.state_bucket_name) >= 3 &&
      length(var.state_bucket_name) <= 63 &&
      can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.state_bucket_name))
    )
    error_message = "state_bucket_name must be a valid lowercase S3 bucket name."
  }
}

variable "github_repository" {
  description = "GitHub repository allowed to assume the deployment role, in owner/repository form."
  type        = string
  default     = "praxzy/gatehouse"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must use owner/repository form."
  }
}

variable "github_environment" {
  description = "Protected GitHub environment allowed to deploy."
  type        = string
  default     = "production"

  validation {
    condition     = length(trimspace(var.github_environment)) > 0
    error_message = "github_environment must not be empty."
  }
}

variable "create_github_oidc_provider" {
  description = "Create the account-level GitHub Actions OIDC provider. Disable when the account already has one."
  type        = bool
  default     = true
}

variable "deploy_role_name" {
  description = "Name of the GitHub Actions deployment role."
  type        = string
  default     = "gatehouse-github-deploy"
}

variable "state_key_prefixes" {
  description = "State-key prefixes the deployment role may access."
  type        = set(string)
  default = [
    "gatehouse/dev",
    "gatehouse/prod",
  ]

  validation {
    condition = alltrue([
      for prefix in var.state_key_prefixes :
      length(trim(prefix, "/")) > 0 && !startswith(prefix, "/")
    ])
    error_message = "State-key prefixes must be non-empty relative S3 paths."
  }
}

variable "additional_tags" {
  description = "Additional tags applied to bootstrap resources."
  type        = map(string)
  default     = {}
}
