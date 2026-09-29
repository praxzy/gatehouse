variable "project_name" {
  description = "Short project name used in resource names and tags."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.project_name))
    error_message = "project_name must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be either dev or prod."
  }
}

variable "export_retention_days" {
  description = "Number of days completed audit export objects remain in S3."
  type        = number
  default     = 30
  nullable    = false

  validation {
    condition = (
      var.export_retention_days >= 1 &&
      var.export_retention_days <= 365
    )
    error_message = "export_retention_days must be between 1 and 365."
  }
}

variable "message_retention_seconds" {
  description = "Number of seconds SQS retains source and dead-letter messages."
  type        = number
  default     = 1209600
  nullable    = false

  validation {
    condition = (
      var.message_retention_seconds >= 60 &&
      var.message_retention_seconds <= 1209600
    )
    error_message = "message_retention_seconds must be between 60 and 1209600."
  }
}

variable "visibility_timeout_seconds" {
  description = "Initial SQS visibility timeout for audit export processing."
  type        = number
  default     = 90
  nullable    = false

  validation {
    condition = (
      var.visibility_timeout_seconds >= 30 &&
      var.visibility_timeout_seconds <= 43200
    )
    error_message = "visibility_timeout_seconds must be between 30 and 43200."
  }
}

variable "max_receive_count" {
  description = "Number of receives before SQS moves a message to the DLQ."
  type        = number
  default     = 5
  nullable    = false

  validation {
    condition = (
      var.max_receive_count >= 1 &&
      var.max_receive_count <= 100
    )
    error_message = "max_receive_count must be between 1 and 100."
  }
}

variable "tags" {
  description = "Additional tags applied to audit export resources."
  type        = map(string)
  default     = {}
  nullable    = false
}