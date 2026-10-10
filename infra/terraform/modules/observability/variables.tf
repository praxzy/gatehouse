variable "project_name" {
  description = "Short project name used in alarm names and tags."
  type        = string
  nullable    = false
}

variable "environment" {
  description = "Deployment environment represented by these alarms."
  type        = string
  nullable    = false

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "monitor_api_service" {
  description = "Whether ALB alarms should be active for an API service expected to have running tasks."
  type        = bool
  default     = true
  nullable    = false
}

variable "load_balancer_arn_suffix" {
  description = "Application Load Balancer ARN suffix used by CloudWatch."
  type        = string
  nullable    = false
}

variable "api_target_group_arn_suffix" {
  description = "API target group ARN suffix used by CloudWatch."
  type        = string
  nullable    = false
}

variable "database_identifier" {
  description = "RDS DB instance identifier used by CloudWatch."
  type        = string
  nullable    = false
}

variable "dead_letter_queue_name" {
  description = "Audit export DLQ name used by CloudWatch."
  type        = string
  nullable    = false
}

variable "alarm_action_arns" {
  description = "Optional SNS topic or incident-action ARNs invoked when an alarm enters ALARM."
  type        = set(string)
  default     = []
  nullable    = false
}

variable "target_5xx_threshold" {
  description = "Target-generated 5xx responses within five minutes that trigger an alarm."
  type        = number
  default     = 5
  nullable    = false
}

variable "database_cpu_threshold_percent" {
  description = "Average RDS CPU utilization that triggers an alarm."
  type        = number
  default     = 80
  nullable    = false
}

variable "database_free_storage_threshold_bytes" {
  description = "Free RDS storage below which an alarm is raised."
  type        = number
  default     = 5368709120
  nullable    = false
}

variable "tags" {
  description = "Additional tags applied to alarms."
  type        = map(string)
  default     = {}
  nullable    = false
}
