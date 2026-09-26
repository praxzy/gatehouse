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