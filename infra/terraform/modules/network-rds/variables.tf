variable "project_name" {
  description = "Short project name used in resource names and tags."
  type        = string
  default     = "gatehouse"
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

variable "vpc_cidr" {
  description = "IPv4 CIDR block assigned to the VPC."
  type        = string
  nullable    = false

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "availability_zones" {
  description = "Availability zones used by the subnet tiers."
  type        = list(string)
  nullable    = false

  validation {
    condition = (
      length(var.availability_zones) >= 2 &&
      length(distinct(var.availability_zones)) == length(var.availability_zones)
    )
    error_message = "Provide at least two distinct availability zones."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public ingress and NAT subnets."
  type        = list(string)
  nullable    = false

  validation {
    condition = alltrue([
      for cidr in var.public_subnet_cidrs :
      can(cidrhost(cidr, 0))
    ])
    error_message = "Every public subnet must use a valid IPv4 CIDR block."
  }
}

variable "application_subnet_cidrs" {
  description = "CIDR blocks for private application workloads."
  type        = list(string)
  nullable    = false

  validation {
    condition = alltrue([
      for cidr in var.application_subnet_cidrs :
      can(cidrhost(cidr, 0))
    ])
    error_message = "Every application subnet must use a valid IPv4 CIDR block."
  }
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for isolated database subnets."
  type        = list(string)
  nullable    = false

  validation {
    condition = alltrue([
      for cidr in var.database_subnet_cidrs :
      can(cidrhost(cidr, 0))
    ])
    error_message = "Every database subnet must use a valid IPv4 CIDR block."
  }
}

variable "nat_gateway_mode" {
  description = "NAT topology: none, single, or one per availability zone."
  type        = string
  default     = "none"
  nullable    = false

  validation {
    condition     = contains(["none", "single", "per_az"], var.nat_gateway_mode)
    error_message = "nat_gateway_mode must be none, single, or per_az."
  }
}

variable "database_name" {
  description = "Initial PostgreSQL database name."
  type        = string
  default     = "gatehouse"
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.database_name))
    error_message = "database_name must begin with a letter and contain at most 63 letters, numbers, or underscores."
  }
}

variable "database_master_username" {
  description = "RDS administrator username. The password is managed by AWS."
  type        = string
  default     = "gatehouse_admin"
  nullable    = false

  validation {
    condition = (
      can(regex("^[A-Za-z][A-Za-z0-9_]{0,62}$", var.database_master_username)) &&
      lower(var.database_master_username) != "postgres"
    )
    error_message = "database_master_username must be a valid identifier and cannot be postgres."
  }
}

variable "database_engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "17"
  nullable    = false
}

variable "database_parameter_group_family" {
  description = "RDS parameter-group family matching the PostgreSQL major version."
  type        = string
  default     = "postgres17"
  nullable    = false
}

variable "database_instance_class" {
  description = "RDS database instance class."
  type        = string
  nullable    = false
}

variable "database_allocated_storage" {
  description = "Initial database storage in GiB."
  type        = number
  default     = 20
  nullable    = false

  validation {
    condition     = var.database_allocated_storage >= 20
    error_message = "database_allocated_storage must be at least 20 GiB."
  }
}

variable "database_max_allocated_storage" {
  description = "Maximum storage autoscaling limit in GiB."
  type        = number
  nullable    = false
}

variable "database_backup_retention_days" {
  description = "Number of days automated backups are retained."
  type        = number
  nullable    = false

  validation {
    condition = (
      var.database_backup_retention_days >= 1 &&
      var.database_backup_retention_days <= 35
    )
    error_message = "database_backup_retention_days must be between 1 and 35."
  }
}

variable "database_multi_az" {
  description = "Whether RDS maintains a synchronous standby in another availability zone."
  type        = bool
  nullable    = false
}

variable "database_deletion_protection" {
  description = "Whether RDS refuses deletion until protection is explicitly disabled."
  type        = bool
  nullable    = false
}

variable "database_skip_final_snapshot" {
  description = "Whether database destruction skips the final snapshot."
  type        = bool
  nullable    = false
}

variable "tags" {
  description = "Additional tags applied to every supported resource."
  type        = map(string)
  default     = {}
  nullable    = false
}