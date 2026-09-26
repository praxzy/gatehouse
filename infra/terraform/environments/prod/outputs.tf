output "vpc_id" {
  description = "Production VPC ID."
  value       = module.network_rds.vpc_id
}

output "public_subnet_ids" {
  description = "Production public subnet IDs."
  value       = module.network_rds.public_subnet_ids
}

output "application_subnet_ids" {
  description = "Production private application subnet IDs."
  value       = module.network_rds.application_subnet_ids
}

output "application_security_group_id" {
  description = "Security group for production application workloads."
  value       = module.network_rds.application_security_group_id
}

output "database_address" {
  description = "Private production PostgreSQL hostname."
  value       = module.network_rds.database_address
}

output "database_port" {
  description = "Production PostgreSQL port."
  value       = module.network_rds.database_port
}

output "database_name" {
  description = "Production PostgreSQL database name."
  value       = module.network_rds.database_name
}

output "database_master_secret_arn" {
  description = "ARN of the AWS-managed production database secret."
  value       = module.network_rds.database_master_secret_arn
}