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

output "audit_export_queue_url" {
  description = "Production audit export source queue URL."
  value       = module.audit_exports.queue_url
}

output "audit_export_dead_letter_queue_url" {
  description = "Production audit export dead-letter queue URL."
  value       = module.audit_exports.dead_letter_queue_url
}

output "audit_export_bucket_name" {
  description = "Production private audit export bucket."
  value       = module.audit_exports.bucket_name
}

output "ecs_cluster_name" {
  description = "Name of the Gatehouse ECS cluster."
  value       = module.ecs_runtime.cluster_name
}

output "api_repository_url" {
  description = "ECR repository URL for the Gatehouse API."
  value       = module.ecs_runtime.api_repository_url
}

output "worker_repository_url" {
  description = "ECR repository URL for the audit-export worker."
  value       = module.ecs_runtime.worker_repository_url
}

output "api_service_name" {
  description = "Name of the Gatehouse API ECS service."
  value       = module.ecs_runtime.api_service_name
}

output "worker_service_name" {
  description = "Name of the audit-export worker ECS service."
  value       = module.ecs_runtime.worker_service_name
}

output "load_balancer_dns_name" {
  description = "Public DNS name of the Gatehouse application load balancer."
  value       = module.ecs_runtime.load_balancer_dns_name
}

output "api_log_group_name" {
  description = "CloudWatch log group used by the Gatehouse API."
  value       = module.ecs_runtime.api_log_group_name
}

output "worker_log_group_name" {
  description = "CloudWatch log group used by the audit-export worker."
  value       = module.ecs_runtime.worker_log_group_name
}

output "runtime_secret_arns" {
  description = "Secrets Manager ARNs that must be populated outside Terraform."
  value       = module.ecs_runtime.runtime_secret_arns
}

output "cloudwatch_alarm_names" {
  description = "CloudWatch alarms monitoring the production environment."
  value       = module.observability.alarm_names
}
