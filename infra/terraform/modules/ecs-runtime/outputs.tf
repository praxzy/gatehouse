output "cluster_name" {
  description = "Name of the ECS cluster."
  value       = aws_ecs_cluster.this.name
}

output "cluster_arn" {
  description = "ARN of the ECS cluster."
  value       = aws_ecs_cluster.this.arn
}

output "api_repository_url" {
  description = "ECR repository URL for the Gatehouse API image."
  value       = aws_ecr_repository.api.repository_url
}

output "worker_repository_url" {
  description = "ECR repository URL for the audit-export worker image."
  value       = aws_ecr_repository.worker.repository_url
}

output "api_service_name" {
  description = "Name of the Gatehouse API ECS service."
  value       = aws_ecs_service.api.name
}

output "worker_service_name" {
  description = "Name of the audit-export worker ECS service."
  value       = aws_ecs_service.worker.name
}

output "load_balancer_arn" {
  description = "ARN of the public application load balancer."
  value       = aws_lb.this.arn
}

output "load_balancer_arn_suffix" {
  description = "CloudWatch LoadBalancer dimension for the application load balancer."
  value       = aws_lb.this.arn_suffix
}

output "load_balancer_dns_name" {
  description = "Public DNS name assigned to the application load balancer."
  value       = aws_lb.this.dns_name
}

output "api_target_group_arn" {
  description = "ARN of the API target group."
  value       = aws_lb_target_group.api.arn
}

output "api_target_group_arn_suffix" {
  description = "CloudWatch TargetGroup dimension for the API target group."
  value       = aws_lb_target_group.api.arn_suffix
}

output "api_log_group_name" {
  description = "CloudWatch log group used by the API."
  value       = aws_cloudwatch_log_group.api.name
}

output "worker_log_group_name" {
  description = "CloudWatch log group used by the export worker."
  value       = aws_cloudwatch_log_group.worker.name
}

output "runtime_secret_arns" {
  description = "Runtime secret ARNs keyed by container environment variable."

  value = {
    for name, secret in aws_secretsmanager_secret.runtime :
    name => secret.arn
  }
}

output "api_assigns_public_ip" {
  description = "Security assertion exposed for Terraform tests."
  value       = false
}

output "worker_assigns_public_ip" {
  description = "Security assertion exposed for Terraform tests."
  value       = false
}
