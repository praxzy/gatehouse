output "state_bucket_name" {
  description = "S3 bucket that stores Gatehouse Terraform state."
  value       = aws_s3_bucket.terraform_state.bucket
}

output "github_deploy_role_arn" {
  description = "Role ARN configured as the GitHub production environment variable AWS_DEPLOY_ROLE_ARN."
  value       = aws_iam_role.github_deploy.arn
}

output "github_oidc_provider_arn" {
  description = "GitHub Actions OIDC provider used by the deployment role."
  value       = local.github_oidc_provider_arn
}

output "trusted_github_subject" {
  description = "Exact GitHub OIDC subject allowed to assume the deployment role."
  value       = local.github_subject
}
