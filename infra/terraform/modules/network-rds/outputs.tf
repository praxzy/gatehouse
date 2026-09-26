output "vpc_id" {
  description = "ID of the Gatehouse VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs keyed by availability zone."

  value = {
    for availability_zone, subnet in aws_subnet.public :
    availability_zone => subnet.id
  }
}

output "application_subnet_ids" {
  description = "Private application subnet IDs keyed by availability zone."

  value = {
    for availability_zone, subnet in aws_subnet.application :
    availability_zone => subnet.id
  }
}

output "database_subnet_ids" {
  description = "Isolated database subnet IDs keyed by availability zone."

  value = {
    for availability_zone, subnet in aws_subnet.database :
    availability_zone => subnet.id
  }
}

output "application_security_group_id" {
  description = "Security group to attach to Gatehouse application workloads."
  value       = aws_security_group.application.id
}

output "database_security_group_id" {
  description = "Security group attached to PostgreSQL."
  value       = aws_security_group.database.id
}

output "nat_gateway_ids" {
  description = "NAT gateway IDs keyed by availability zone."

  value = {
    for availability_zone, nat_gateway in aws_nat_gateway.this :
    availability_zone => nat_gateway.id
  }
}

output "database_address" {
  description = "Private PostgreSQL hostname."
  value       = aws_db_instance.this.address
}

output "database_port" {
  description = "PostgreSQL listener port."
  value       = aws_db_instance.this.port
}

output "database_name" {
  description = "Initial PostgreSQL database name."
  value       = aws_db_instance.this.db_name
}

output "database_master_username" {
  description = "PostgreSQL administrator username."
  value       = aws_db_instance.this.username
}

output "database_master_secret_arn" {
  description = "ARN of the AWS-managed master-password secret."

  value = try(
    aws_db_instance.this.master_user_secret[0].secret_arn,
    null,
  )
}