mock_provider "aws" {
  override_during = plan
}

override_resource {
  target          = aws_security_group.application
  override_during = plan

  values = {
    id = "sg-00000000000000001"
  }
}

override_resource {
  target          = aws_security_group.database
  override_during = plan

  values = {
    id = "sg-00000000000000002"
  }
}

run "development_security_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "dev"

    vpc_cidr           = "10.20.0.0/16"
    availability_zones = ["ap-south-1a", "ap-south-1b"]

    public_subnet_cidrs = [
      "10.20.0.0/24",
      "10.20.1.0/24",
    ]

    application_subnet_cidrs = [
      "10.20.10.0/24",
      "10.20.11.0/24",
    ]

    database_subnet_cidrs = [
      "10.20.20.0/24",
      "10.20.21.0/24",
    ]

    nat_gateway_mode = "none"

    database_instance_class        = "db.t4g.micro"
    database_max_allocated_storage = 100
    database_backup_retention_days = 7
    database_multi_az              = false
    database_deletion_protection   = false
    database_skip_final_snapshot   = true
  }

  assert {
    condition     = !aws_db_instance.this.publicly_accessible
    error_message = "Development RDS must not be public."
  }

  assert {
    condition     = aws_db_instance.this.storage_encrypted
    error_message = "Development RDS storage must be encrypted."
  }

  assert {
    condition     = aws_db_instance.this.manage_master_user_password
    error_message = "AWS must manage the development database password."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 0
    error_message = "Development must not create billable NAT gateways."
  }

  assert {
    condition     = length(aws_route.application_internet) == 0
    error_message = "Development application subnets must not receive an internet route."
  }

  assert {
    condition = alltrue([
      for subnet in values(aws_subnet.database) :
      !subnet.map_public_ip_on_launch
    ])
    error_message = "Database subnets must not assign public IP addresses."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.database_from_application.referenced_security_group_id ==
      aws_security_group.application.id
    )
    error_message = "Database ingress must reference the application security group."
  }

  assert {
    condition = contains(
      aws_db_instance.this.vpc_security_group_ids,
      aws_security_group.database.id,
    )
    error_message = "RDS must use the database security group."
  }
}

run "production_security_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "prod"

    vpc_cidr           = "10.30.0.0/16"
    availability_zones = ["ap-south-1a", "ap-south-1b"]

    public_subnet_cidrs = [
      "10.30.0.0/24",
      "10.30.1.0/24",
    ]

    application_subnet_cidrs = [
      "10.30.10.0/24",
      "10.30.11.0/24",
    ]

    database_subnet_cidrs = [
      "10.30.20.0/24",
      "10.30.21.0/24",
    ]

    nat_gateway_mode = "per_az"

    database_instance_class        = "db.t4g.small"
    database_allocated_storage     = 50
    database_max_allocated_storage = 500
    database_backup_retention_days = 35
    database_multi_az              = true
    database_deletion_protection   = true
    database_skip_final_snapshot   = false
  }

  assert {
    condition     = !aws_db_instance.this.publicly_accessible
    error_message = "Production RDS must not be public."
  }

  assert {
    condition     = aws_db_instance.this.storage_encrypted
    error_message = "Production RDS storage must be encrypted."
  }

  assert {
    condition     = aws_db_instance.this.manage_master_user_password
    error_message = "AWS must manage the production database password."
  }

  assert {
    condition     = aws_db_instance.this.multi_az
    error_message = "Production RDS must be Multi-AZ."
  }

  assert {
    condition     = aws_db_instance.this.deletion_protection
    error_message = "Production RDS must enable deletion protection."
  }

  assert {
    condition     = !aws_db_instance.this.skip_final_snapshot
    error_message = "Production destruction must retain a final snapshot."
  }

  assert {
    condition     = aws_db_instance.this.backup_retention_period >= 30
    error_message = "Production must retain at least 30 days of automated backups."
  }

  assert {
    condition     = length(aws_nat_gateway.this) == 2
    error_message = "Production must plan one NAT gateway per availability zone."
  }

  assert {
    condition     = length(aws_route.application_internet) == 2
    error_message = "Each production application subnet needs its NAT route."
  }

  assert {
    condition = alltrue([
      for subnet in values(aws_subnet.database) :
      !subnet.map_public_ip_on_launch
    ])
    error_message = "Production database subnets must not assign public IP addresses."
  }

  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.database_from_application.referenced_security_group_id ==
      aws_security_group.application.id
    )
    error_message = "Production database ingress must reference the application security group."
  }

  assert {
    condition = contains(
      aws_db_instance.this.vpc_security_group_ids,
      aws_security_group.database.id,
    )
    error_message = "Production RDS must use the database security group."
  }
}
