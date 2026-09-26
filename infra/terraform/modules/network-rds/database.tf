check "database_engine_family" {
  assert {
    condition = (
      var.database_parameter_group_family ==
      "postgres${split(".", var.database_engine_version)[0]}"
    )
    error_message = "database_parameter_group_family must match the PostgreSQL major engine version."
  }
}

check "production_database_safety" {
  assert {
    condition = (
      var.environment != "prod" ||
      (
        var.database_multi_az &&
        var.database_deletion_protection &&
        !var.database_skip_final_snapshot &&
        var.database_backup_retention_days >= 30
      )
    )
    error_message = "Production requires Multi-AZ, deletion protection, a final snapshot, and at least 30 days of backups."
  }
}

resource "aws_db_subnet_group" "this" {
  name        = "${local.name_prefix}-database"
  description = "Isolated database subnets for Gatehouse"

  subnet_ids = [
    for subnet in aws_subnet.database :
    subnet.id
  ]

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-database"
    },
  )
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${local.name_prefix}-postgres-"
  description = "Gatehouse PostgreSQL security and connection settings"
  family      = var.database_parameter_group_family

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "password_encryption"
    value        = "scram-sha-256"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-postgres"
    },
  )
}

resource "aws_db_instance" "this" {
  identifier = "${local.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = var.database_engine_version
  instance_class = var.database_instance_class

  db_name  = var.database_name
  username = var.database_master_username
  port     = 5432

  manage_master_user_password = true

  allocated_storage     = var.database_allocated_storage
  max_allocated_storage = var.database_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  publicly_accessible = false
  network_type        = "IPV4"
  multi_az            = var.database_multi_az

  backup_retention_period = var.database_backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  auto_minor_version_upgrade = true
  apply_immediately          = false

  deletion_protection = var.database_deletion_protection
  skip_final_snapshot = var.database_skip_final_snapshot
  final_snapshot_identifier = (
    var.database_skip_final_snapshot
    ? null
    : "${local.name_prefix}-postgres-final"
  )

  copy_tags_to_snapshot    = true
  delete_automated_backups = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-postgres"
    },
  )
}