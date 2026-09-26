module "network_rds" {
  source = "../../modules/network-rds"

  project_name = "gatehouse"
  environment  = "prod"

  vpc_cidr           = "10.30.0.0/16"
  availability_zones = var.availability_zones

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

  database_name                   = "gatehouse"
  database_master_username        = "gatehouse_admin"
  database_engine_version         = "17"
  database_parameter_group_family = "postgres17"
  database_instance_class         = "db.t4g.small"
  database_allocated_storage      = 50
  database_max_allocated_storage  = 500
  database_backup_retention_days  = 35
  database_multi_az               = true
  database_deletion_protection    = true
  database_skip_final_snapshot    = false

  tags = var.additional_tags
}