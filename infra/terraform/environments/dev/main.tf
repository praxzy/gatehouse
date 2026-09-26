module "network_rds" {
  source = "../../modules/network-rds"

  project_name = "gatehouse"
  environment  = "dev"

  vpc_cidr           = "10.20.0.0/16"
  availability_zones = var.availability_zones

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

  database_name                   = "gatehouse"
  database_master_username        = "gatehouse_admin"
  database_engine_version         = "17"
  database_parameter_group_family = "postgres17"
  database_instance_class         = "db.t4g.micro"
  database_allocated_storage      = 20
  database_max_allocated_storage  = 100
  database_backup_retention_days  = 7
  database_multi_az               = false
  database_deletion_protection    = false
  database_skip_final_snapshot    = true

  tags = var.additional_tags
}