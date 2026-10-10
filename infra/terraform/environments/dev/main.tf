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

module "audit_exports" {
  source = "../../modules/audit-exports"

  project_name = "gatehouse"
  environment  = "dev"

  export_retention_days      = 30
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 90
  max_receive_count          = 5

  tags = var.additional_tags
}

module "ecs_runtime" {
  source = "../../modules/ecs-runtime"

  project_name = "gatehouse"
  environment  = "dev"
  aws_region   = var.aws_region

  vpc_id                        = module.network_rds.vpc_id
  public_subnet_ids             = toset(values(module.network_rds.public_subnet_ids))
  application_subnet_ids        = toset(values(module.network_rds.application_subnet_ids))
  application_security_group_id = module.network_rds.application_security_group_id

  audit_export_queue_url   = module.audit_exports.queue_url
  audit_export_queue_arn   = module.audit_exports.queue_arn
  audit_export_bucket_name = module.audit_exports.bucket_name
  audit_export_bucket_arn  = module.audit_exports.bucket_arn

  web_app_url           = var.web_app_url
  oidc_issuer           = var.oidc_issuer
  admin_allowed_origins = var.admin_allowed_origins
  certificate_arn       = var.certificate_arn

  api_desired_count    = var.api_desired_count
  worker_desired_count = var.worker_desired_count
  api_image_tag        = var.api_image_tag
  worker_image_tag     = var.worker_image_tag

  enable_load_balancer_deletion_protection = false
  force_delete_ecr_repositories            = true
  log_retention_days                       = 7
  secret_recovery_window_days              = 0

  tags = var.additional_tags
}

module "observability" {
  source = "../../modules/observability"

  project_name = "gatehouse"
  environment  = "dev"

  monitor_api_service         = var.api_desired_count > 0
  load_balancer_arn_suffix    = module.ecs_runtime.load_balancer_arn_suffix
  api_target_group_arn_suffix = module.ecs_runtime.api_target_group_arn_suffix
  database_identifier         = module.network_rds.database_identifier
  dead_letter_queue_name      = module.audit_exports.dead_letter_queue_name
  alarm_action_arns           = var.alarm_action_arns

  tags = var.additional_tags
}
