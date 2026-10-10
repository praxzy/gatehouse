locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = merge(
    var.tags,
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Purpose     = "operational-readiness"
    },
  )

  api_dimensions = {
    LoadBalancer = var.load_balancer_arn_suffix
    TargetGroup  = var.api_target_group_arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "api_target_5xx" {
  count = var.monitor_api_service ? 1 : 0

  alarm_name        = "${local.name_prefix}-api-target-5xx"
  alarm_description = "Gatehouse API targets returned elevated HTTP 5xx responses."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_Target_5XX_Count"
  dimensions  = local.api_dimensions

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = var.target_5xx_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = sort(tolist(var.alarm_action_arns))
  tags          = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "api_no_healthy_targets" {
  count = var.monitor_api_service ? 1 : 0

  alarm_name        = "${local.name_prefix}-api-no-healthy-targets"
  alarm_description = "Gatehouse has no healthy API target for two consecutive minutes."

  namespace   = "AWS/ApplicationELB"
  metric_name = "HealthyHostCount"
  dimensions  = local.api_dimensions

  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = sort(tolist(var.alarm_action_arns))
  tags          = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_cpu_pressure" {
  alarm_name        = "${local.name_prefix}-database-high-cpu"
  alarm_description = "Gatehouse RDS CPU has remained above the operating threshold."

  namespace   = "AWS/RDS"
  metric_name = "CPUUtilization"
  dimensions = {
    DBInstanceIdentifier = var.database_identifier
  }

  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = var.database_cpu_threshold_percent
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "missing"

  alarm_actions = sort(tolist(var.alarm_action_arns))
  tags          = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_low_storage" {
  alarm_name        = "${local.name_prefix}-database-low-storage"
  alarm_description = "Gatehouse RDS free storage is below the safe operating threshold."

  namespace   = "AWS/RDS"
  metric_name = "FreeStorageSpace"
  dimensions = {
    DBInstanceIdentifier = var.database_identifier
  }

  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = var.database_free_storage_threshold_bytes
  comparison_operator = "LessThanOrEqualToThreshold"
  treat_missing_data  = "missing"

  alarm_actions = sort(tolist(var.alarm_action_arns))
  tags          = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "audit_export_dlq" {
  alarm_name        = "${local.name_prefix}-audit-export-dlq-not-empty"
  alarm_description = "One or more audit export messages require operator attention in the DLQ."

  namespace   = "AWS/SQS"
  metric_name = "ApproximateNumberOfMessagesVisible"
  dimensions = {
    QueueName = var.dead_letter_queue_name
  }

  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = sort(tolist(var.alarm_action_arns))
  tags          = local.common_tags
}
