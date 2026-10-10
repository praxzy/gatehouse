mock_provider "aws" {
  override_during = plan
}

run "production_alarm_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "prod"

    monitor_api_service         = true
    load_balancer_arn_suffix    = "app/gatehouse-prod/0123456789abcdef"
    api_target_group_arn_suffix = "targetgroup/gatehouse-prod-api/0123456789abcdef"
    database_identifier         = "gatehouse-prod-postgres"
    dead_letter_queue_name      = "gatehouse-prod-audit-export-dlq"

    alarm_action_arns = [
      "arn:aws:sns:ap-south-1:123456789012:gatehouse-prod-operations",
    ]
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.api_target_5xx[0].namespace == "AWS/ApplicationELB" &&
      aws_cloudwatch_metric_alarm.api_target_5xx[0].metric_name == "HTTPCode_Target_5XX_Count" &&
      aws_cloudwatch_metric_alarm.api_target_5xx[0].statistic == "Sum" &&
      aws_cloudwatch_metric_alarm.api_target_5xx[0].dimensions.LoadBalancer == "app/gatehouse-prod/0123456789abcdef" &&
      aws_cloudwatch_metric_alarm.api_target_5xx[0].dimensions.TargetGroup == "targetgroup/gatehouse-prod-api/0123456789abcdef"
    )
    error_message = "The API 5xx alarm must use the ALB target metric and exact resource dimensions."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.api_no_healthy_targets[0].metric_name == "HealthyHostCount" &&
      aws_cloudwatch_metric_alarm.api_no_healthy_targets[0].comparison_operator == "LessThanThreshold" &&
      aws_cloudwatch_metric_alarm.api_no_healthy_targets[0].threshold == 1 &&
      aws_cloudwatch_metric_alarm.api_no_healthy_targets[0].treat_missing_data == "breaching"
    )
    error_message = "The healthy-target alarm must detect both zero hosts and missing service metrics."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.database_cpu_pressure.namespace == "AWS/RDS" &&
      aws_cloudwatch_metric_alarm.database_cpu_pressure.metric_name == "CPUUtilization" &&
      aws_cloudwatch_metric_alarm.database_cpu_pressure.dimensions.DBInstanceIdentifier == "gatehouse-prod-postgres"
    )
    error_message = "The database CPU alarm must target the exact RDS instance."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.database_low_storage.metric_name == "FreeStorageSpace" &&
      aws_cloudwatch_metric_alarm.database_low_storage.comparison_operator == "LessThanOrEqualToThreshold"
    )
    error_message = "The database storage alarm must detect low free space."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.audit_export_dlq.namespace == "AWS/SQS" &&
      aws_cloudwatch_metric_alarm.audit_export_dlq.metric_name == "ApproximateNumberOfMessagesVisible" &&
      aws_cloudwatch_metric_alarm.audit_export_dlq.dimensions.QueueName == "gatehouse-prod-audit-export-dlq"
    )
    error_message = "The DLQ alarm must detect visible failed export messages in the exact queue."
  }

  assert {
    condition = alltrue([
      for alarm in concat(
        aws_cloudwatch_metric_alarm.api_target_5xx,
        aws_cloudwatch_metric_alarm.api_no_healthy_targets,
        [
          aws_cloudwatch_metric_alarm.database_cpu_pressure,
          aws_cloudwatch_metric_alarm.database_low_storage,
          aws_cloudwatch_metric_alarm.audit_export_dlq,
        ],
        ) : contains(
        alarm.alarm_actions,
        "arn:aws:sns:ap-south-1:123456789012:gatehouse-prod-operations",
      )
    ])
    error_message = "Every alarm must notify the configured operations destination."
  }
}

run "inactive_development_api_contract" {
  command = plan

  variables {
    project_name = "gatehouse"
    environment  = "dev"

    monitor_api_service         = false
    load_balancer_arn_suffix    = "app/gatehouse-dev/0123456789abcdef"
    api_target_group_arn_suffix = "targetgroup/gatehouse-dev-api/0123456789abcdef"
    database_identifier         = "gatehouse-dev-postgres"
    dead_letter_queue_name      = "gatehouse-dev-audit-export-dlq"
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.api_target_5xx) == 0 &&
      length(aws_cloudwatch_metric_alarm.api_no_healthy_targets) == 0
    )
    error_message = "A deliberately scaled-to-zero development API must not produce noisy ALB alarms."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.database_cpu_pressure.alarm_name == "gatehouse-dev-database-high-cpu" &&
      aws_cloudwatch_metric_alarm.audit_export_dlq.alarm_name == "gatehouse-dev-audit-export-dlq-not-empty"
    )
    error_message = "Database and DLQ alarms remain active when the development API is scaled to zero."
  }
}
