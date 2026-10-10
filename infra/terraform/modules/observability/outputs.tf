output "alarm_names" {
  description = "CloudWatch alarms created for Gatehouse operational signals."

  value = concat(
    [
      aws_cloudwatch_metric_alarm.database_cpu_pressure.alarm_name,
      aws_cloudwatch_metric_alarm.database_low_storage.alarm_name,
      aws_cloudwatch_metric_alarm.audit_export_dlq.alarm_name,
    ],
    aws_cloudwatch_metric_alarm.api_target_5xx[*].alarm_name,
    aws_cloudwatch_metric_alarm.api_no_healthy_targets[*].alarm_name,
  )
}
