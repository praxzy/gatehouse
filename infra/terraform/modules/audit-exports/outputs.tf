output "queue_name" {
  description = "Name of the audit export source queue."
  value       = aws_sqs_queue.exports.name
}

output "queue_url" {
  description = "URL supplied to the Gatehouse API and export worker."
  value       = aws_sqs_queue.exports.url
}

output "queue_arn" {
  description = "ARN used by API and worker IAM policies."
  value       = aws_sqs_queue.exports.arn
}

output "dead_letter_queue_url" {
  description = "URL of the audit export dead-letter queue."
  value       = aws_sqs_queue.dead_letter.url
}

output "dead_letter_queue_name" {
  description = "Name used as the CloudWatch QueueName dimension for the dead-letter queue."
  value       = aws_sqs_queue.dead_letter.name
}

output "dead_letter_queue_arn" {
  description = "ARN of the audit export dead-letter queue."
  value       = aws_sqs_queue.dead_letter.arn
}

output "bucket_name" {
  description = "Private S3 bucket containing generated audit exports."
  value       = aws_s3_bucket.exports.id
}

output "bucket_arn" {
  description = "ARN used by the export worker IAM policy."
  value       = aws_s3_bucket.exports.arn
}
