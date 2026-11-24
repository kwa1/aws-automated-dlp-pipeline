output "rule_name" {
  description = "Name of the EventBridge rule that routes Macie findings"
  value       = aws_cloudwatch_event_rule.macie.name
}

output "dlq_name" {
  description = "Name of the dead-letter queue for undelivered finding events"
  value       = aws_sqs_queue.dlq.name
}
