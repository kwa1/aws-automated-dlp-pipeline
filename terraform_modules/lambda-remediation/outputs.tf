output "lambda_arn" {
  description = "ARN of the remediation Lambda"
  value       = aws_lambda_function.this.arn
}

output "lambda_name" {
  description = "Name of the remediation Lambda"
  value       = aws_lambda_function.this.function_name
}

output "failure_queue_name" {
  description = "Name of the queue that receives events the Lambda failed to process"
  value       = aws_sqs_queue.failures.name
}
