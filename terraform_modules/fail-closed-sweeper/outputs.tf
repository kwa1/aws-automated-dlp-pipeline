output "role_arn" {
  description = "ARN of the sweeper role (the only principal besides remediation allowed to write the Scanned tag)"
  value       = aws_iam_role.sweeper.arn
}

output "function_name" {
  description = "Name of the sweeper Lambda"
  value       = aws_lambda_function.sweeper.function_name
}
