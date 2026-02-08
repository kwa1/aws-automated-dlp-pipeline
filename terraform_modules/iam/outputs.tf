output "lambda_role_arn" {
  description = "ARN of the IAM role assumed by the DLP Lambda"
  value       = aws_iam_role.lambda_dlp.arn
}

output "lambda_role_name" {
  description = "Name of the IAM role assumed by the DLP Lambda"
  value       = aws_iam_role.lambda_dlp.name
}
