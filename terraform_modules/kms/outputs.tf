output "key_arn" {
  description = "ARN of the DLP KMS key"
  value       = aws_kms_key.this.arn
}
