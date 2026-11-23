output "bucket_name" {
  description = "Name of the DLP-protected S3 bucket"
  value       = module.s3.bucket
}

output "kms_key_arn" {
  description = "ARN of the KMS key encrypting the bucket"
  value       = module.kms.key_arn
}

output "remediation_lambda_arn" {
  description = "ARN of the Macie remediation Lambda"
  value       = module.lambda_remediation.lambda_arn
}
