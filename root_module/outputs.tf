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

output "remediation_role_arn" {
  description = "ARN of the remediation Lambda role (exempt this from the org_guardrails SCP)"
  value       = module.iam.lambda_role_arn
}

output "alerts_topic_arn" {
  description = "ARN of the SNS topic that receives pipeline alarms"
  value       = module.alerting.topic_arn
}
