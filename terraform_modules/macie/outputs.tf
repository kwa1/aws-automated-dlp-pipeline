output "job_id" {
  description = "ID of the recurring Macie classification job"
  value       = aws_macie2_classification_job.scan.job_id
}

output "job_arn" {
  description = "ARN of the recurring Macie classification job"
  value       = aws_macie2_classification_job.scan.job_arn
}
