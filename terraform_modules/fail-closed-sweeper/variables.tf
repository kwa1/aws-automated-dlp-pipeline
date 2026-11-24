variable "name_prefix" {
  description = "Prefix for resource names, e.g. dlp-staging"
  type        = string
}

variable "bucket_name" {
  description = "Name of the DLP-protected bucket whose objects are marked Scanned=true"
  type        = string
}

variable "bucket_arn" {
  description = "ARN of the DLP-protected bucket"
  type        = string
}

variable "macie_job_arn" {
  description = "ARN of the recurring Macie classification job the sweeper reads the run status of"
  type        = string
}

variable "macie_job_id" {
  description = "ID of the recurring Macie classification job"
  type        = string
}

variable "grace_minutes" {
  description = "Minutes to wait after a Macie job run before clearing objects, so findings can reach the remediation Lambda first"
  type        = number
  default     = 120
}

variable "schedule_expression" {
  description = "How often the sweeper runs"
  type        = string
  default     = "rate(1 hour)"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the sweeper log group (days)"
  type        = number
  default     = 90
}
