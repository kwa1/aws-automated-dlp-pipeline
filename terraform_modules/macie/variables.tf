variable "name_prefix" {
  description = "Prefix for resource names, e.g. dlp-staging"
  type        = string
}

variable "s3_buckets" {
  description = "Names of the S3 buckets Macie should classify"
  type        = list(string)
}

variable "finding_publishing_frequency" {
  description = "How often Macie publishes updates to existing findings. FIFTEEN_MINUTES is the fastest Macie offers; new findings are still published as they are created."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS."
  }
}
