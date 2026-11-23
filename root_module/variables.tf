variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment (used for tagging)"
  type        = string

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be either \"staging\" or \"production\"."
  }
}

variable "bucket_name" {
  description = "Name of the S3 bucket protected by the DLP pipeline"
  type        = string
}

variable "alert_emails" {
  description = "Email addresses that receive cost budget and anomaly alerts"
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "At least one alert email address is required."
  }
}

variable "monthly_limit_usd" {
  description = "Monthly cost budget (USD) for DLP resources"
  type        = number
  default     = 300
}
