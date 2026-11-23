variable "role_arn" {
  description = "ARN of the IAM role assumed by the Lambda"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda log group (days)"
  type        = number
  default     = 90
}
