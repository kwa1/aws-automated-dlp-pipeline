variable "name_prefix" {
  description = "Prefix for resource names, e.g. dlp-staging"
  type        = string
}

variable "lambda_arn" {
  description = "ARN of the Lambda function invoked for Macie findings"
  type        = string
}

variable "dlq_message_retention_seconds" {
  description = "How long undelivered events are kept in the dead-letter queue"
  type        = number
  default     = 1209600 # 14 days, the SQS maximum
}
