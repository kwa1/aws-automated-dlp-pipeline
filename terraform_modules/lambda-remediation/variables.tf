variable "function_name" {
  description = "Name of the remediation Lambda function (also names its log group)"
  type        = string
}

variable "failure_queue_name" {
  description = "Name of the SQS queue that receives events the Lambda failed to process after all retries. The IAM module grants sqs:SendMessage on the queue with this name."
  type        = string
}

variable "role_arn" {
  description = "ARN of the IAM role assumed by the Lambda"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda log group (days)"
  type        = number
  default     = 90
}
