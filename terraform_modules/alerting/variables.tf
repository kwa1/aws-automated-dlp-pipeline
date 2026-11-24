variable "name_prefix" {
  description = "Prefix for resource names, e.g. dlp-staging"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the CMK that encrypts the alerts topic (its key policy must allow cloudwatch.amazonaws.com)"
  type        = string
}

variable "alert_emails" {
  description = "Email addresses subscribed to pipeline alarms (each must confirm the subscription)"
  type        = list(string)
}

variable "dlq_name" {
  description = "Name of the EventBridge dead-letter queue"
  type        = string
}

variable "failure_queue_name" {
  description = "Name of the Lambda on-failure destination queue"
  type        = string
}

variable "lambda_name" {
  description = "Name of the remediation Lambda"
  type        = string
}

variable "rule_name" {
  description = "Name of the EventBridge rule that routes Macie findings"
  type        = string
}

variable "sweeper_enabled" {
  description = "Whether the fail-closed sweeper exists. Kept separate from its name because the name is unknown until apply, and for_each keys must be known at plan time."
  type        = bool
  default     = false
}

variable "sweeper_function_name" {
  description = "Name of the fail-closed sweeper Lambda (only used when sweeper_enabled is true)"
  type        = string
  default     = ""
}
