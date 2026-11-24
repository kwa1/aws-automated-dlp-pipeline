variable "name_prefix" {
  description = "Prefix for the role and policy names, e.g. dlp-staging"
  type        = string
}

variable "bucket_arn" {
  description = "ARN of the DLP-protected bucket the Lambda is allowed to tag"
  type        = string
}

variable "failure_queue_name" {
  description = "Name of the queue the Lambda's async failure destination sends to"
  type        = string
}
