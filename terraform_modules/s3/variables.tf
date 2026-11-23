variable "bucket" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "kms_key_id" {
  description = "ARN of the KMS key used for default bucket encryption"
  type        = string
}
