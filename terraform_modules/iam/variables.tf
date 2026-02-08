variable "role_name" {
  description = "Name of the IAM role for the DLP Lambda"
  type        = string
  default     = "macie-dlp-lambda-role"
}

variable "policy_name" {
  description = "Name of the IAM policy for the DLP Lambda"
  type        = string
  default     = "macie-dlp-lambda-policy"
}
