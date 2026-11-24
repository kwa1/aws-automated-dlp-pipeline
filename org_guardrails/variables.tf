variable "region" {
  description = "Region for the Organizations API calls (Organizations is global; any region works)"
  type        = string
  default     = "us-east-1"
}

variable "management_account_id" {
  description = "ID of the AWS Organizations management account this stack must run in. The provider refuses to run anywhere else."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit AWS account ID."
  }
}

variable "target_ids" {
  description = "Organization root (r-xxxx), OU (ou-xxxx-xxxxxxxx) or account IDs the SCP is attached to. Start with a staging OU or account and widen after verifying."
  type        = list(string)
}

variable "exempt_principal_arns" {
  description = "Role ARNs (wildcards allowed) that may still administer the pipeline, e.g. arn:aws:iam::*:role/dlp-*-lambda-role and the Terraform apply roles"
  type        = list(string)
}

variable "protected_bucket_arns" {
  description = "ARNs of the DLP buckets whose bucket policy is protected"
  type        = list(string)
}

variable "resource_name_pattern" {
  description = "Name pattern of the pipeline's Lambda functions and EventBridge rules, e.g. dlp-*"
  type        = string
  default     = "dlp-*"
}
