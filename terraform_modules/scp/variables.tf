variable "name" {
  description = "Name of the service control policy"
  type        = string
  default     = "dlp-guardrails"
}

variable "target_ids" {
  description = "Organization root, OU or account IDs the SCP is attached to. SCPs never apply to the management account itself."
  type        = list(string)

  validation {
    condition     = length(var.target_ids) > 0
    error_message = "At least one target (root, OU or account ID) is required."
  }
}

variable "exempt_principal_arns" {
  description = "IAM role ARNs (wildcards allowed) that may still administer the DLP pipeline: the Terraform apply roles, the remediation Lambda role and break-glass roles. Without these the SCP would block the pipeline's own deployment and remediation."
  type        = list(string)

  validation {
    condition     = length(var.exempt_principal_arns) > 0
    error_message = "exempt_principal_arns must include at least the Terraform apply role, otherwise the SCP locks out deployments."
  }
}

variable "protected_bucket_arns" {
  description = "ARNs of the DLP buckets whose bucket policy must not be changed or removed outside the exempt principals"
  type        = list(string)

  validation {
    condition     = length(var.protected_bucket_arns) > 0
    error_message = "At least one protected bucket ARN is required."
  }
}

variable "resource_name_pattern" {
  description = "Name pattern shared by the pipeline's Lambda functions and EventBridge rules (the name_prefix used by the root module, plus a wildcard)"
  type        = string
  default     = "dlp-*"
}
