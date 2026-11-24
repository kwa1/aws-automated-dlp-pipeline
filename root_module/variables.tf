variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment (used for tagging and resource names)"
  type        = string

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be either \"staging\" or \"production\"."
  }
}

variable "allowed_account_id" {
  description = "AWS account ID this environment may be applied to. The provider refuses to run against any other account, so a wrong role or profile cannot deploy into the wrong account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account ID (replace the REPLACE-ME placeholder)."
  }
}

variable "bucket_name" {
  description = "Name of the S3 bucket protected by the DLP pipeline"
  type        = string

  validation {
    condition     = !can(regex("REPLACE-ME", var.bucket_name))
    error_message = "bucket_name still contains the REPLACE-ME placeholder."
  }
}

variable "alert_emails" {
  description = "Email addresses that receive cost and pipeline alarms"
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "At least one alert email address is required."
  }

  validation {
    condition     = alltrue([for e in var.alert_emails : !can(regex("REPLACE-ME", e))])
    error_message = "alert_emails still contains the REPLACE-ME placeholder."
  }
}

variable "monthly_limit_usd" {
  description = "Monthly cost budget (USD) for DLP resources"
  type        = number
  default     = 300
}

variable "break_glass_role_arns" {
  description = "IAM role ARNs that may still read Sensitive objects and change their tags (incident response, false-positive release). Leave empty unless such a role exists; no one can read a Sensitive object without one."
  type        = list(string)
  default     = []
}

variable "fail_closed" {
  description = "Deny reads of every object until Macie has scanned it (Scanned=true). Safer, but new uploads are unreadable for up to a day, so leave false unless that delay is acceptable."
  type        = bool
  default     = false
}

variable "activate_cost_allocation_tag" {
  description = "Activate the CostCenter cost allocation tag so the budget can filter on it. Needs the tag to have appeared in billing data (up to 24h after first deploy). Account-wide: enable in only one environment per account."
  type        = bool
  default     = false
}
