variable "bucket_name" {
  description = "Name of the bucket the DLP deny policy is attached to"
  type        = string
}

variable "remediation_role_arn" {
  description = "ARN of the remediation Lambda role. It is the only principal (besides break-glass roles) allowed to change tags on Sensitive objects."
  type        = string
}

variable "sweeper_role_arn" {
  description = "ARN of the fail-closed sweeper role, which alone may write the Scanned tag. Empty when fail_closed is false."
  type        = string
  default     = ""
}

variable "break_glass_role_arns" {
  description = "IAM role ARNs exempt from the read and tag-protection denies (incident response, false-positive release). Keep this list tiny and monitor use of these roles through CloudTrail."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for arn in var.break_glass_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", arn))])
    error_message = "break_glass_role_arns must contain IAM role ARNs (arn:aws:iam::<account>:role/<name>)."
  }
}

variable "fail_closed" {
  description = "Deny reads of every object that is not tagged Scanned=true. Objects are unreadable until Macie has scanned them and the sweeper has cleared them."
  type        = bool
  default     = false
}
