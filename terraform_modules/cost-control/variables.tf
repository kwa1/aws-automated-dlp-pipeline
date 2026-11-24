variable "name_prefix" {
  description = "Prefix for resource names, e.g. dlp-staging"
  type        = string
}

variable "monthly_limit_usd" {
  description = "Monthly DLP cost limit"
  type        = number
  default     = 300
}

variable "alert_emails" {
  description = "Email addresses for budget alerts"
  type        = list(string)
}

variable "anomaly_threshold_usd" {
  description = "Absolute anomaly impact (USD) that triggers an anomaly alert"
  type        = number
  default     = 50
}

variable "cost_allocation_tag_key" {
  description = "Tag key that identifies DLP resources in cost reports (applied to every resource through the provider's default_tags)"
  type        = string
  default     = "CostCenter"
}

variable "cost_allocation_tag_value" {
  description = "Tag value that identifies DLP resources in cost reports"
  type        = string
  default     = "Security-DLP"
}

variable "activate_cost_allocation_tag" {
  description = "Activate the cost allocation tag. AWS lists a tag key for activation only after it has been applied to billed resources, which can take up to 24 hours, so leave this false for the first deploy and set it true on a later one. Activation is account-wide, so enable it in one environment per account. Needs ce:UpdateCostAllocationTagsStatus (payer account)."
  type        = bool
  default     = false
}
