variable "monthly_limit_usd" {
  description = "Monthly DLP cost limit"
  type        = number
  default     = 300
}

variable "alert_emails" {
  description = "Email addresses for budget alerts"
  type        = list(string)
}
