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
