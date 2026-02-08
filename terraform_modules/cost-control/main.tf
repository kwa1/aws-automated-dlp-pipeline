resource "aws_budgets_budget" "dlp_monthly" {
  name              = "dlp-monthly-budget"
  budget_type       = "COST"
  limit_amount      = var.monthly_limit_usd
  limit_unit        = "USD"
  time_unit         = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["CostCenter$Security-DLP"]
  }

  notification {
    comparison_operator = "GREATER_THAN"
    threshold           = 80
    threshold_type      = "PERCENTAGE"
    notification_type   = "ACTUAL"

    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator = "GREATER_THAN"
    threshold           = 100
    threshold_type      = "PERCENTAGE"
    notification_type   = "ACTUAL"

    subscriber_email_addresses = var.alert_emails
  }
}
