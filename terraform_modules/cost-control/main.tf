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
# Macie Cost Anomaly Detector
resource "aws_ce_anomaly_monitor" "macie" {
  name              = "macie-cost-anomaly"
  monitor_type      = "DIMENSIONAL"

  monitor_dimension = "SERVICE"
}
# Alert Subscription
resource "aws_ce_anomaly_subscription" "macie_alerts" {
  name      = "macie-anomaly-alerts"
  frequency = "IMMEDIATE"

  monitor_arn_list = [
    aws_ce_anomaly_monitor.macie.arn
  ]

  subscribers {
    type    = "EMAIL"
    address = var.alert_emails[0]
  }

  threshold_expression {
    dimension {
      key           = "SERVICE"
      values        = ["Amazon Macie"]
      match_options = ["EQUALS"]
    }
  }
}
