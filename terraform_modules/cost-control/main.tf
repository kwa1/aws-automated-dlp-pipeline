# Budgets and Cost Explorer can only filter on a tag after it has been activated as a
# cost allocation tag. Until then the tag filter matches nothing and the budget reads $0,
# so the budget filters on the Macie service as well (always accurate), and the tag filter
# is added only once activation is enabled.
resource "aws_ce_cost_allocation_tag" "dlp" {
  count = var.activate_cost_allocation_tag ? 1 : 0

  tag_key = var.cost_allocation_tag_key
  status  = "Active"
}

resource "aws_budgets_budget" "dlp_monthly" {
  name         = "${var.name_prefix}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_limit_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "cost_filter" {
    for_each = var.activate_cost_allocation_tag ? [1] : []

    content {
      name   = "TagKeyValue"
      # Budgets syntax is user:<key>$<value>; format() avoids Terraform's "${" escape.
      values = [format("user:%s$%s", var.cost_allocation_tag_key, var.cost_allocation_tag_value)]
    }
  }

  dynamic "cost_filter" {
    for_each = var.activate_cost_allocation_tag ? [] : [1]

    content {
      name   = "Service"
      values = ["Amazon Macie"]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.alert_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.alert_emails
  }

  depends_on = [aws_ce_cost_allocation_tag.dlp]
}

# Cost anomaly detection across all AWS services in the account.
resource "aws_ce_anomaly_monitor" "services" {
  name              = "${var.name_prefix}-service-cost-anomaly"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

# EMAIL subscribers only support DAILY / WEEKLY summaries; IMMEDIATE requires SNS.
resource "aws_ce_anomaly_subscription" "alerts" {
  name      = "${var.name_prefix}-anomaly-alerts"
  frequency = "DAILY"

  monitor_arn_list = [
    aws_ce_anomaly_monitor.services.arn
  ]

  dynamic "subscriber" {
    for_each = toset(var.alert_emails)

    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = [tostring(var.anomaly_threshold_usd)]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }
}
