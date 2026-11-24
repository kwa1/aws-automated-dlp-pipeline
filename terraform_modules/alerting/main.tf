resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

locals {
  queues = {
    eventbridge-dlq      = var.dlq_name
    remediation-failures = var.failure_queue_name
  }

  functions = merge(
    { remediation = var.lambda_name },
    var.sweeper_enabled ? { sweeper = var.sweeper_function_name } : {},
  )

  rule_metrics = toset(["FailedInvocations", "InvocationsFailedToBeSentToDlq"])
}

# Anything sitting in these queues is a sensitive-data finding that was NOT remediated.
resource "aws_cloudwatch_metric_alarm" "queue_not_empty" {
  for_each = local.queues

  alarm_name          = "${var.name_prefix}-${each.key}-not-empty"
  alarm_description   = "Messages in ${each.value}: a Macie finding event was not processed. Investigate and replay."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.functions

  alarm_name          = "${var.name_prefix}-${each.key}-lambda-errors"
  alarm_description   = "${each.value} reported invocation errors."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "rule_delivery" {
  for_each = local.rule_metrics

  alarm_name          = "${var.name_prefix}-macie-rule-${lower(each.value)}"
  alarm_description   = "EventBridge rule ${var.rule_name} reported ${each.value}."
  namespace           = "AWS/Events"
  metric_name         = each.value
  dimensions          = { RuleName = var.rule_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}
