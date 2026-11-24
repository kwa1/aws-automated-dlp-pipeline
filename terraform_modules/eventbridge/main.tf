resource "aws_cloudwatch_event_rule" "macie" {
  name        = "${var.name_prefix}-macie-findings"
  description = "Route every Macie sensitive-data classification finding to the DLP remediation Lambda"

  # No severity filter: Macie rates small PII counts as Low, and a DLP control must lock
  # those objects too.
  event_pattern = jsonencode({
    source        = ["aws.macie"]
    "detail-type" = ["Macie Finding"]
    detail = {
      category = ["CLASSIFICATION"]
    }
  })
}

# Events EventBridge cannot deliver to the Lambda (after retries) land here instead of
# being dropped. An alarm fires on any visible message.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-eventbridge-dlq"
  message_retention_seconds = var.dlq_message_retention_seconds
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "AllowRuleToSendFailedEvents"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.macie.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.macie.name
  arn  = var.lambda_arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  depends_on = [aws_sqs_queue_policy.dlq]
}

resource "aws_lambda_permission" "allow" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.macie.arn
}
