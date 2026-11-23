resource "aws_cloudwatch_event_rule" "macie" {
  name        = "macie-findings"
  description = "Route Macie sensitive-data classification findings to the DLP remediation Lambda"

  event_pattern = jsonencode({
    source        = ["aws.macie"]
    "detail-type" = ["Macie Finding"]
    detail = {
      category = ["CLASSIFICATION"]
      severity = {
        description = ["High", "Medium"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.macie.name
  arn  = var.lambda_arn
}

resource "aws_lambda_permission" "allow" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.macie.arn
}
