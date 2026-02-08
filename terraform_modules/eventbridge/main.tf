resource "aws_cloudwatch_event_rule" "macie" {
  name = "macie-findings"
  event_pattern = jsonencode({
    source = ["aws.macie"]
    detail-type = ["Macie Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
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
