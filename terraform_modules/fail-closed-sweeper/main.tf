data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "archive_file" "sweeper" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/build/sweeper.zip"
  excludes    = ["__pycache__"]
}

locals {
  function_name = "${var.name_prefix}-fail-closed-sweeper"
}

resource "aws_cloudwatch_log_group" "sweeper" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "sweeper" {
  name = "${var.name_prefix}-sweeper-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "sweeper" {
  statement {
    sid       = "ListBucketVersions"
    effect    = "Allow"
    actions   = ["s3:ListBucketVersions"]
    resources = [var.bucket_arn]
  }

  statement {
    sid       = "MarkObjectsScanned"
    effect    = "Allow"
    actions   = ["s3:GetObjectVersionTagging", "s3:PutObjectVersionTagging"]
    resources = ["${var.bucket_arn}/*"]
  }

  statement {
    sid       = "ReadMacieJobStatus"
    effect    = "Allow"
    actions   = ["macie2:DescribeClassificationJob"]
    resources = [var.macie_job_arn]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.sweeper.arn}:*"]
  }
}

resource "aws_iam_role_policy" "sweeper" {
  name   = "${var.name_prefix}-sweeper-policy"
  role   = aws_iam_role.sweeper.id
  policy = data.aws_iam_policy_document.sweeper.json
}

resource "aws_lambda_function" "sweeper" {
  function_name = local.function_name
  role          = aws_iam_role.sweeper.arn
  runtime       = "python3.13"
  handler       = "handler.lambda_handler"
  timeout       = 300

  filename         = data.archive_file.sweeper.output_path
  source_code_hash = data.archive_file.sweeper.output_base64sha256

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.sweeper.name
  }

  environment {
    variables = {
      LOG_LEVEL     = "INFO"
      BUCKET_NAME   = var.bucket_name
      MACIE_JOB_ID  = var.macie_job_id
      GRACE_MINUTES = tostring(var.grace_minutes)
    }
  }

  depends_on = [aws_cloudwatch_log_group.sweeper, aws_iam_role_policy.sweeper]
}

resource "aws_cloudwatch_event_rule" "sweep" {
  name                = "${var.name_prefix}-fail-closed-sweep"
  description         = "Periodically release objects Macie has scanned (fail-closed mode)"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "sweep" {
  rule = aws_cloudwatch_event_rule.sweep.name
  arn  = aws_lambda_function.sweeper.arn
}

resource "aws_lambda_permission" "sweep" {
  statement_id  = "AllowEventBridgeSweep"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sweeper.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweep.arn
}
