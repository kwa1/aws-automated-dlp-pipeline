data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role" "lambda_dlp" {
  name = "${var.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose    = "DLP-Remediation"
    Compliance = "GDPR"
  }
}

data "aws_iam_policy_document" "lambda_dlp" {
  statement {
    sid    = "TagSensitiveObjects"
    effect = "Allow"
    actions = [
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = ["${var.bucket_arn}/*"]
  }

  statement {
    sid       = "ImportSecurityHubFindings"
    effect    = "Allow"
    actions   = ["securityhub:BatchImportFindings"]
    resources = ["arn:aws:securityhub:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:product/${data.aws_caller_identity.current.account_id}/default"]
  }

  # Lambda's on-failure destination sends with the function's execution role.
  statement {
    sid       = "SendFailedEventsToQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = ["arn:aws:sqs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:${var.failure_queue_name}"]
  }
}

resource "aws_iam_policy" "lambda_dlp" {
  name        = "${var.name_prefix}-lambda-policy"
  description = "Least-privilege policy for Macie-triggered DLP remediation Lambda"
  policy      = data.aws_iam_policy_document.lambda_dlp.json
}

resource "aws_iam_role_policy_attachment" "lambda_dlp_attach" {
  role       = aws_iam_role.lambda_dlp.name
  policy_arn = aws_iam_policy.lambda_dlp.arn
}

# Required for Lambda logging
resource "aws_iam_role_policy_attachment" "lambda_basic_logging" {
  role       = aws_iam_role.lambda_dlp.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
