resource "aws_iam_role" "lambda_dlp" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Purpose     = "DLP-Remediation"
    ManagedBy   = "Terraform"
    Compliance  = "GDPR"
  }
}

resource "aws_iam_policy" "lambda_dlp" {
  name        = var.policy_name
  description = "Least-privilege policy for Macie-triggered DLP remediation Lambda"
  policy      = file("${path.module}/policies/lambda_dlp.json")
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
