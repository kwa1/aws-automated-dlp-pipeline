resource "aws_lambda_function" "this" {
  function_name = "macie-dlp-remediation"
  role          = var.role_arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  filename      = "${path.module}/lambda.zip"
  timeout       = 30

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

output "lambda_arn" {
  value = aws_lambda_function.this.arn
}
