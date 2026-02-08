resource "aws_kms_key" "this" {
  description             = "DLP KMS Key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

output "key_arn" {
  value = aws_kms_key.this.arn
}
