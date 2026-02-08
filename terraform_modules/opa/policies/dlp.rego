package dlp

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket"
  not r.change.after.server_side_encryption_configuration
  msg := "S3 must enforce SSE-KMS"
}

deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_macie2_account"
  r.change.after.status != "ENABLED"
  msg := "Macie must be enabled"
}
