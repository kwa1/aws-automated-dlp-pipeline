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
#package cost.guardrails
deny[msg] {
  r := input.resource_changes[_]
  r.type == "aws_macie2_classification_job"
  r.change.after.job_type == "CONTINUOUS"
  msg := "Continuous Macie jobs are forbidden without explicit approval (cost risk)"
}

#package terraform.security.iam

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_policy"

  statement := resource.change.after.policy.Statement[_]
  action := statement.Action[_]

  startswith(action, "s3:*")

  msg := sprintf(
    "IAM policy %s contains wildcard S3 permissions",
    [resource.name]
  )
}
#package terraform.security.tags

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_policy"

  not contains(resource.change.after.policy, "Sensitive")

  msg := sprintf(
    "Bucket policy %s must enforce controls based on Sensitive tag",
    [resource.name]
  )
}
