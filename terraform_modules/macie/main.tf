resource "aws_macie2_account" "this" {}

resource "aws_macie2_classification_job" "scan" {
  name      = "s3-sensitive-scan"
  job_type = "ONE_TIME"

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = var.s3_buckets
    }
  }
}
