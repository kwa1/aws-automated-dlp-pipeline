data "aws_caller_identity" "current" {}

resource "aws_macie2_account" "this" {
  finding_publishing_frequency = var.finding_publishing_frequency
}

# A ONE_TIME job only scans what exists at apply time (an empty bucket on first deploy),
# so later uploads would never be classified. A daily recurring job scans everything on
# the first run and new or changed objects on each following run.
resource "aws_macie2_classification_job" "scan" {
  name                = "${var.name_prefix}-s3-sensitive-scan"
  job_type            = "SCHEDULED"
  initial_run         = true
  sampling_percentage = 100

  schedule_frequency {
    daily_schedule = true
  }

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = var.s3_buckets
    }
  }

  depends_on = [aws_macie2_account.this]
}
