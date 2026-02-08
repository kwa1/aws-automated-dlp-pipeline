data "aws_iam_policy_document" "dlp" {
  statement {
    effect = "Deny"
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.bucket_name}/*"]
    principals { type = "*" identifiers = ["*"] }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/Sensitive"
      values   = ["true"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.bucket_name
  policy = data.aws_iam_policy_document.dlp.json
}
