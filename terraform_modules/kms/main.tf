data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # Service-linked role Macie uses to read (and decrypt) objects. The ARN is
  # referenced via a condition rather than a Principal so that the key can be
  # created before Macie has been enabled in the account.
  macie_slr_arn = "arn:aws:iam::${local.account_id}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
}

data "aws_iam_policy_document" "key" {
  statement {
    sid       = "EnableIamPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowMacieToDecryptForClassification"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.macie_slr_arn]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "DLP KMS Key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}
