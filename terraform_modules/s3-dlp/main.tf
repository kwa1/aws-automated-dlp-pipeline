data "aws_caller_identity" "current" {}

locals {
  bucket_arn  = "arn:aws:s3:::${var.bucket_name}"
  objects_arn = "${local.bucket_arn}/*"

  # Macie reads objects through its service-linked role to classify them. It must
  # never be locked out by the read denies, or tagged objects could not be re-scanned
  # (and, in fail-closed mode, no object could ever be scanned).
  macie_slr_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"

  # aws:PrincipalArn holds the role ARN (not the session ARN) for assumed roles.
  # Every list is non-empty, so the conditions below stay valid without dynamic blocks.
  read_exempt_arns = concat([local.macie_slr_arn], var.break_glass_role_arns)

  # Only remediation (and break-glass) may touch tags on a Sensitive=true object. The
  # sweeper is deliberately NOT here: if it races with remediation, S3 evaluates the
  # existing tags at request time and denies its tag-set replacement instead of letting
  # it wipe Sensitive=true.
  tag_exempt_arns = concat([var.remediation_role_arn], var.break_glass_role_arns)

  # Principals allowed to write the Scanned tag (fail-closed mode).
  scanned_writer_arns = compact(concat([var.remediation_role_arn, var.sweeper_role_arn], var.break_glass_role_arns))
}

# Keep statements literal (no dynamic blocks): the OPA gate inspects this document's
# configuration to prove the controls exist.
data "aws_iam_policy_document" "dlp" {
  # Every read path for an object version. GetObjectAttributes and GetObjectTorrent are
  # authorised through s3:GetObject / s3:GetObjectVersion, so they are covered as well.
  statement {
    sid       = "DenyReadOfSensitiveObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectVersionAttributes"]
    resources = [local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/Sensitive"
      values   = ["true"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.read_exempt_arns
    }
  }

  # Without this, anyone with tagging rights could flip Sensitive=false (or delete the
  # tag) and re-open the object.
  statement {
    sid    = "DenyTagTamperingOnSensitiveObjects"
    effect = "Deny"
    actions = [
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
      "s3:DeleteObjectTagging",
      "s3:DeleteObjectVersionTagging",
    ]
    resources = [local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/Sensitive"
      values   = ["true"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.tag_exempt_arns
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyOldTlsVersions"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
}

# Fail-closed mode: an object is unreadable until it carries Scanned=true. For
# negated operators a missing tag evaluates to true, so untagged objects are denied.
data "aws_iam_policy_document" "fail_closed" {
  count = var.fail_closed ? 1 : 0

  statement {
    sid       = "DenyReadOfUnscannedObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectVersionAttributes"]
    resources = [local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:ExistingObjectTag/Scanned"
      values   = ["true"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.read_exempt_arns
    }
  }

  # Without this an uploader could write Scanned=true themselves (x-amz-tagging on
  # PutObject, or PutObjectTagging) and skip the scan. Remediation re-writes the whole
  # tag set, so it must be allowed to carry an existing Scanned tag forward.
  statement {
    sid       = "DenyScannedTagWrites"
    effect    = "Deny"
    actions   = ["s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging"]
    resources = [local.objects_arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:RequestObjectTag/Scanned"
      values   = ["false"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.scanned_writer_arns
    }
  }
}

# A bucket has exactly one policy, so every statement is merged into one document.
data "aws_iam_policy_document" "combined" {
  source_policy_documents = concat(
    [data.aws_iam_policy_document.dlp.json],
    data.aws_iam_policy_document.fail_closed[*].json,
  )
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.bucket_name
  policy = data.aws_iam_policy_document.combined.json
}
