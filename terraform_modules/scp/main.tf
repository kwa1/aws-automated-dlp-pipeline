locals {
  exempt = var.exempt_principal_arns
}

# SCPs support neither Principal nor NotPrincipal, so every exemption is expressed with an
# aws:PrincipalArn condition. SCPs only ever deny here (they cannot grant), and they do
# not apply to the organization's management account.
data "aws_iam_policy_document" "guardrails" {
  statement {
    sid    = "DenyDisablingSecurityServices"
    effect = "Deny"
    actions = [
      "macie2:DisableMacie",
      "macie2:DisableOrganizationAdminAccount",
      "macie2:UpdateMacieSession",
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromAdministratorAccount",
      "guardduty:DisableOrganizationAdminAccount",
      "securityhub:DisableSecurityHub",
      "securityhub:DisassociateFromAdministratorAccount",
      "securityhub:DisableOrganizationAdminAccount",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }

  statement {
    sid    = "DenyWeakeningAuditLogging"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }

  statement {
    sid       = "DenyChangingDlpBucketPolicy"
    effect    = "Deny"
    actions   = ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    resources = var.protected_bucket_arns

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }

  # Mirrors the bucket policy so that the tag protection survives even if that policy is
  # replaced. Keyed on the existing tag, so it blocks flipping Sensitive to false and
  # deleting the tag set, which a request-tag condition cannot.
  statement {
    sid    = "DenyTaggingChangesOnSensitiveObjects"
    effect = "Deny"
    actions = [
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
      "s3:DeleteObjectTagging",
      "s3:DeleteObjectVersionTagging",
    ]
    resources = ["arn:aws:s3:::*/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/Sensitive"
      values   = ["true"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }

  statement {
    sid    = "DenyTamperingWithRemediationPipeline"
    effect = "Deny"
    actions = [
      "events:DisableRule",
      "events:DeleteRule",
      "events:RemoveTargets",
      "lambda:DeleteFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:PutFunctionEventInvokeConfig",
      "lambda:DeleteFunctionEventInvokeConfig",
    ]
    resources = [
      "arn:aws:events:*:*:rule/${var.resource_name_pattern}",
      "arn:aws:lambda:*:*:function:${var.resource_name_pattern}",
    ]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }

  statement {
    sid       = "DenyStoppingClassificationJobs"
    effect    = "Deny"
    actions   = ["macie2:UpdateClassificationJob"]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.exempt
    }
  }
}

locals {
  # Whitespace counts toward the 5,120 character SCP limit, so minify the document.
  content = jsonencode(jsondecode(data.aws_iam_policy_document.guardrails.json))
}

resource "aws_organizations_policy" "guardrails" {
  name        = var.name
  description = "Non-bypassable DLP guardrails: security services, audit logging, DLP bucket policy, sensitive-object tags, remediation pipeline"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.content

  lifecycle {
    precondition {
      condition     = length(local.content) <= 5120
      error_message = "The SCP document exceeds the 5,120 character AWS Organizations limit. Remove statements or shorten the exempt ARN list."
    }
  }
}

resource "aws_organizations_policy_attachment" "guardrails" {
  for_each = toset(var.target_ids)

  policy_id = aws_organizations_policy.guardrails.id
  target_id = each.value
}
