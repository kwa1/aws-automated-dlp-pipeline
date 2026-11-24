provider "aws" {
  region              = var.region
  allowed_account_ids = [var.allowed_account_id]

  default_tags {
    tags = {
      CostCenter  = "Security-DLP"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

locals {
  # Prefix for every named resource so staging and production can share an account
  # (or a region) without name collisions.
  name_prefix = "dlp-${var.environment}"
}

module "kms" {
  source = "../terraform_modules/kms"
  alias  = "${local.name_prefix}-key"
}

module "s3" {
  source     = "../terraform_modules/s3"
  bucket     = var.bucket_name
  kms_key_id = module.kms.key_arn
}

module "macie" {
  source      = "../terraform_modules/macie"
  name_prefix = local.name_prefix
  s3_buckets  = [module.s3.bucket]
}

module "iam" {
  source             = "../terraform_modules/iam"
  name_prefix        = local.name_prefix
  bucket_arn         = module.s3.bucket_arn
  failure_queue_name = "${local.name_prefix}-remediation-failures"
}

module "cost_control" {
  source                       = "../terraform_modules/cost-control"
  name_prefix                  = local.name_prefix
  monthly_limit_usd            = var.monthly_limit_usd
  alert_emails                 = var.alert_emails
  activate_cost_allocation_tag = var.activate_cost_allocation_tag
}

module "lambda_remediation" {
  source             = "../terraform_modules/lambda-remediation"
  function_name      = "${local.name_prefix}-macie-remediation"
  failure_queue_name = "${local.name_prefix}-remediation-failures"
  role_arn           = module.iam.lambda_role_arn
}

module "eventbridge" {
  source      = "../terraform_modules/eventbridge"
  name_prefix = local.name_prefix
  lambda_arn  = module.lambda_remediation.lambda_arn
}

# Only exists in fail-closed mode: it alone may mark objects Scanned=true.
module "fail_closed_sweeper" {
  count  = var.fail_closed ? 1 : 0
  source = "../terraform_modules/fail-closed-sweeper"

  name_prefix   = local.name_prefix
  bucket_name   = module.s3.bucket
  bucket_arn    = module.s3.bucket_arn
  macie_job_arn = module.macie.job_arn
  macie_job_id  = module.macie.job_id
}

module "s3_dlp" {
  source = "../terraform_modules/s3-dlp"

  bucket_name           = module.s3.bucket
  remediation_role_arn  = module.iam.lambda_role_arn
  sweeper_role_arn      = var.fail_closed ? module.fail_closed_sweeper[0].role_arn : ""
  break_glass_role_arns = var.break_glass_role_arns
  fail_closed           = var.fail_closed
}

module "alerting" {
  source = "../terraform_modules/alerting"

  name_prefix           = local.name_prefix
  kms_key_arn           = module.kms.key_arn
  alert_emails          = var.alert_emails
  dlq_name              = module.eventbridge.dlq_name
  failure_queue_name    = module.lambda_remediation.failure_queue_name
  lambda_name           = module.lambda_remediation.lambda_name
  rule_name             = module.eventbridge.rule_name
  sweeper_enabled       = var.fail_closed
  sweeper_function_name = var.fail_closed ? module.fail_closed_sweeper[0].function_name : ""
}

module "securityhub" {
  source = "../terraform_modules/securityhub"
}
