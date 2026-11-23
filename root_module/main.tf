provider "aws" {
  region = var.region

  default_tags {
    tags = {
      CostCenter  = "Security-DLP"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

module "kms" {
  source = "../terraform_modules/kms"
  alias  = "dlp-key"
}

module "s3" {
  source     = "../terraform_modules/s3"
  bucket     = var.bucket_name
  kms_key_id = module.kms.key_arn
}

module "macie" {
  source     = "../terraform_modules/macie"
  s3_buckets = [module.s3.bucket]
}

module "iam" {
  source     = "../terraform_modules/iam"
  bucket_arn = module.s3.bucket_arn
}

module "cost_control" {
  source            = "../terraform_modules/cost-control"
  monthly_limit_usd = var.monthly_limit_usd
  alert_emails      = var.alert_emails
}

module "lambda_remediation" {
  source   = "../terraform_modules/lambda-remediation"
  role_arn = module.iam.lambda_role_arn
}

module "eventbridge" {
  source     = "../terraform_modules/eventbridge"
  lambda_arn = module.lambda_remediation.lambda_arn
}

module "s3_dlp" {
  source      = "../terraform_modules/s3-dlp"
  bucket_name = module.s3.bucket
}

module "securityhub" {
  source = "../terraform_modules/securityhub"
}
