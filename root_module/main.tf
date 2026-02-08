terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

module "kms" {
  source      = "./terraform-modules/kms"
  alias       = "dlp-key"
  account_id  = data.aws_caller_identity.current.account_id
}

module "s3" {
  source     = "./terraform-modules/s3"
  bucket     = var.bucket_name
  kms_key_id = module.kms.key_arn
}

module "macie" {
  source      = "./terraform-modules/macie"
  s3_buckets  = [module.s3.bucket]
}

module "iam" {
  source = "./terraform-modules/iam"
}
module "cost_control" {
  source            = "./terraform-modules/cost-control"
  monthly_limit_usd = 300
  alert_emails      = ["security@company.com"]
}

module "lambda_remediation" {
  source        = "./terraform-modules/lambda-remediation"
  role_arn     = module.iam.lambda_role_arn
  kms_key_arn  = module.kms.key_arn
}

module "eventbridge" {
  source            = "./terraform-modules/eventbridge"
  lambda_arn        = module.lambda_remediation.lambda_arn
}

module "s3_dlp" {
  source      = "./terraform-modules/s3-dlp"
  bucket_name = module.s3.bucket
}

module "cloudtrail" {
  source = "./terraform-modules/cloudtrail"
}

module "guardduty" {
  source = "./terraform-modules/guardduty"
}

module "securityhub" {
  source = "./terraform-modules/securityhub"
}


