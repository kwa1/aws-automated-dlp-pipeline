# Organization-level guardrails. Deploy this stack separately, from the AWS Organizations
# management account, after the workload stack (root_module) exists. It is deliberately
# not part of the CI/CD deploy workflows: it is high blast radius and changes rarely.
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = {
      CostCenter = "Security-DLP"
      ManagedBy  = "Terraform"
    }
  }
}

module "scp" {
  source = "../terraform_modules/scp"

  target_ids            = var.target_ids
  exempt_principal_arns = var.exempt_principal_arns
  protected_bucket_arns = var.protected_bucket_arns
  resource_name_pattern = var.resource_name_pattern
}

output "policy_id" {
  description = "ID of the DLP guardrails service control policy"
  value       = module.scp.policy_id
}

output "policy_size" {
  description = "Size of the SCP document in characters (limit 5,120)"
  value       = module.scp.policy_size
}
