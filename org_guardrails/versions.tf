terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial configuration, injected at init time (-backend-config), like root_module.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
