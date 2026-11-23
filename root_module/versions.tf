terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Partial configuration: bucket, key and region are injected at init time
  # (-backend-config) so that each environment has its own isolated state.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}
