terraform {
  required_version = "~> 1.16.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.66.0"
    }
  }

  # bootstrap starts with local state because 
  # the state bucket does not exist
  # until this configuration has been applied once
  backend "local" {
    path = "terraform.tfstate"
  }
}
