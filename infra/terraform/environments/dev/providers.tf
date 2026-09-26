provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      var.additional_tags,
      {
        Project     = "gatehouse"
        Environment = "dev"
        ManagedBy   = "Terraform"
      },
    )
  }
}