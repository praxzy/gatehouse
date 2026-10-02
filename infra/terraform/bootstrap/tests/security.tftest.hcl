mock_provider "aws" {
  override_during = plan
}

override_data {
  target          = data.aws_partition.current
  override_during = plan

  values = {
    partition = "aws"
  }
}

override_data {
  target          = data.aws_caller_identity.current
  override_during = plan

  values = {
    account_id = "123456789012"
  }
}

override_resource {
  target          = aws_iam_openid_connect_provider.github_actions[0]
  override_during = plan

  values = {
    arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  }
}

run "bootstrap_security_contract" {
  command = plan

  variables {
    state_bucket_name  = "gatehouse-example-terraform-state"
    github_repository  = "praxzy/gatehouse"
    github_environment = "production"
  }

  assert {
    condition     = !aws_s3_bucket.terraform_state.force_destroy
    error_message = "Terraform state must not be force-deleted."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.terraform_state.block_public_acls &&
      aws_s3_bucket_public_access_block.terraform_state.block_public_policy &&
      aws_s3_bucket_public_access_block.terraform_state.ignore_public_acls &&
      aws_s3_bucket_public_access_block.terraform_state.restrict_public_buckets
    )
    error_message = "Terraform state must block every form of public access."
  }

  assert {
    condition = (
      aws_s3_bucket_versioning.terraform_state.versioning_configuration[0].status ==
      "Enabled"
    )
    error_message = "Terraform state must be versioned."
  }

  assert {
    condition = (
      one(
        one(
          aws_s3_bucket_server_side_encryption_configuration.terraform_state.rule
        ).apply_server_side_encryption_by_default
      ).sse_algorithm == "AES256"
    )
    error_message = "Terraform state must be encrypted at rest."
  }

  assert {
    condition = (
      jsondecode(
        aws_iam_role.github_deploy.assume_role_policy
      ).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] ==
      "sts.amazonaws.com"
    )
    error_message = "The deployment role must require the AWS STS audience."
  }

  assert {
    condition = (
      jsondecode(
        aws_iam_role.github_deploy.assume_role_policy
      ).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] ==
      "repo:praxzy/gatehouse:environment:production"
    )
    error_message = "The deployment role must trust only the protected production environment."
  }

  assert {
    condition     = aws_iam_role.github_deploy.max_session_duration == 3600
    error_message = "GitHub deployment sessions must be short lived."
  }
}
