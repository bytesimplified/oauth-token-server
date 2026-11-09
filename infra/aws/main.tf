terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type = string
}

variable "workload_role_name" {
  description = "Existing least-privileged AWS IAM role assigned to the OAuth application."
  type        = string
}

variable "previous_kms_key_arns" {
  description = "Retired KMS keys that must remain accessible for JWT verification through expiry."
  type        = list(string)
  default     = []
}

data "aws_iam_role" "workload" {
  name = var.workload_role_name
}

resource "aws_kms_key" "signing" {
  description             = "OAuth RS256 asymmetric access-token signing"
  key_usage               = "SIGN_VERIFY"
  key_spec                = "RSA_3072"
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "signing" {
  name          = "alias/oauth-token-server-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# Secret is deliberately created without a version: keep secret VALUES out of Terraform state.
resource "aws_secretsmanager_secret" "runtime" {
  name                    = "oauth-token-server/runtime"
  recovery_window_in_days = 30
}

resource "aws_iam_role_policy" "oauth" {
  name = "oauth-token-server-runtime"
  role = data.aws_iam_role.workload.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SignOAuthTokens"
        Effect   = "Allow"
        Action   = ["kms:Sign", "kms:GetPublicKey"]
        Resource = concat([aws_kms_key.signing.arn], var.previous_kms_key_arns)
      },
      {
        Sid      = "ReadOAuthRuntimeSecrets"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.runtime.arn]
      }
    ]
  })
}

output "kms_key_arn" {
  value = aws_kms_key.signing.arn
}

output "secret_arn" {
  value = aws_secretsmanager_secret.runtime.arn
}

output "workload_role_arn" {
  value = data.aws_iam_role.workload.arn
}
