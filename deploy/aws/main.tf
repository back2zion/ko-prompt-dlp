# AX Filter KMS key + least-privilege IAM for envelope encryption.
# Apply:  terraform init && terraform apply
# Then:   export AXFILTER_KEY_PROVIDER=awskms AXFILTER_KMS_KEY_ID=$(terraform output -raw kms_key_id)

terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
variable "region" { default = "ap-northeast-2" }
variable "name"   { default = "axfilter" }
provider "aws" { region = var.region }

resource "aws_kms_key" "dek" {
  description             = "AX Filter data-key wrapping key (envelope encryption)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
resource "aws_kms_alias" "dek" {
  name          = "alias/${var.name}-dek"
  target_key_id = aws_kms_key.dek.key_id
}

# Least privilege: the app may only Encrypt/Decrypt (wrap/unwrap the DEK), nothing else.
data "aws_iam_policy_document" "app" {
  statement {
    sid       = "AxfilterEnvelope"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.dek.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:app"
      values   = ["axfilter"]
    }
  }
}
resource "aws_iam_policy" "app" {
  name   = "${var.name}-kms"
  policy = data.aws_iam_policy_document.app.json
}

output "kms_key_id"  { value = aws_kms_key.dek.key_id }
output "kms_alias"   { value = aws_kms_alias.dek.name }
output "iam_policy"  { value = aws_iam_policy.app.arn }
