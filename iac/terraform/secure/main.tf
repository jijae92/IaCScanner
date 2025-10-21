provider "aws" {
  region = "us-east-1"
}

# This configuration is intended to pass tfsec + Checkov policy engines.

resource "aws_security_group" "restricted_ssh" {
  name        = "iac-scanner-restricted-ssh"
  description = "Allow SSH only from corporate network"

  ingress {
    description = "SSH from corp"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow outbound to VPC endpoints only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [
      "pl-0123456789abcdef0"
    ]
  }
}

resource "aws_s3_bucket" "private_bucket" {
  bucket        = "iac-scanner-demo-private"
  acl           = "private"
  force_destroy = false

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.bucket_key.arn
      }
    }
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    id      = "expire-old-versions"
    enabled = true

    noncurrent_version_expiration {
      days = 365
    }
  }

  tags = {
    Purpose = "Secure demo bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "private_bucket" {
  bucket = aws_s3_bucket.private_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "bucket_key" {
  description             = "KMS key for secure bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_iam_policy" "least_privilege_policy" {
  name        = "iac-scanner-least-privilege"
  description = "Restrictive policy with scoped resources and conditions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ListOwnBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.private_bucket.arn
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalTag/Team" = "Security"
          }
        }
      },
      {
        Sid    = "AllowObjectReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.private_bucket.arn}/*"
        ]
        Condition = {
          StringEqualsIfExists = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}
