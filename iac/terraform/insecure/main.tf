provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "ssh_everywhere" {
  name        = "iac-scanner-open-ssh"
  description = "Allows SSH from the entire internet (intentional insecure example)"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "world_readable" {
  bucket = "iac-scanner-demo-public"
  acl    = "public-read"

  tags = {
    Purpose = "Public demo bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "world_readable" {
  bucket = aws_s3_bucket.world_readable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_policy" "allow_everything" {
  name        = "iac-scanner-allow-everything"
  description = "Overly permissive policy for demo findings"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      }
    ]
  })
}
