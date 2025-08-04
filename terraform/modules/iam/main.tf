# IAM Role Segmentation Module
# Implements least privilege access for banking operations

# Banking Application Role
resource "aws_iam_role" "banking_app" {
  name = "${var.project_name}-banking-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-banking-app-role"
    Purpose = "Application-tier-access"
  }
}

# Database Admin Role
resource "aws_iam_role" "db_admin" {
  name = "${var.project_name}-db-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-db-admin-role"
    Purpose = "Database-administration"
  }
}

# Security Audit Role
resource "aws_iam_role" "security_audit" {
  name = "${var.project_name}-security-audit-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          StringEquals = {
            "aws:RequestedRegion": ["us-east-1", "us-west-2"]
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-security-audit-role"
    Purpose = "Security-compliance-audit"
  }
}

# Custom policies for banking operations
resource "aws_iam_policy" "banking_app_policy" {
  name        = "${var.project_name}-banking-app-policy"
  description = "Policy for banking application operations"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::${var.project_name}-app-data-*/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption": "aws:kms"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService": "s3.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Attach policies to roles
resource "aws_iam_role_policy_attachment" "banking_app" {
  role       = aws_iam_role.banking_app.name
  policy_arn = aws_iam_policy.banking_app_policy.arn
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Variables
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

# Outputs
output "banking_app_role_arn" {
  description = "ARN of the banking application role"
  value       = aws_iam_role.banking_app.arn
}

output "db_admin_role_arn" {
  description = "ARN of the database admin role"
  value       = aws_iam_role.db_admin.arn
}
