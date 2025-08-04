
# Banking Cloud Security Framework - Main Infrastructure
# Author: Shivam Patel
# Version: 2.0.0

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "banking-terraform-state-bucket"
    key            = "security-framework/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Banking-Cloud-Security"
      Environment = var.environment
      Owner       = "Security-Team"
      CostCenter  = "SEC-001"
      Compliance  = "PCI-DSS"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Random password for database
resource "random_password" "db_password" {
  length  = 32
  special = true
}

# VPC and Networking
module "vpc" {
  source = "./modules/vpc"
  
  cidr_block           = var.vpc_cidr
  availability_zones   = var.availability_zones
  private_subnets      = var.private_subnets
  public_subnets       = var.public_subnets
  database_subnets     = var.database_subnets
  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  enable_flow_logs     = true
  
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# IAM Module - Role Segmentation
module "iam" {
  source = "./modules/iam"
  
  project_name = var.project_name
  environment  = var.environment
}

# KMS Module - Encryption Management
module "kms" {
  source = "./modules/kms"
  
  project_name     = var.project_name
  environment      = var.environment
  key_admin_arns   = var.key_admin_arns
  key_user_arns    = var.key_user_arns
}

# WAF Module - Web Application Firewall
module "waf" {
  source = "./modules/waf"
  
  project_name    = var.project_name
  environment     = var.environment
  allowed_ips     = var.allowed_ips
  blocked_countries = var.blocked_countries
}

# GuardDuty Module - Threat Detection
module "guardduty" {
  source = "./modules/guardduty"
  
  project_name           = var.project_name
  environment            = var.environment
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  enable_s3_protection   = true
  enable_eks_protection  = true
}

# Security Hub - Centralized Security Findings
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

# Config - Configuration Compliance
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# CloudTrail - API Logging
resource "aws_cloudtrail" "main" {
  name           = "${var.project_name}-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
  s3_key_prefix  = "cloudtrail"

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::${aws_s3_bucket.application_data.id}/*"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
  
  tags = {
    Name = "${var.project_name}-cloudtrail"
  }
}

# S3 Buckets with Security Hardening
resource "aws_s3_bucket" "application_data" {
  bucket = "${var.project_name}-app-data-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name        = "${var.project_name}-application-data"
    Sensitive   = "true"
    Encryption  = "required"
  }
}

resource "aws_s3_bucket_versioning" "application_data" {
  bucket = aws_s3_bucket.application_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = module.kms.s3_key_id
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "application_data" {
  bucket = aws_s3_bucket.application_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# RDS with Encryption
resource "aws_db_instance" "banking_db" {
  identifier             = "${var.project_name}-database"
  allocated_storage      = 100
  max_allocated_storage  = 1000
  storage_type           = "gp3"
  storage_encrypted      = true
  kms_key_id            = module.kms.rds_key_id
  
  engine                = "postgres"
  engine_version        = "14.9"
  instance_class        = "db.r5.xlarge"
  
  db_name  = "bankingdb"
  username = "bankadmin"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn        = aws_iam_role.rds_monitoring.arn
  
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  tags = {
    Name        = "${var.project_name}-database"
    Sensitive   = "true"
    Compliance  = "PCI-DSS"
  }
}

# CloudWatch Dashboard for Security Monitoring
resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "${var.project_name}-security-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/GuardDuty", "FindingCount"],
            ["AWS/WAF", "BlockedRequests"],
            ["AWS/CloudTrail", "ErrorCount"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Security Metrics Overview"
          period  = 300
        }
      }
    ]
  })
}

# Random ID for unique naming
resource "random_id" "bucket_suffix" {
  byte_length = 8
}

# Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.banking_db.endpoint
  sensitive   = true
}

output "kms_key_id" {
  description = "KMS key ID"
  value       = module.kms.s3_key_id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = module.guardduty.detector_id
}
