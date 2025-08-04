# 🏗️ Banking Cloud Security Architecture

## Overview

This document outlines the comprehensive security architecture implemented for the digital banking platform on AWS. The design follows defense-in-depth principles with multiple layers of security controls.

## Architecture Diagram

```mermaid
graph TB
    subgraph "Internet Gateway"
        A[User Requests]
    end
    
    subgraph "Edge Security Layer"
        B[Route 53 DNS]
        C[CloudFront CDN]
        D[AWS WAF]
    end
    
    subgraph "Network Security Layer"
        E[Application Load Balancer]
        F[VPC with Private Subnets]
        G[Security Groups]
        H[NACLs]
    end
    
    subgraph "Application Layer"
        I[EC2 Instances]
        J[Auto Scaling Group]
        K[IAM Roles]
    end
    
    subgraph "Data Layer"
        L[RDS PostgreSQL]
        M[S3 Buckets]
        N[KMS Encryption]
    end
    
    subgraph "Monitoring & Detection"
        O[GuardDuty]
        P[CloudTrail]
        Q[Config]
        R[CloudWatch]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    G --> I
    I --> L
    I --> M
    N --> L
    N --> M
    O --> R
    P --> R
    Q --> R
