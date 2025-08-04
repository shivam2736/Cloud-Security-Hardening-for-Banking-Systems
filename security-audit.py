#!/usr/bin/env python3
"""
Banking Cloud Security Framework - Security Audit Script
Author: [Your Name]
Description: Comprehensive security audit for AWS banking infrastructure
"""

import boto3
import json
import sys
import argparse
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError
import logging

class BankingSecurityAudit:
    def __init__(self, profile=None, region='us-east-1'):
        """Initialize the security audit tool."""
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.region = region
            self.setup_clients()
            self.setup_logging()
            self.security_findings = []
            self.compliance_score = 0
            
        except NoCredentialsError:
            print("❌ AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
    
    def setup_clients(self):
        """Setup AWS service clients."""
        self.iam = self.session.client('iam')
        self.s3 = self.session.client('s3')
        self.rds = self.session.client('rds')
        self.guardduty = self.session.client('guardduty')
        self.waf = self.session.client('wafv2')
        self.config = self.session.client('config')
        self.cloudtrail = self.session.client('cloudtrail')
        self.kms = self.session.client('kms')
        
    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'security_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def check_iam_security(self):
        """Audit IAM security configurations."""
        print("\n🔐 Auditing IAM Security...")
        findings = []
        
        try:
            # Check for users without MFA
            users = self.iam.list_users()['Users']
            for user in users:
                mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                if not mfa_devices['MFADevices']:
                    findings.append({
                        'severity': 'HIGH',
                        'type': 'IAM_USER_WITHOUT_MFA',
                        'resource': user['UserName'],
                        'description': f"User {user['UserName']} does not have MFA enabled"
                    })
            
            # Check for overly permissive policies
            policies = self.iam.list_policies(Scope='Local')['Policies']
            for policy in policies:
                if 'admin' in policy['PolicyName'].lower() or 'full' in policy['PolicyName'].lower():
                    findings.append({
                        'severity': 'MEDIUM',
                        'type': 'OVERLY_PERMISSIVE_POLICY',
                        'resource': policy['Arn'],
                        'description': f"Policy {policy['PolicyName']} may be overly permissive"
                    })
            
            # Check root account usage
            account_summary = self.iam.get_account_summary()
            if account_summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                findings.append({
                    'severity': 'CRITICAL',
                    'type': 'ROOT_ACCESS_KEYS',
                    'resource': 'Root Account',
                    'description': "Root account has access keys - this is a critical security risk"
                })
                
        except ClientError as e:
            self.logger.error(f"Error checking IAM security: {e}")
        
        self.security_findings.extend(findings)
        print(f"✅ IAM audit completed. Found {len(findings)} issues.")
        return findings

    def check_s3_security(self):
        """Audit S3 bucket security configurations."""
        print("\n🪣 Auditing S3 Security...")
        findings = []
        
        try:
            buckets = self.s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket encryption
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                    if not encryption.get('ServerSideEncryptionConfiguration'):
                        findings.append({
                            'severity': 'HIGH',
                            'type': 'S3_UNENCRYPTED_BUCKET',
                            'resource': bucket_name,
                            'description': f"Bucket {bucket_name} is not encrypted"
                        })
                except ClientError:
                    findings.append({
                        'severity': 'HIGH',
                        'type': 'S3_UNENCRYPTED_BUCKET',
                        'resource': bucket_name,
                        'description': f"Bucket {bucket_name} has no encryption configuration"
                    })
                
                # Check public access block
                try:
                    public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                    pab = public_access['PublicAccessBlockConfiguration']
                    if not all([pab['BlockPublicAcls'], pab['IgnorePublicAcls'], 
                               pab['BlockPublicPolicy'], pab['RestrictPublicBuckets']]):
                        findings.append({
                            'severity': 'CRITICAL',
                            'type': 'S3_PUBLIC_ACCESS_ALLOWED',
                            'resource': bucket_name,
                            'description': f"Bucket {bucket_name} allows public access"
                        })
                except ClientError:
                    findings.append({
                        'severity': 'CRITICAL',
                        'type': 'S3_NO_PUBLIC_ACCESS_BLOCK',
                        'resource': bucket_name,
                        'description': f"Bucket {bucket_name} has no public access block configuration"
                    })
                
                # Check versioning
                try:
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            'severity': 'MEDIUM',
                            'type': 'S3_VERSIONING_DISABLED',
                            'resource': bucket_name,
                            'description': f"Bucket {bucket_name} does not have versioning enabled"
                        })
                except ClientError as e:
                    self.logger.error(f"Error checking versioning for {bucket_name}: {e}")
                    
        except ClientError as e:
            self.logger.error(f"Error checking S3 security: {e}")
        
        self.security_findings.extend(findings)
        print(f"✅ S3 audit completed. Found {len(findings)} issues.")
        return findings

    def check_rds_security(self):
        """Audit RDS security configurations."""
        print("\n🗄️ Auditing RDS Security...")
        findings = []
        
        try:
            # Check RDS instances
            instances = self.rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_name = instance['DBInstanceIdentifier']
                
                # Check encryption
                if not instance.get('StorageEncrypted', False):
                    findings.append({
                        'severity': 'CRITICAL',
                        'type': 'RDS_UNENCRYPTED',
                        'resource': db_name,
                        'description': f"RDS instance {db_name} is not encrypted"
                    })
                
                # Check backup retention
                if instance.get('BackupRetentionPeriod', 0) < 7:
                    findings.append({
                        'severity': 'MEDIUM',
                        'type': 'RDS_INSUFFICIENT_BACKUP_RETENTION',
                        'resource': db_name,
                        'description': f"RDS instance {db_name} has insufficient backup retention"
                    })
                
                # Check multi-AZ
                if not instance.get('MultiAZ', False):
                    findings.append({
                        'severity': 'MEDIUM',
                        'type': 'RDS_NO_MULTI_AZ',
                        'resource': db_name,
                        'description': f"RDS instance {db_name} is not configured for Multi-AZ"
                    })
                
                # Check deletion protection
                if not instance.get('DeletionProtection', False):
                    findings.append({
                        'severity': 'HIGH',
                        'type': 'RDS_NO_DELETION_PROTECTION',
                        'resource': db_name,
                        'description': f"RDS instance {db_name} does not have deletion protection"
                    })
                    
        except ClientError as e:
            self.logger.error(f"Error checking RDS security: {e}")
        
        self.security_findings.extend(findings)
        print(f"✅ RDS audit completed. Found {len(findings)} issues.")
        return findings

    def check_guardduty_status(self):
        """Check GuardDuty configuration and findings."""
        print("\n🛡️ Auditing GuardDuty...")
        findings = []
        
        try:
            detectors = self.guardduty.list_detectors()['DetectorIds']
            
            if not detectors:
                findings.append({
                    'severity': 'CRITICAL',
                    'type': 'GUARDDUTY_DISABLED',
                    'resource': 'GuardDuty Service',
                    'description': "GuardDuty is not enabled in this region"
                })
            else:
                for detector_id in detectors:
                    detector = self.guardduty.get_detector(DetectorId=detector_id)
                    
                    if detector['Status'] != 'ENABLED':
                        findings.append({
                            'severity': 'HIGH',
                            'type': 'GUARDDUTY_NOT_ACTIVE',
                            'resource': detector_id,
                            'description': f"GuardDuty detector {detector_id} is not active"
                        })
                    
                    # Check for recent findings
                    recent_findings = self.guardduty.list_findings(
                        DetectorId=detector_id,
                        FindingCriteria={
                            'Criterion': {
                                'createdAt': {
                                    'Gte': int((datetime.now() - timedelta(days=7)).timestamp() * 1000)
                                }
                            }
                        }
                    )
                    
                    if recent_findings['FindingIds']:
                        findings.append({
                            'severity': 'HIGH',
                            'type': 'GUARDDUTY_RECENT_FINDINGS',
                            'resource': detector_id,
                            'description': f"GuardDuty has {len(recent_findings['FindingIds'])} recent findings"
                        })
                        
        except ClientError as e:
            self.logger.error(f"Error checking GuardDuty: {e}")
        
        self.security_findings.extend(findings)
        print(f"✅ GuardDuty audit completed. Found {len(findings)} issues.")
        return findings

    def calculate_compliance_score(self):
        """Calculate overall compliance score."""
        total_findings = len(self.security_findings)
        critical_findings = len([f for f in self.security_findings if f['severity'] == 'CRITICAL'])
        high_findings = len([f for f in self.security_findings if f['severity'] == 'HIGH'])
        medium_findings = len([f for f in self.security_findings if f['severity'] == 'MEDIUM'])
        
        # Weighted scoring system
        max_score = 100
        critical_weight = 20
        high_weight = 10
        medium_weight = 5
        
        score_deduction = (critical_findings * critical_weight + 
                          high_findings * high_weight + 
                          medium_findings * medium_weight)
        
        self.compliance_score = max(0, max_score - score_deduction)
        return self.compliance_score

    def generate_report(self):
        """Generate comprehensive security report."""
        print("\n📊 Generating Security Report...")
        
        score = self.calculate_compliance_score()
        
        report = {
            'audit_timestamp': datetime.now().isoformat(),
            'region': self.region,
            'compliance_score': score,
            'total_findings': len(self.security_findings),
            'findings_by_severity': {
                'CRITICAL': len([f for f in self.security_findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in self.security_findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in self.security_findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in self.security_findings if f['severity'] == 'LOW'])
            },
            'detailed_findings': self.security_findings
        }
        
        # Save report to file
        report_filename = f'security_audit_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n🎯 COMPLIANCE SCORE: {score}/100")
        print(f"📁 Report saved to: {report_filename}")
        
        return report

    def run_full_audit(self):
        """Run complete security audit."""
        print("🚀 Starting Banking Cloud Security Audit...")
        print("=" * 60)
        
        self.check_iam_security()
        self.check_s3_security()
        self.check_rds_security()
        self.check_guardduty_status()
        
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("🏁 Security Audit Completed!")
        
        if report['compliance_score'] >= 90:
            print("🟢 EXCELLENT: Your security posture is strong!")
        elif report['compliance_score'] >= 70:
            print("🟡 GOOD: Some security improvements needed.")
        else:
            print("🔴 CRITICAL: Immediate security attention required!")
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Banking Cloud Security Framework Audit Tool')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--environment', default='production', help='Environment to audit')
    
    args = parser.parse_args()
    
    # Initialize and run audit
    audit = BankingSecurityAudit(profile=args.profile, region=args.region)
    audit.run_full_audit()

if __name__ == "__main__":
    main()
