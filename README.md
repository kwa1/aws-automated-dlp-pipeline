# data-loss-prevention
Overview

This repository implements an enterprise-grade, automated Data Loss Prevention (DLP) pipeline on AWS using native security services, infrastructure as code, and policy-as-code.

The solution automatically:

Detects PII and sensitive data in Amazon S3

Applies authoritative classification labels

Prevents downloads, sharing, and exfiltration

Enforces non-bypassable guardrails using SCPs

Blocks insecure infrastructure before deployment via OPA

Produces audit-ready evidence for compliance and leadership

This design follows AWS Well-Architected (Security Pillar) and security-by-design principles without disrupting developer workflows.

Key Outcomes

✔ True DLP enforcement (not just alerts)
✔ Zero manual triage
✔ Explicit deny controls (cannot be overridden)
✔ Shift-left security with CI enforcement
✔ Defensible compliance posture
####################################################
Architecture
High-Level Flow
######################################################
S3 Upload
   ↓
AWS Macie (Sensitive Data Classification)
   ↓
Amazon EventBridge (Finding Events)
   ↓
Lambda Remediation
   ├─ Apply classification tags (Sensitive=true, DataType=PII)
   └─ Enforce DLP bucket policy
   ↓
S3 Bucket Policy (Explicit Deny)
   ↓
❌ Download / Exfiltration Blocked
###########################################################################
Enforcement Layers (Defense in Depth)

| Layer            | Purpose                  | Bypassable |
| ---------------- | ------------------------ | ---------- |
| Macie            | Detection                | ❌          |
| Lambda           | Labeling                 | ❌          |
| S3 Bucket Policy | DLP Enforcement          | ❌          |
| AWS SCP          | Control Plane Protection | ❌          |
| OPA (CI)         | Shift-left Guardrails    | ❌          |

Repository Structure

cloud-security-pipeline/
├── main.tf
├── variables.tf
├── outputs.tf
├── terraform.tfvars
├── terraform-modules/
│   ├── iam/
│   ├── s3/
│   ├── s3-dlp/
│   ├── macie/
│   ├── eventbridge/
│   ├── lambda-remediation/
│   ├── cloudtrail/
│   ├── guardduty/
│   ├── securityhub/
│   ├── kms/
│   ├── cloudwatch/
│   ├── network-security/
│   ├── org-scp/
│   └── opa/
│       └── policies/
│           └── dlp.rego
└── README.md
############################################################
Core Components

1. Amazon Macie – Sensitive Data Detection

Classifies S3 objects for:

PII

Credentials

Financial data

Emits structured findings with severity

Fully automated and continuous

2. EventBridge – Near Real-Time Response

Captures Macie findings

Filters by severity and resource type

Routes events to remediation Lambda

3. Lambda Remediation – Classification & Control
Lambda responsibilities (intentionally minimal):

Parse Macie findings

Identify affected S3 object

Apply object tags:

Sensitive=true

DataClassification=PII

Compliance=GDPR

Log immutable evidence

Lambda does not copy, move, or delete data.

4. S3 DLP Enforcement (Critical)

True DLP is implemented via explicit deny bucket policies:

Deny s3:GetObject if Sensitive=true

Block presigned URL downloads

Prevent cross-account access

Allow tightly scoped break-glass roles only

This makes data cryptographically present but operationally inaccessible.

5. AWS Organizations SCP – Non-Bypassable Guardrails

Service Control Policies prevent:

Disabling Macie, GuardDuty, Security Hub

Removing S3 DLP bucket policies

Untagging sensitive objects

Weakening logging or monitoring

SCPs apply before IAM and cannot be overridden.   

6. OPA / Policy-as-Code (Shift Left)

OPA validates Terraform plans in CI to ensure:

S3 uses SSE-KMS

Macie is enabled

CloudTrail is multi-region

Lambda uses least privilege

DLP bucket policies exist

Insecure infrastructure never reaches AWS.
###########################################################################
CI/CD & Environments
GitHub Actions

Pull Requests

Terraform validate

OPA policy evaluation

Security gate enforcement

Staging Deployment

Auto-deploy on merge to main

Isolated account / environment

Production Deployment

Parameterized

Manual approval

SCP-protected
################################################################
Operational Model
#################################################################
Scenario	                                    Outcome
Developer uploads PII	                        Detected and tagged automatically
User attempts download	                      Explicitly denied
Admin tries to bypass	                        Blocked by SCP
Misconfigured Terraform	                      Blocked by OPA
Auditor requests evidence	                    Instantly available

################################################################
Deployment

terraform init
terraform plan
terraform apply

OPA validation (CI or local):

terraform show -json tfplan > plan.json
opa eval --fail-defined --data terraform-modules/opa/policies plan.json
#######################################################################

Final Note

This repository demonstrates how mature security organizations implement DLP on AWS:

Preventive, not detective

Automated, not manual

Enforced, not advisory

Auditable by design

