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
GitHub Actions (`.github/workflows/`)

| Workflow | Trigger | What it does |
| -------- | ------- | ------------ |
| `pr.yml` | Pull request to `main` | `terraform fmt -check`, `validate`, OPA format/strict-check/unit tests (**Static checks**); read-only `plan` against staging, then `opa eval` of the plan JSON, failing on any `deny` (**Plan and OPA gate**) |
| `deploy-staging.yml` | Push to `main` | plan, OPA gate, then apply of the exact saved plan |
| `deploy-prod.yml` | Manual (`workflow_dispatch`) from `main` or a tag | plan, OPA gate, reviewer approval, then apply of the exact saved plan |
| `terraform.yml` | Called by the three above | Shared plan/gate/apply logic (not run directly) |

How it works:

- Plan and apply are separate jobs. The apply job downloads the plan artifact produced (and OPA-checked) by the plan job and runs `terraform apply tfplan`, so what is applied is exactly what was reviewed. Terraform rejects the plan if state changed in between.
- Approval: the `environment:` key is only on the apply job, so required reviewers on the GitHub `production` environment approve after the plan is visible in the job summary.
- AWS access uses GitHub OIDC. There are no long-lived AWS keys. Plan and apply use separate roles.
- Each environment has its own state: `s3://<bucket>/dlp/<environment>/terraform.tfstate`. Backend settings are passed at `init` time (`-backend-config`), and `environments/<env>.tfvars` is passed with `-var-file`.
- Deploys for an environment are serialised with a `concurrency` group and never cancelled mid-apply.
- A deploy fails fast if `environments/<env>.tfvars` still contains `REPLACE-ME`.

One-time setup:

1. Create an S3 state bucket per environment (versioning and encryption on).
2. Create the GitHub OIDC identity provider in each AWS account, plus two IAM roles per environment:
   - Plan role (read-only: `ReadOnlyAccess` plus read on the state bucket). Trust `sub` values: `repo:<org>/<repo>:pull_request` and `repo:<org>/<repo>:ref:refs/heads/main`.
   - Apply role (write access to deploy the stack and the state bucket). Trust `sub`: `repo:<org>/<repo>:environment:<staging|production>`.
3. Set these repository variables (Settings > Secrets and variables > Actions > Variables):
   `STAGING_TF_STATE_BUCKET`, `STAGING_PLAN_ROLE_ARN`, `STAGING_APPLY_ROLE_ARN`,
   `PRODUCTION_TF_STATE_BUCKET`, `PRODUCTION_PLAN_ROLE_ARN`, `PRODUCTION_APPLY_ROLE_ARN`,
   and optionally `TF_AWS_REGION` (defaults to `eu-west-1`).
4. Replace the `REPLACE-ME` values in `root_module/environments/*.tfvars`.
5. Create the `staging` and `production` GitHub environments; add required reviewers to `production`.
6. Branch protection on `main`: require the `Static checks` and `Plan and OPA gate` checks and a pull request review.

Note: PRs from forks skip the plan job because they cannot obtain OIDC credentials.
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

Deployments run through GitHub Actions (see above). To plan locally:

cd root_module
terraform init -backend-config="bucket=<state-bucket>" -backend-config="key=dlp/staging/terraform.tfstate" -backend-config="region=eu-west-1"
terraform plan -var-file=environments/staging.tfvars -out=tfplan

OPA validation (CI or local):

terraform show -json tfplan > plan.json
opa test ../terraform_modules/opa/policies
opa eval --fail-defined --format pretty --data ../terraform_modules/opa/policies --input plan.json 'data.terraform.security.deny[msg]'
#######################################################################

Final Note

This repository demonstrates how mature security organizations implement DLP on AWS:

Preventive, not detective

Automated, not manual

Enforced, not advisory

Auditable by design

