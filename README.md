# AWS automated DLP pipeline

Automated Data Loss Prevention for an Amazon S3 bucket, built with Terraform, native AWS
security services and policy-as-code.

Amazon Macie classifies objects. When it finds sensitive data, a Lambda tags the object
`Sensitive=true`, and an explicit-deny bucket policy then blocks every read of that object.
Terraform plans are checked by OPA in CI before anything is deployed.

## What it does, and what it does not

| It does | It does not |
| ------- | ----------- |
| Scan the bucket daily with Macie and tag sensitive objects | Block reads in real time: see [the detection window](#the-detection-window) |
| Deny reads of tagged objects, including versioned reads | Stop a principal that is exempted (the Macie service-linked role, break-glass roles) |
| Stop anyone but the remediation role changing tags on a sensitive object | Protect the management account from SCPs (SCPs never apply to it) |
| Alarm when a finding fails to reach, or is not processed by, the remediation Lambda | Detect sensitive data that Macie's managed identifiers do not recognise |
| Reject insecure Terraform plans in CI | Replace reviewing OPA rules: they only check what they were written to check |

### The detection window

Detection is not instant. Macie scans on a daily schedule, so an object uploaded between two
runs is readable until the next run finishes and its finding reaches the Lambda. The
default mode is therefore **fail-open**. To close the window, turn on
[fail-closed mode](#fail-closed-mode).

## Architecture

```
S3 upload
   |
   v
Macie scheduled classification job (daily)
   |  every CLASSIFICATION finding, any severity
   v
EventBridge rule  --(retry 8x / 1h)-->  Lambda remediation  --(2 retries)-->  failure queue
   |                                        |                                     |
   | undeliverable                          | tags Sensitive=true,                |
   v                                        | DataClassification, Compliance      |
DLQ (SQS)                                   | publishes a Security Hub finding    |
   |                                        v                                     |
   +-----------------------------> CloudWatch alarms ------> SNS (KMS) -----> email
                                            
S3 bucket policy: explicit Deny on Sensitive=true objects (reads, tag changes)
```

## Controls

### 1. S3 bucket policy (`terraform_modules/s3-dlp`)

One policy document, all statements are explicit denies:

| Statement | Effect |
| --------- | ------ |
| `DenyReadOfSensitiveObjects` | Denies `s3:GetObject`, `s3:GetObjectVersion` and `s3:GetObjectVersionAttributes` on objects tagged `Sensitive=true`. Versioning is on, so the version variants matter. |
| `DenyTagTamperingOnSensitiveObjects` | Denies `Put/DeleteObjectTagging` and their `Version` variants on `Sensitive=true` objects, so the tag cannot be flipped or removed. |
| `DenyInsecureTransport` | Denies all S3 actions over plain HTTP. |
| `DenyOldTlsVersions` | Denies all S3 actions below TLS 1.2. |

Exemptions are made with `aws:PrincipalArn` conditions (a bucket policy cannot use `NotPrincipal` safely here):

- **Macie service-linked role**: exempt from the read deny, so tagged objects can still be re-scanned.
- **Remediation Lambda role**: the only role (plus break-glass) that may change tags on a sensitive object.
- **`break_glass_role_arns`** (variable, empty by default): may read sensitive objects and change their tags. The role itself is **not** created here: create it yourself, restrict who can assume it, and monitor its use in CloudTrail. With an empty list, nobody can read a sensitive object, including to release a false positive.

Limits to know about:

- A bucket policy cannot stop the **bucket owner account's root user or an admin** replacing the policy itself. The SCP in section 3 covers that.
- `s3:ExistingObjectTag` is checked at request time against the object's current tags. An object that Macie has not yet tagged is not protected.

### 2. Detection (`macie`, `eventbridge`, `lambda-remediation`, `alerting`)

- **Macie job**: a `SCHEDULED` daily job, first run immediately, 100% sampling. A `ONE_TIME` job would only scan what exists at apply time. Macie publishes updates to existing findings every 15 minutes (`finding_publishing_frequency`).
- **Every severity**: the EventBridge rule matches all `CLASSIFICATION` findings. Macie rates small PII counts as Low, and a severity filter would leave those objects readable.
- **Failure handling**: EventBridge retries delivery for up to 1 hour (8 attempts), then writes the event to an SQS dead-letter queue. The Lambda retries twice, then sends the event to a failure queue. Both queues are encrypted and TLS-only.
- **Alarms** (all notify an encrypted SNS topic, one email subscription per address in `alert_emails`, **each of which must confirm**):
  - messages waiting in either queue
  - Lambda errors (remediation, and the sweeper when fail-closed is on)
  - EventBridge `FailedInvocations` and `InvocationsFailedToBeSentToDlq`
- **Remediation Lambda** is idempotent: it merges tags rather than overwriting, uses a deterministic Security Hub finding ID, and re-raises on failure so the retry and failure paths run.

An alarm means a finding was **not** acted on. Investigate it, fix the cause, and replay the event from the queue.

### Fail-closed mode

`fail_closed = true` (default `false`) removes the detection window at a cost.

- The bucket policy additionally denies reads of any object **not** tagged `Scanned=true`, and denies anyone except the remediation role, the sweeper role and break-glass roles from writing that tag.
- A sweeper Lambda (`terraform_modules/fail-closed-sweeper`, hourly) marks objects `Scanned=true`. It only does so when the Macie job is `IDLE`, has completed at least one run with no access errors, and that run started at least 2 hours ago (so findings reach the remediation Lambda first). It only touches object versions last modified **before** that run started, and it never touches an object tagged `Sensitive=true`.
- If an object becomes `Sensitive=true` between the sweeper reading its tags and writing them, the bucket policy denies the sweeper's write, and the object stays locked.

Consequences you must accept before enabling it:

- **New uploads are unreadable for up to about a day** (next Macie run, plus the grace period, plus the next hourly sweep). Do not enable it for buckets that applications read straight after writing.
- **Writers must not set `Scanned`** on objects themselves: the policy denies it.
- The sweeper's per-run limit is 2,000 object versions. A large backlog is released over several runs.
- Enabling it on a bucket with existing objects makes all of them unreadable until the first sweep completes.

### 3. Service control policies (`terraform_modules/scp`, `org_guardrails`)

SCPs are deployed by a **separate stack**, `org_guardrails/`, because they need the AWS
Organizations management account and have a large blast radius. It is **not** part of the CI/CD
deploy workflows. Apply it by hand, from the management account, after the workload stack exists.

The SCP (`aws_organizations_policy`, attached to the targets you choose) denies the following, except for `exempt_principal_arns`:

- disabling Macie, GuardDuty or Security Hub, or leaving their organization
- stopping or weakening CloudTrail
- changing or deleting the DLP bucket policy
- changing or deleting tags on `Sensitive=true` objects
- deleting or disabling the remediation Lambda and its EventBridge rule, and changing the Macie job

`exempt_principal_arns` **must** include your Terraform apply roles and the remediation Lambda role,
or the SCP blocks your own deployments. The module refuses an empty list.

Limits:

- SCPs **never apply to the management account**, and do not affect service-linked roles.
- SCPs deny only. They grant nothing.
- The stack refuses to run outside `management_account_id`.
- Roll out to a staging OU or account first, then widen `target_ids`.
- The earlier `deny-sensitive-downloads.json` was removed: it used a `Principal` element, which SCPs do not support, and it duplicated the bucket policy.

### 4. OPA policy gate (`terraform_modules/opa/policies`)

CI evaluates the Terraform plan against these rules and fails on any violation:

- every bucket has SSE-KMS, a full public access block and a bucket policy
- the bucket policy denies `GetObject` **and** `GetObjectVersion` on the Sensitive tag, denies all tagging actions (including version variants) on Sensitive objects, and denies non-TLS requests
- Macie is enabled, and its classification job is not `ONE_TIME`
- no Macie EventBridge rule filters by severity
- no IAM policy grants `*` or `s3:*` in an Allow
- Lambda functions set `source_code_hash`

These checks read the **statements as written in HCL** (the plan's `configuration` section). They verify that the controls are present, not that AWS enforces them. The rules do not currently check: CloudTrail, KMS key rotation, or the SCP content.

## Naming and environments

Every named resource is prefixed `dlp-<environment>` (for example `dlp-staging-macie-remediation`),
so staging and production can share an account or region without colliding. The provider pins
`allowed_account_ids`, so a wrong role cannot deploy into the wrong account.

Account-wide singletons are still one-per-account: `aws_macie2_account`, `aws_securityhub_account`
and the cost allocation tag. **Use one AWS account per environment** (the recommended setup). If two
environments share an account, the second apply fails on Macie and Security Hub because they are
already enabled.

## Cost control

- **Budget**: monthly, with alerts at 80% (actual), 100% (forecast) and 100% (actual). By default it filters on the `Amazon Macie` service, which always works.
- **Cost allocation tag**: AWS lists a tag for activation only after it has appeared on billed resources, which takes up to 24 hours. Leave `activate_cost_allocation_tag = false` for the first deploy. Once the `CostCenter` tag shows up in the Billing console, set it to `true` and redeploy; the budget then filters on `CostCenter=Security-DLP`. Activation is account-wide, so enable it in only one environment per account, and the applying role needs `ce:UpdateCostAllocationTagsStatus` (payer account).
- **Anomaly detection**: a service-level monitor with a daily email summary.

Macie's scanning charges are not covered by a resource tag, which is why the service filter is the default.

## CI/CD

Workflows live in `.github/workflows/`.

| Workflow | Trigger | What it does |
| -------- | ------- | ------------ |
| `pr.yml` | Pull request to `main` | **Static checks**: `terraform fmt -check`, `validate` (workload and `org_guardrails`), Lambda unit tests, OPA format, strict check and unit tests. **Plan and OPA gate**: a read-only staging plan, then `opa eval` of the plan JSON, failing on any `deny`. |
| `deploy-staging.yml` | Push to `main` | plan, OPA gate, then apply of the exact saved plan |
| `deploy-prod.yml` | Manual, from `main` or a tag | plan, OPA gate, reviewer approval, then apply of the exact saved plan |
| `terraform.yml` | Called by the three above | Shared plan, gate and apply logic (not run directly) |

How it works:

- Plan and apply are separate jobs. The apply job downloads the plan artifact the plan job produced and OPA-checked, and runs `terraform apply tfplan`. Terraform rejects a saved plan if state changed in between.
- The `environment:` key is only on the apply job, so required reviewers on the GitHub `production` environment approve after the plan is visible in the job summary.
- AWS access uses GitHub OIDC with no long-lived keys. Plan and apply use separate roles.
- Each environment has its own state: `s3://<bucket>/dlp/<environment>/terraform.tfstate`. Backend settings are passed at `init` time and `environments/<env>.tfvars` is passed with `-var-file`.
- Deploys for an environment are serialised and never cancelled mid-apply.
- A deploy fails fast if `environments/<env>.tfvars` still contains `REPLACE-ME`.
- PRs from forks skip the plan job, because they cannot obtain OIDC credentials.

One-time setup:

1. Create an S3 state bucket per environment (versioning and encryption on).
2. Create the GitHub OIDC identity provider in each AWS account, plus two IAM roles per environment:
   - **Plan role**: read-only (`ReadOnlyAccess` plus read on the state bucket). Trust `sub` values `repo:<org>/<repo>:pull_request` and `repo:<org>/<repo>:ref:refs/heads/main`.
   - **Apply role**: write access to deploy the stack and the state bucket. Trust `sub` `repo:<org>/<repo>:environment:<staging|production>`.
3. Set these repository variables: `STAGING_TF_STATE_BUCKET`, `STAGING_PLAN_ROLE_ARN`, `STAGING_APPLY_ROLE_ARN`, `PRODUCTION_TF_STATE_BUCKET`, `PRODUCTION_PLAN_ROLE_ARN`, `PRODUCTION_APPLY_ROLE_ARN`, and optionally `TF_AWS_REGION` (default `eu-west-1`).
4. Replace every `REPLACE-ME` in `root_module/environments/*.tfvars`, including `allowed_account_id`.
5. Create the `staging` and `production` GitHub environments, with required reviewers on `production`.
6. Protect `main`: require the `Static checks` and `Plan and OPA gate` checks and a pull request review.

The plan job's role also needs to read what it plans: the `ReadOnlyAccess` managed policy covers it.

## Repository layout

```
.github/workflows/        CI/CD (pr, deploy-staging, deploy-prod, terraform)
root_module/              Workload stack: wires the modules together, per-environment tfvars
org_guardrails/           Organization SCP stack (apply by hand, management account)
terraform_modules/
  kms/                    Customer-managed key (Macie and CloudWatch can use it)
  s3/                     Bucket: versioning, SSE-KMS, public access block
  s3-dlp/                 DLP bucket policy (reads, tag protection, TLS, fail-closed)
  macie/                  Macie account and the scheduled classification job
  eventbridge/            Finding rule, retry policy, dead-letter queue
  lambda-remediation/     Tagging Lambda, async retry and failure queue
  fail-closed-sweeper/    Optional: marks scanned objects Scanned=true (+ unit tests)
  alerting/               SNS topic and alarms
  iam/                    Remediation Lambda role and policy
  securityhub/            Security Hub (receives the Lambda's findings)
  cost-control/           Budget, anomaly detection, cost allocation tag
  scp/                    Service control policy (used by org_guardrails)
  opa/policies/           Rego policies and their tests
  cloudwatch-dashboard/   Billing dashboard (not wired into root_module)
```

## Local use

```
cd root_module
terraform init -backend-config="bucket=<state-bucket>" \
  -backend-config="key=dlp/staging/terraform.tfstate" -backend-config="region=eu-west-1"
terraform plan -var-file=environments/staging.tfvars -out=tfplan

terraform show -json tfplan > plan.json
opa test ../terraform_modules/opa/policies
opa eval --fail-defined --format pretty --data ../terraform_modules/opa/policies \
  --input plan.json 'data.terraform.security.deny[msg]'

python -m unittest discover -s ../terraform_modules/fail-closed-sweeper/tests -v
```

`opa eval --fail-defined` exits 1 when any rule denies, and prints the reasons.

## Known gaps

- The state buckets, OIDC provider and IAM roles are created by hand: there is no bootstrap stack yet.
- No break-glass role is created: you must provide one.
- The `cloudwatch-dashboard` module is not wired into `root_module`, and needs billing metrics enabled in `us-east-1`.
- OPA does not yet check CloudTrail, KMS rotation or the SCP content, and the repo creates no CloudTrail data-event trail for bucket access auditing.
- The bucket has no access logging, lifecycle rule or noncurrent-version expiry, so versions accumulate and cost grows.
- The Lambda has no reserved concurrency, tracing or KMS-encrypted logs, and still uses the AWS-managed `AWSLambdaBasicExecutionRole`.
- Macie discovery results are not exported to S3 for long-term evidence.
