package terraform.security

import rego.v1

# Policy gate evaluated against `terraform show -json <plan>` output.
#
# Resource attributes that depend on not-yet-created resources are unknown at
# plan time (and therefore absent from `change.after`). Content checks on such
# values read the plan's `configuration` section instead, which always holds
# the literal HCL expressions.

# ---------------------------------------------------------------- helpers

managed(type) := [r |
	some r in input.resource_changes
	r.mode == "managed"
	r.type == type
	not deleting(r)
]

deleting(r) if r.change.actions == ["delete"]

buckets := managed("aws_s3_bucket")

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# aws_iam_policy_document data sources, wherever they sit in the module tree.
policy_docs := [n |
	walk(input.configuration, [_, n])
	n.mode == "data"
	n.type == "aws_iam_policy_document"
]

wildcard_action(a) if a == "*"

wildcard_action(a) if a == "s3:*"

# ------------------------------------------------------------- S3 controls

kms_sse(r) if {
	some rule in r.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm == "aws:kms"
}

deny contains msg if {
	count(buckets) > 0
	count([r | some r in managed("aws_s3_bucket_server_side_encryption_configuration"); kms_sse(r)]) < count(buckets)
	msg := "every aws_s3_bucket requires an aws:kms default encryption configuration"
}

deny contains msg if {
	some r in managed("aws_s3_bucket_server_side_encryption_configuration")
	some rule in r.change.after.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm != "aws:kms"
	msg := sprintf("%s must use SSE-KMS (aws:kms), found %s", [r.address, d.sse_algorithm])
}

deny contains msg if {
	count(buckets) > 0
	count(managed("aws_s3_bucket_public_access_block")) < count(buckets)
	msg := "every aws_s3_bucket requires an aws_s3_bucket_public_access_block"
}

deny contains msg if {
	some r in managed("aws_s3_bucket_public_access_block")
	some attr in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	r.change.after[attr] == false
	msg := sprintf("%s must set %s = true", [r.address, attr])
}

deny contains msg if {
	count(buckets) > 0
	count(managed("aws_s3_bucket_policy")) < count(buckets)
	msg := "every aws_s3_bucket requires an aws_s3_bucket_policy (DLP deny policy)"
}

# ------------------------------------------------- DLP bucket policy content
#
# The bucket policy is built with aws_iam_policy_document, so it is checked from the
# plan's `configuration` section. Action lists must be literal in HCL: a statement
# whose actions are computed cannot be verified and therefore does not count.

deny_statements := [st |
	some n in policy_docs
	some st in n.expressions.statement
	st.effect.constant_value == "Deny"
]

# A Deny statement conditioned on `key` that covers every action in `required`.
condition_deny_covers(key, required) if {
	some st in deny_statements
	some c in as_array(st.condition)
	c.variable.constant_value == key
	every a in required {
		a in st.actions.constant_value
	}
}

sensitive_tag := "s3:ExistingObjectTag/Sensitive"

deny contains msg if {
	count(buckets) > 0
	not condition_deny_covers(sensitive_tag, ["s3:GetObject", "s3:GetObjectVersion"])
	msg := "no bucket policy statement denies s3:GetObject and s3:GetObjectVersion based on the s3:ExistingObjectTag/Sensitive tag"
}

# Without this, anyone with tagging rights can flip Sensitive=false and re-open the object.
deny contains msg if {
	count(buckets) > 0
	not condition_deny_covers(sensitive_tag, [
		"s3:PutObjectTagging",
		"s3:PutObjectVersionTagging",
		"s3:DeleteObjectTagging",
		"s3:DeleteObjectVersionTagging",
	])
	msg := "no bucket policy statement stops Sensitive objects being re-tagged or untagged (tagging actions and their version variants)"
}

deny contains msg if {
	count(buckets) > 0
	not condition_deny_covers("aws:SecureTransport", ["s3:*"])
	msg := "no bucket policy statement denies requests made without TLS (aws:SecureTransport = false)"
}

# ------------------------------------------------------------------ Macie

deny contains msg if {
	count(buckets) > 0
	count(managed("aws_macie2_account")) == 0
	msg := "Macie must be enabled (aws_macie2_account missing) when S3 buckets are managed"
}

deny contains msg if {
	some r in managed("aws_macie2_account")
	r.change.after.status != "ENABLED"
	msg := sprintf("%s must have status ENABLED", [r.address])
}

# A ONE_TIME job only scans what exists at apply time, so later uploads are never classified.
deny contains msg if {
	some r in managed("aws_macie2_classification_job")
	r.change.after.job_type == "ONE_TIME"
	msg := sprintf("%s is a ONE_TIME job and never scans later uploads; use job_type SCHEDULED", [r.address])
}

# Macie rates small PII counts as Low. Filtering by severity would leave those objects readable.
deny contains msg if {
	some r in managed("aws_cloudwatch_event_rule")
	is_string(r.change.after.event_pattern)
	pattern := json.unmarshal(r.change.after.event_pattern)
	"aws.macie" in pattern.source
	pattern.detail.severity
	msg := sprintf("%s filters Macie findings by severity; every classification finding must reach remediation", [r.address])
}

# -------------------------------------------------------------------- IAM

# Policies whose JSON is already known at plan time.
deny contains msg if {
	some r in array.concat(managed("aws_iam_policy"), managed("aws_iam_role_policy"))
	doc := json.unmarshal(r.change.after.policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
	some a in as_array(st.Action)
	wildcard_action(a)
	msg := sprintf("%s grants wildcard action %q", [r.address, a])
}

# Policies built through aws_iam_policy_document (usually unknown at plan time).
deny contains msg if {
	some n in policy_docs
	some st in n.expressions.statement
	object.get(st, ["effect", "constant_value"], "Allow") == "Allow"
	some a in object.get(st, ["actions", "constant_value"], [])
	wildcard_action(a)
	msg := sprintf("%s grants wildcard action %q", [n.address, a])
}

# ----------------------------------------------------------------- Lambda

deny contains msg if {
	some r in managed("aws_lambda_function")
	not r.change.after.source_code_hash
	r.change.after.filename
	msg := sprintf("%s must set source_code_hash so code changes are deployed", [r.address])
}
