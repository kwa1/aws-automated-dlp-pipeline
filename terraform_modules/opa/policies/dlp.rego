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

# The DLP bucket policy must contain an explicit Deny keyed on the Sensitive tag.
dlp_deny_configured if {
	some n in policy_docs
	some st in n.expressions.statement
	st.effect.constant_value == "Deny"
	some c in as_array(st.condition)
	c.variable.constant_value == "s3:ExistingObjectTag/Sensitive"
}

deny contains msg if {
	count(buckets) > 0
	not dlp_deny_configured
	msg := "no bucket policy statement denies access based on the s3:ExistingObjectTag/Sensitive tag"
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
