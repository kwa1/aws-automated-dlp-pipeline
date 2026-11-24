package terraform.security_test

import data.terraform.security
import rego.v1

# ----------------------------------------------------------------- fixtures

read_statement := {
	"effect": {"constant_value": "Deny"},
	"actions": {"constant_value": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectVersionAttributes"]},
	"condition": [{
		"test": {"constant_value": "StringEquals"},
		"variable": {"constant_value": "s3:ExistingObjectTag/Sensitive"},
		"values": {"constant_value": ["true"]},
	}],
}

tagging_statement := {
	"effect": {"constant_value": "Deny"},
	"actions": {"constant_value": [
		"s3:PutObjectTagging",
		"s3:PutObjectVersionTagging",
		"s3:DeleteObjectTagging",
		"s3:DeleteObjectVersionTagging",
	]},
	"condition": [{
		"test": {"constant_value": "StringEquals"},
		"variable": {"constant_value": "s3:ExistingObjectTag/Sensitive"},
		"values": {"constant_value": ["true"]},
	}],
}

tls_statement := {
	"effect": {"constant_value": "Deny"},
	"actions": {"constant_value": ["s3:*"]},
	"condition": [{
		"test": {"constant_value": "Bool"},
		"variable": {"constant_value": "aws:SecureTransport"},
		"values": {"constant_value": ["false"]},
	}],
}

dlp_doc := {
	"address": "aws_iam_policy_document.dlp",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"name": "dlp",
	"expressions": {"statement": [read_statement, tagging_statement, tls_statement]},
}

# JSON-patch path of the DLP document's statement list.
stmts := "/configuration/root_module/module_calls/s3_dlp/module/resources/0/expressions/statement"

good_input := {
	"resource_changes": [
		{
			"address": "module.s3.aws_s3_bucket.this",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"change": {"actions": ["create"], "after": {"bucket": "b"}},
		},
		{
			"address": "module.s3.aws_s3_bucket_server_side_encryption_configuration.this",
			"mode": "managed",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"actions": ["create"], "after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}},
		},
		{
			"address": "module.s3.aws_s3_bucket_public_access_block.this",
			"mode": "managed",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"actions": ["create"], "after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
		{
			"address": "module.s3_dlp.aws_s3_bucket_policy.this",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"change": {"actions": ["create"], "after": {}},
		},
		{
			"address": "module.macie.aws_macie2_account.this",
			"mode": "managed",
			"type": "aws_macie2_account",
			"change": {"actions": ["create"], "after": {"status": "ENABLED"}},
		},
		{
			"address": "module.iam.aws_iam_policy.lambda_dlp",
			"mode": "managed",
			"type": "aws_iam_policy",
			"change": {"actions": ["create"], "after": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObjectTagging\"],\"Resource\":\"*\"}]}"}},
		},
		{
			"address": "module.lambda.aws_lambda_function.this",
			"mode": "managed",
			"type": "aws_lambda_function",
			"change": {"actions": ["create"], "after": {"filename": "x.zip", "source_code_hash": "abc"}},
		},
	],
	"configuration": {"root_module": {"module_calls": {"s3_dlp": {"module": {"resources": [dlp_doc]}}}}},
}

# ------------------------------------------------------------------- tests

test_compliant_plan_has_no_denials if {
	count(security.deny) == 0 with input as good_input
}

test_unencrypted_bucket_denied if {
	bad := json.patch(good_input, [{"op": "remove", "path": "/resource_changes/1"}])
	some msg in security.deny with input as bad
	contains(msg, "aws:kms default encryption")
}

test_non_kms_encryption_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/resource_changes/1/change/after/rule/0/apply_server_side_encryption_by_default/0/sse_algorithm", "value": "AES256"}])
	some msg in security.deny with input as bad
	contains(msg, "must use SSE-KMS")
}

test_missing_public_access_block_denied if {
	bad := json.patch(good_input, [{"op": "remove", "path": "/resource_changes/2"}])
	some msg in security.deny with input as bad
	contains(msg, "public_access_block")
}

test_public_access_block_disabled_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/resource_changes/2/change/after/block_public_acls", "value": false}])
	some msg in security.deny with input as bad
	contains(msg, "block_public_acls")
}

test_missing_bucket_policy_denied if {
	bad := json.patch(good_input, [{"op": "remove", "path": "/resource_changes/3"}])
	some msg in security.deny with input as bad
	contains(msg, "aws_s3_bucket_policy")
}

test_bucket_policy_without_sensitive_deny_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/configuration/root_module/module_calls/s3_dlp/module/resources", "value": []}])
	some msg in security.deny with input as bad
	contains(msg, "Sensitive")
}

test_missing_macie_denied if {
	bad := json.patch(good_input, [{"op": "remove", "path": "/resource_changes/4"}])
	some msg in security.deny with input as bad
	contains(msg, "Macie must be enabled")
}

test_disabled_macie_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/resource_changes/4/change/after/status", "value": "PAUSED"}])
	some msg in security.deny with input as bad
	contains(msg, "ENABLED")
}

test_wildcard_iam_policy_json_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/resource_changes/5/change/after/policy", "value": "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}}"}])
	some msg in security.deny with input as bad
	contains(msg, "wildcard action")
}

test_full_star_action_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": "/resource_changes/5/change/after/policy", "value": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":\"*\"}]}"}])
	some msg in security.deny with input as bad
	contains(msg, "wildcard action")
}

test_wildcard_in_policy_document_denied if {
	doc := {
		"address": "aws_iam_policy_document.lambda",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"expressions": {"statement": [{"actions": {"constant_value": ["s3:*"]}}]},
	}
	bad := json.patch(good_input, [{"op": "add", "path": "/configuration/root_module/module_calls/s3_dlp/module/resources/-", "value": doc}])
	some msg in security.deny with input as bad
	contains(msg, "wildcard action")
}

test_deny_statement_with_wildcard_is_allowed if {
	doc := {
		"address": "aws_iam_policy_document.guard",
		"mode": "data",
		"type": "aws_iam_policy_document",
		"expressions": {"statement": [{"effect": {"constant_value": "Deny"}, "actions": {"constant_value": ["s3:*"]}}]},
	}
	ok := json.patch(good_input, [{"op": "add", "path": "/configuration/root_module/module_calls/s3_dlp/module/resources/-", "value": doc}])
	count(security.deny) == 0 with input as ok
}

test_lambda_without_source_hash_denied if {
	bad := json.patch(good_input, [{"op": "remove", "path": "/resource_changes/6/change/after/source_code_hash"}])
	some msg in security.deny with input as bad
	contains(msg, "source_code_hash")
}

test_deleted_resources_ignored if {
	ok := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": {
		"address": "aws_s3_bucket.old",
		"mode": "managed",
		"type": "aws_s3_bucket",
		"change": {"actions": ["delete"], "after": null},
	}}])
	count(security.deny) == 0 with input as ok
}

test_empty_plan_has_no_denials if {
	count(security.deny) == 0 with input as {"resource_changes": [], "configuration": {"root_module": {}}}
}

# ------------------------------------------------- hardened bucket policy rules

# Remove statement `i` from the DLP policy document.
without_statement(i) := json.patch(good_input, [{"op": "remove", "path": sprintf("%s/%d", [stmts, i])}])

test_missing_version_read_deny_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": concat("", [stmts, "/0/actions/constant_value"]), "value": ["s3:GetObject"]}])
	some msg in security.deny with input as bad
	contains(msg, "s3:GetObjectVersion")
}

test_missing_read_deny_statement_denied if {
	some msg in security.deny with input as without_statement(0)
	contains(msg, "s3:GetObjectVersion")
}

test_missing_tag_tamper_deny_denied if {
	some msg in security.deny with input as without_statement(1)
	contains(msg, "re-tagged or untagged")
}

test_tag_deny_missing_version_variant_denied if {
	bad := json.patch(good_input, [{"op": "replace", "path": concat("", [stmts, "/1/actions/constant_value"]), "value": ["s3:PutObjectTagging", "s3:DeleteObjectTagging"]}])
	some msg in security.deny with input as bad
	contains(msg, "re-tagged or untagged")
}

test_missing_tls_deny_denied if {
	some msg in security.deny with input as without_statement(2)
	contains(msg, "without TLS")
}

test_allow_statement_does_not_satisfy_tag_deny if {
	bad := json.patch(good_input, [{"op": "replace", "path": concat("", [stmts, "/1/effect/constant_value"]), "value": "Allow"}])
	some msg in security.deny with input as bad
	contains(msg, "re-tagged or untagged")
}

test_computed_actions_do_not_satisfy_read_deny if {
	bad := json.patch(good_input, [{"op": "remove", "path": concat("", [stmts, "/0/actions"])}])
	some msg in security.deny with input as bad
	contains(msg, "s3:GetObjectVersion")
}

# ----------------------------------------------------- detection rules

macie_job(job_type) := {
	"address": "module.macie.aws_macie2_classification_job.scan",
	"mode": "managed",
	"type": "aws_macie2_classification_job",
	"change": {"actions": ["create"], "after": {"job_type": job_type}},
}

macie_rule(pattern) := {
	"address": "module.eventbridge.aws_cloudwatch_event_rule.macie",
	"mode": "managed",
	"type": "aws_cloudwatch_event_rule",
	"change": {"actions": ["create"], "after": {"event_pattern": json.marshal(pattern)}},
}

test_scheduled_macie_job_allowed if {
	ok := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": macie_job("SCHEDULED")}])
	count(security.deny) == 0 with input as ok
}

test_one_time_macie_job_denied if {
	bad := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": macie_job("ONE_TIME")}])
	some msg in security.deny with input as bad
	contains(msg, "ONE_TIME")
}

test_macie_rule_without_severity_filter_allowed if {
	ok := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": macie_rule({
		"source": ["aws.macie"],
		"detail": {"category": ["CLASSIFICATION"]},
	})}])
	count(security.deny) == 0 with input as ok
}

test_macie_rule_with_severity_filter_denied if {
	bad := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": macie_rule({
		"source": ["aws.macie"],
		"detail": {"category": ["CLASSIFICATION"], "severity": {"description": ["High", "Medium"]}},
	})}])
	some msg in security.deny with input as bad
	contains(msg, "filters Macie findings by severity")
}

test_unrelated_event_rule_with_severity_allowed if {
	ok := json.patch(good_input, [{"op": "add", "path": "/resource_changes/-", "value": macie_rule({
		"source": ["aws.guardduty"],
		"detail": {"severity": [7]},
	})}])
	count(security.deny) == 0 with input as ok
}
