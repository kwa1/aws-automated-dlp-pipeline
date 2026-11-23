"""Macie finding remediation: tag sensitive S3 objects so the bucket policy denies reads."""
import datetime
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

# Tag keys owned by the DLP pipeline; they always win over pre-existing values.
DLP_TAG_KEYS = {"Sensitive", "DataClassification", "Compliance"}


def lambda_handler(event, context):
    detail = event.get("detail", {})
    finding_id = detail.get("id", "unknown")
    resources = detail.get("resourcesAffected", {})

    bucket = resources.get("s3Bucket", {}).get("name")
    key = resources.get("s3Object", {}).get("key")
    version_id = resources.get("s3Object", {}).get("versionId")

    if not bucket or not key:
        logger.warning("No S3 object in Macie finding", extra={"finding_id": finding_id})
        return {"status": "skipped"}

    categories = sorted({
        item.get("category")
        for item in detail.get("classificationDetails", {})
        .get("result", {})
        .get("sensitiveData", [])
        if item.get("category")
    })
    classification = "+".join(categories) if categories else "UNKNOWN"

    dlp_tags = {"Sensitive": "true", "DataClassification": classification}
    if "PERSONAL_INFORMATION" in categories or classification == "UNKNOWN":
        dlp_tags["Compliance"] = "GDPR"

    try:
        apply_tags(bucket, key, version_id, dlp_tags)
        publish_securityhub_finding(context, finding_id, bucket, key, classification)
    except Exception:
        logger.exception("DLP remediation failed", extra={"finding_id": finding_id})
        raise

    logger.info("DLP tags applied", extra={"finding_id": finding_id, "bucket": bucket})
    return {"status": "tagged"}


def apply_tags(bucket, key, version_id, dlp_tags):
    """Merge DLP tags into the existing tag set (put_object_tagging replaces it)."""
    version_args = {"VersionId": version_id} if version_id else {}

    current = s3.get_object_tagging(Bucket=bucket, Key=key, **version_args)["TagSet"]
    merged = {t["Key"]: t["Value"] for t in current if t["Key"] not in DLP_TAG_KEYS}
    merged.update(dlp_tags)

    s3.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in merged.items()]},
        **version_args,
    )


def publish_securityhub_finding(context, finding_id, bucket, key, classification):
    arn_parts = context.invoked_function_arn.split(":")
    region, account_id = arn_parts[3], arn_parts[4]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    securityhub.batch_import_findings(
        Findings=[{
            "SchemaVersion": "2018-10-08",
            # Deterministic ID so retries update the same finding instead of duplicating it.
            "Id": f"macie-dlp/{finding_id}",
            "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            "GeneratorId": "macie-dlp-lambda",
            "AwsAccountId": account_id,
            "Types": ["Sensitive Data Identifications/PII/Sensitive S3 Object"],
            "CreatedAt": now,
            "UpdatedAt": now,
            "Severity": {"Label": "HIGH"},
            "Title": "Sensitive S3 object protected by DLP",
            "Description": (
                f"An object in bucket {bucket} was classified ({classification}) by Macie "
                "and tagged Sensitive=true; downloads are denied by bucket policy."
            ),
            "Resources": [{
                "Type": "AwsS3Object",
                "Id": f"arn:aws:s3:::{bucket}/{key}",
            }],
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }]
    )
