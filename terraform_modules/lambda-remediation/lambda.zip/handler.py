import boto3
import json
import logging
import os
import uuid
import datetime

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail", {})
    resources = detail.get("resourcesAffected", {})

    s3_bucket = resources.get("s3Bucket", {}).get("name")
    s3_object = resources.get("s3Object", {}).get("key")

    if not s3_bucket or not s3_object:
        logger.warning("No S3 object found in Macie finding")
        return

    classification = detail.get("classificationDetails", {}).get(
        "result", {}).get("status", "UNKNOWN"
    )

    try:
        # 1️⃣ Remove public ACLs (defense-in-depth)
        s3.put_object_acl(
            Bucket=s3_bucket,
            Key=s3_object,
            ACL="private"
        )

        # 2️⃣ Apply authoritative DLP tags
        s3.put_object_tagging(
            Bucket=s3_bucket,
            Key=s3_object,
            Tagging={
                "TagSet": [
                    {"Key": "Sensitive", "Value": "true"},
                    {"Key": "DataClassification", "Value": "PII"},
                    {"Key": "Compliance", "Value": "GDPR"}
                ]
            }
        )

        # 3️⃣ Publish Security Hub finding
        publish_securityhub_finding(
            context,
            s3_bucket,
            s3_object,
            classification
        )

        logger.info("DLP enforced for %s/%s", s3_bucket, s3_object)

    except Exception as e:
        logger.exception("DLP remediation failed")
        raise e


def publish_securityhub_finding(context, bucket, key, classification):
    account_id = context.invoked_function_arn.split(":")[4]

    securityhub.batch_import_findings(
        Findings=[{
            "SchemaVersion": "2018-10-08",
            "Id": str(uuid.uuid4()),
            "ProductArn": "arn:aws:securityhub:::product/aws/macie",
            "GeneratorId": "macie-dlp-lambda",
            "AwsAccountId": account_id,
            "Types": ["Sensitive Data Identification"],
            "CreatedAt": datetime.datetime.utcnow().isoformat() + "Z",
            "UpdatedAt": datetime.datetime.utcnow().isoformat() + "Z",
            "Severity": {"Label": "HIGH"},
            "Title": "Sensitive S3 object protected by DLP",
            "Description": (
                f"S3 object {key} in bucket {bucket} "
                f"was classified ({classification}) and download blocked."
            ),
            "Resources": [{
                "Type": "AwsS3Object",
                "Id": f"arn:aws:s3:::{bucket}/{key}"
            }],
            "Compliance": {"Status": "PASSED"}
        }]
    )
