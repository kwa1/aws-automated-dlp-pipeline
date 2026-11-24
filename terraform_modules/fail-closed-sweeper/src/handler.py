"""Fail-closed sweeper: mark objects Scanned=true once Macie has demonstrably scanned them.

With fail-closed mode on, the bucket policy denies reads of any object that is not tagged
Scanned=true (Sensitive objects stay denied regardless). This function releases objects
only when ALL of these hold:

* the recurring Macie job is IDLE (not RUNNING, PAUSED over quota, or cancelled),
* its last run reported no error,
* the last run started at least GRACE_MINUTES ago, so findings had time to reach the
  remediation Lambda and tag the sensitive objects first,
* the object version was last modified before that run started, so the run saw it.

Lambda does not copy, move or delete data; it only writes the Scanned tag.
"""
import datetime
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

BUCKET = os.environ["BUCKET_NAME"]
JOB_ID = os.environ["MACIE_JOB_ID"]
GRACE = datetime.timedelta(minutes=int(os.getenv("GRACE_MINUTES", "120")))
# Bounds one invocation; remaining objects are picked up by the next scheduled run.
MAX_OBJECTS_PER_RUN = int(os.getenv("MAX_OBJECTS_PER_RUN", "2000"))

SCANNED_TAG = "Scanned"
SENSITIVE_TAG = "Sensitive"

s3 = boto3.client("s3")
macie = boto3.client("macie2")


def lambda_handler(event, context, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)

    job = macie.describe_classification_job(jobId=JOB_ID)
    cutoff = scan_cutoff(job, now)
    if cutoff is None:
        return {"status": "skipped"}

    marked = skipped = examined = 0
    for version in iter_versions(BUCKET):
        if examined >= MAX_OBJECTS_PER_RUN:
            logger.info("Per-run object limit reached", extra={"limit": MAX_OBJECTS_PER_RUN})
            break
        examined += 1

        if version["LastModified"] > cutoff:
            skipped += 1  # uploaded after the last scan started; wait for the next run
            continue

        if mark_scanned(BUCKET, version["Key"], version["VersionId"]):
            marked += 1

    logger.info(
        "Sweep finished",
        extra={"examined": examined, "marked": marked, "not_yet_scanned": skipped},
    )
    return {"status": "swept", "marked": marked}


def scan_cutoff(job, now):
    """Return the time before which objects are known to have been scanned, or None."""
    status = job.get("jobStatus")
    last_run = job.get("lastRunTime")
    runs = (job.get("statistics") or {}).get("numberOfRuns", 0)
    error_code = (job.get("lastRunErrorStatus") or {}).get("code", "NONE")

    if status != "IDLE":
        logger.info("Macie job not idle; nothing released", extra={"job_status": status})
        return None
    # For a recurring job that has not run yet, Macie reports lastRunTime as the time the
    # job was CREATED. Only numberOfRuns proves a scan actually happened.
    if runs < 1 or last_run is None:
        logger.info("Macie job has not completed a run yet; nothing released")
        return None
    if error_code != "NONE":
        logger.warning("Last Macie run had errors; nothing released", extra={"error_code": error_code})
        return None
    if now - last_run < GRACE:
        logger.info("Within grace period after last Macie run; nothing released")
        return None
    return last_run


def iter_versions(bucket):
    """Yield every non-delete-marker object version in the bucket."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for version in page.get("Versions", []):
            yield version


def mark_scanned(bucket, key, version_id):
    """Add Scanned=true unless already present. Returns True when the tag was written."""
    current = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=version_id)["TagSet"]
    tags = {t["Key"]: t["Value"] for t in current}

    if tags.get(SCANNED_TAG) == "true":
        return False
    if tags.get(SENSITIVE_TAG) == "true":
        # Remediation got there first. The object stays denied; never touch its tags.
        return False

    tags[SCANNED_TAG] = "true"
    try:
        s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            VersionId=version_id,
            Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]},
        )
    except ClientError as err:
        # Remediation tagged the object Sensitive=true after we read its tags. The bucket
        # policy denies this sweeper from replacing the tag set of a Sensitive object, which
        # is exactly the outcome we want: leave the object locked and carry on.
        if err.response.get("Error", {}).get("Code") == "AccessDenied":
            logger.info("Object became Sensitive during sweep; left locked", extra={"key": key})
            return False
        raise
    return True
