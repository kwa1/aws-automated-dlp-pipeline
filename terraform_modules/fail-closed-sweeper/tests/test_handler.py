"""Unit tests for the fail-closed sweeper (no AWS access or boto3 install needed).

Run: python -m unittest discover -s terraform_modules/fail-closed-sweeper/tests
"""
import datetime
import os
import sys
import unittest
from unittest import mock

os.environ.setdefault("BUCKET_NAME", "test-bucket")
os.environ.setdefault("MACIE_JOB_ID", "job-1")
os.environ.setdefault("GRACE_MINUTES", "120")

sys.modules.setdefault("boto3", mock.MagicMock())
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import handler  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 1, 10, 12, 0, tzinfo=UTC)
LAST_RUN = NOW - datetime.timedelta(hours=5)


def job(status="IDLE", last_run=LAST_RUN, error="NONE"):
    return {"jobStatus": status, "lastRunTime": last_run, "lastRunErrorStatus": {"code": error}}


class ScanCutoffTests(unittest.TestCase):
    def test_idle_clean_job_past_grace_returns_last_run(self):
        self.assertEqual(handler.scan_cutoff(job(), NOW), LAST_RUN)

    def test_running_job_releases_nothing(self):
        self.assertIsNone(handler.scan_cutoff(job(status="RUNNING"), NOW))

    def test_quota_paused_job_releases_nothing(self):
        self.assertIsNone(handler.scan_cutoff(job(status="PAUSED"), NOW))

    def test_job_that_never_ran_releases_nothing(self):
        self.assertIsNone(handler.scan_cutoff(job(last_run=None), NOW))

    def test_run_with_errors_releases_nothing(self):
        self.assertIsNone(handler.scan_cutoff(job(error="ERROR"), NOW))

    def test_within_grace_period_releases_nothing(self):
        recent = NOW - datetime.timedelta(minutes=30)
        self.assertIsNone(handler.scan_cutoff(job(last_run=recent), NOW))


class MarkScannedTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(handler, "s3")
        self.s3 = patcher.start()
        self.addCleanup(patcher.stop)

    def tags(self, **kw):
        self.s3.get_object_tagging.return_value = {"TagSet": [{"Key": k, "Value": v} for k, v in kw.items()]}

    def written(self):
        return {t["Key"]: t["Value"] for t in self.s3.put_object_tagging.call_args.kwargs["Tagging"]["TagSet"]}

    def test_untagged_object_gets_scanned_tag(self):
        self.tags()
        self.assertTrue(handler.mark_scanned("b", "k", "v1"))
        self.assertEqual(self.written(), {"Scanned": "true"})

    def test_existing_tags_are_preserved(self):
        self.tags(Owner="team-a")
        handler.mark_scanned("b", "k", "v1")
        self.assertEqual(self.written(), {"Owner": "team-a", "Scanned": "true"})

    def test_version_id_is_passed_through(self):
        self.tags()
        handler.mark_scanned("b", "k", "v9")
        self.assertEqual(self.s3.put_object_tagging.call_args.kwargs["VersionId"], "v9")

    def test_already_scanned_object_is_not_rewritten(self):
        self.tags(Scanned="true")
        self.assertFalse(handler.mark_scanned("b", "k", "v1"))
        self.s3.put_object_tagging.assert_not_called()

    def test_sensitive_object_is_never_touched(self):
        self.tags(Sensitive="true")
        self.assertFalse(handler.mark_scanned("b", "k", "v1"))
        self.s3.put_object_tagging.assert_not_called()


class LambdaHandlerTests(unittest.TestCase):
    def setUp(self):
        for name in ("s3", "macie"):
            p = mock.patch.object(handler, name)
            setattr(self, name, p.start())
            self.addCleanup(p.stop)
        self.s3.get_object_tagging.return_value = {"TagSet": []}

    def versions(self, *items):
        self.s3.get_paginator.return_value.paginate.return_value = [{"Versions": list(items)}]

    def test_skips_when_job_not_ready(self):
        self.macie.describe_classification_job.return_value = job(status="RUNNING")
        self.assertEqual(handler.lambda_handler({}, None, now=NOW), {"status": "skipped"})
        self.s3.get_paginator.assert_not_called()

    def test_only_objects_older_than_last_run_are_marked(self):
        self.macie.describe_classification_job.return_value = job()
        old = {"Key": "old", "VersionId": "1", "LastModified": LAST_RUN - datetime.timedelta(hours=1)}
        new = {"Key": "new", "VersionId": "1", "LastModified": LAST_RUN + datetime.timedelta(hours=1)}
        self.versions(old, new)

        result = handler.lambda_handler({}, None, now=NOW)

        self.assertEqual(result, {"status": "swept", "marked": 1})
        self.assertEqual(self.s3.put_object_tagging.call_args.kwargs["Key"], "old")

    def test_per_run_limit_bounds_work(self):
        self.macie.describe_classification_job.return_value = job()
        old = LAST_RUN - datetime.timedelta(hours=1)
        self.versions(*[{"Key": f"k{i}", "VersionId": "1", "LastModified": old} for i in range(5)])

        with mock.patch.object(handler, "MAX_OBJECTS_PER_RUN", 2):
            result = handler.lambda_handler({}, None, now=NOW)

        self.assertEqual(result["marked"], 2)


if __name__ == "__main__":
    unittest.main()
