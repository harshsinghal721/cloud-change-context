import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from unittest.mock import patch

from cloud_change_context.cli import main
from cloud_change_context.cloudtrail import CloudTrailError
from cloud_change_context.models import Change, Evidence

NOW = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)


def make_change():
    return Change(
        event_id="event-1",
        time=NOW,
        actor="harsh",
        actor_identifiers=("harsh",),
        event_source="s3.amazonaws.com",
        event_name="PutBucketPublicAccessBlock",
        resource="arn:aws:s3:::acme-logs",
        resource_identifiers=("acme-logs",),
        summary="Updated S3 public access block settings",
    )


def make_evidence():
    return Evidence(
        kind="pull_request",
        ref="PR #1",
        title="Harden acme-logs",
        url="https://github.com/acme/repo/pull/1",
        actor="harsh",
        time=NOW,
        state="merged",
        text="acme-logs",
    )


class CliTests(unittest.TestCase):
    def run_cli(self, argv, changes, evidence):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("cloud_change_context.cli.fetch_changes", return_value=(changes, [])),
            patch(
                "cloud_change_context.cli.fetch_pull_requests",
                return_value=[evidence] if evidence else [],
            ),
            patch("cloud_change_context.cli.fetch_deployments", return_value=[]),
            patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_report_wiring(self):
        argv = [
            "report",
            "--start",
            "2026-10-31T09:00:00Z",
            "--end",
            "2026-10-31T11:00:00Z",
            "--repo",
            "acme/repo",
            "--format",
            "json",
        ]
        code, output, errors = self.run_cli(argv, [make_change()], make_evidence())
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertFalse(report["approval_granted"])
        self.assertEqual(report["changes"][0]["status"], "matched")
        self.assertNotIn("test-token", output)
        self.assertNotIn("test-token", errors)

    def test_no_repo_is_unmatched(self):
        argv = [
            "report",
            "--start",
            "2026-10-31T09:00:00Z",
            "--end",
            "2026-10-31T11:00:00Z",
            "--format",
            "json",
        ]
        code, output, _ = self.run_cli(argv, [make_change()], None)
        self.assertEqual(code, 0)
        report = json.loads(output)
        self.assertEqual(report["changes"][0]["status"], "unmatched")

    def test_cloudtrail_error_exits_nonzero(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch(
                "cloud_change_context.cli.fetch_changes",
                side_effect=CloudTrailError("no credentials"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(
                [
                    "report",
                    "--start",
                    "2026-10-31T09:00:00Z",
                    "--end",
                    "2026-10-31T11:00:00Z",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("no credentials", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
