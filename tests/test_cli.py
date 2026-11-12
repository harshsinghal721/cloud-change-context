import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from unittest.mock import patch

from cloud_change_context.cli import main
from cloud_change_context.cloudtrail import CloudTrailError
from cloud_change_context.github import GitHubError
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


WINDOW = ["--start", "2026-10-31T09:00:00Z", "--end", "2026-10-31T11:00:00Z", "--format", "json"]


class CliBehaviourTests(unittest.TestCase):
    def run_cli(self, argv, *, changes=None, pulls=None, deployments=None, env=None):
        """Run main() with fetchers mocked; ``pulls``/``deployments`` may be callables or errors."""
        stdout, stderr = io.StringIO(), io.StringIO()
        changes_mock = patch(
            "cloud_change_context.cli.fetch_changes",
            return_value=(changes if changes is not None else [make_change()], []),
        )
        pulls_mock = patch(
            "cloud_change_context.cli.fetch_pull_requests",
            **_behaviour(pulls),
        )
        deployments_mock = patch(
            "cloud_change_context.cli.fetch_deployments",
            **_behaviour(deployments),
        )
        with (
            changes_mock as fetch_changes,
            pulls_mock as fetch_pulls,
            deployments_mock as fetch_deploys,
            patch.dict(os.environ, env or {"GITHUB_TOKEN": "test-token"}),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), fetch_changes, fetch_pulls, fetch_deploys

    def test_no_repo_reason_says_github_was_not_queried(self):
        _, output, _, *_ = self.run_cli(["report", *WINDOW])
        reasons = json.loads(output)["changes"][0]["reasons"]
        self.assertIn("not queried", reasons[0])

    def test_github_failure_is_not_reported_as_confirmed_absence(self):
        _, output, errors, *_ = self.run_cli(
            ["report", "--repo", "acme/repo", *WINDOW],
            pulls=GitHubError("boom"),
            deployments=GitHubError("down"),
        )
        report = json.loads(output)
        self.assertEqual(report["changes"][0]["status"], "unmatched")
        self.assertIn("could not be retrieved", report["changes"][0]["reasons"][0])
        self.assertTrue(any("Pull request evidence unavailable" in w for w in report["warnings"]))
        self.assertIn("Deployment evidence unavailable", errors)

    def test_one_failed_source_is_named(self):
        _, output, *_ = self.run_cli(
            ["report", "--repo", "acme/repo", *WINDOW],
            pulls=[],
            deployments=GitHubError("down"),
        )
        reason = json.loads(output)["changes"][0]["reasons"][0]
        self.assertIn("deployment evidence could not be retrieved", reason)
        self.assertNotIn("pull request", reason)

    def test_fetcher_notes_reach_the_report_warnings(self):
        def pulls(*args, notes=None, **kwargs):
            notes.append("PR listing stopped after 5 pages")
            return []

        _, output, errors, *_ = self.run_cli(
            ["report", "--repo", "acme/repo", *WINDOW], pulls=pulls
        )
        self.assertIn("PR listing stopped after 5 pages", json.loads(output)["warnings"])
        self.assertIn("PR listing stopped", errors)

    def test_repeated_region_flag_reads_every_region(self):
        _, output, _, fetch_changes, *_ = self.run_cli(
            ["report", "--region", "eu-west-1", "--region", "us-west-2", *WINDOW]
        )
        self.assertEqual(fetch_changes.call_args.kwargs["region"], ["eu-west-1", "us-west-2"])
        self.assertEqual(json.loads(output)["region"], "eu-west-1, us-west-2")

    def test_region_defaults_to_environment(self):
        _, _, _, fetch_changes, *_ = self.run_cli(
            ["report", *WINDOW], env={"AWS_REGION": "ap-south-1"}
        )
        self.assertEqual(fetch_changes.call_args.kwargs["region"], ["ap-south-1"])

    def test_deployment_detail_limit_is_passed_through(self):
        *_, fetch_deploys = self.run_cli(
            ["report", "--repo", "acme/repo", "--max-deployment-details", "7", *WINDOW]
        )
        self.assertEqual(fetch_deploys.call_args.kwargs["detail_limit"], 7)

    def test_negative_detail_limit_is_rejected(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(["report", "--max-deployment-details", "-1", *WINDOW])
        self.assertEqual(caught.exception.code, 2)


def _behaviour(value):
    """Turn a test value into patch() keyword arguments."""
    if value is None:
        return {"return_value": []}
    if isinstance(value, Exception):
        return {"side_effect": value}
    if callable(value):
        return {"side_effect": value}
    return {"return_value": value}


if __name__ == "__main__":
    unittest.main()
