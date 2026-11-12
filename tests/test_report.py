import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from cloud_change_context.models import Change, ChangeMatch, Evidence, MatchedEvidence
from cloud_change_context.report import ReportMeta, render

NOW = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)
META = ReportMeta(
    start=NOW,
    end=NOW,
    generated_at=NOW,
    region="us-east-1",
    repo="acme/repo",
    tolerance_minutes=90,
    warnings=(),
)


def make_match(status="matched"):
    change = Change(
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
    evidence = Evidence(
        kind="pull_request",
        ref="PR #1",
        title="Harden | bucket\x1b[31m",
        url="https://github.com/acme/repo/pull/1",
        actor="harsh",
        time=NOW,
        state="merged",
        text="acme-logs",
    )
    matched = MatchedEvidence(
        evidence=evidence,
        actor_match=True,
        resource_match=True,
        delta_minutes=0,
    )
    return ChangeMatch(
        change=change,
        status=status,
        reasons=("single time/actor/resource match",),
        evidence=(matched,) if status != "unmatched" else (),
    )


class ReportTests(unittest.TestCase):
    def test_markdown_contains_fields_and_escapes(self):
        output = render([make_match()], META, "markdown")
        self.assertIn("arn:aws:s3:::acme-logs", output)
        self.assertIn("Updated S3 public access block settings", output)
        self.assertIn("https://github.com/acme/repo/pull/1", output)
        self.assertIn("Harden \\| bucket", output)
        self.assertNotIn("\x1b", output)
        self.assertIn("Approval granted: **no**", output)

    def test_json_never_approves(self):
        output = json.loads(render([make_match()], META, "json"))
        self.assertFalse(output["approval_granted"])
        self.assertFalse(output["changes"][0]["approved"])
        self.assertEqual(output["changes"][0]["status"], "matched")

    def test_unmatched_has_no_evidence(self):
        output = json.loads(render([make_match("unmatched")], META, "json"))
        self.assertEqual(output["changes"][0]["status"], "unmatched")
        self.assertEqual(output["changes"][0]["evidence"], [])

    def test_text_report(self):
        output = render([make_match()], META, "text")
        self.assertIn("[MATCHED]", output)
        self.assertIn("Evidence:", output)
        self.assertIn("Approval granted: no", output)

    def test_text_report_strips_control_characters_from_every_field(self):
        match = make_match()
        change = replace(match.change, event_id="id\x1b[31m-1")
        item = match.evidence[0]
        evidence = replace(item.evidence, url="https://github.com/acme/repo/pull/1\x07")
        match = replace(match, change=change, evidence=(replace(item, evidence=evidence),))
        output = render([match], META, "text")
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\x07", output)
        self.assertIn("(id [31m-1)", output)


if __name__ == "__main__":
    unittest.main()
