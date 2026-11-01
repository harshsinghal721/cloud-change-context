import unittest
from datetime import datetime, timedelta, timezone

from cloud_change_context.matching import match_changes, parse_actor_pairs
from cloud_change_context.models import Change, Evidence

NOW = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)


def make_change(actor="harsh", actor_ids=None, resource_ids=None):
    ids = resource_ids or ("acme-logs", "arn:aws:s3:::acme-logs")
    return Change(
        event_id="event-1",
        time=NOW,
        actor=actor,
        actor_identifiers=tuple(actor_ids or ("harsh",)),
        event_source="s3.amazonaws.com",
        event_name="PutBucketPublicAccessBlock",
        resource="arn:aws:s3:::acme-logs",
        resource_identifiers=tuple(ids),
        summary="Updated S3 public access block settings",
    )


def make_evidence(
    minutes=10,
    actor="harsh",
    text="harden acme-logs",
    kind="pull_request",
    state="merged",
    ref="PR #1",
):
    return Evidence(
        kind=kind,
        ref=ref,
        title="Harden bucket",
        url="https://github.com/acme/repo/pull/1",
        actor=actor,
        time=NOW + timedelta(minutes=minutes),
        state=state,
        text=text,
    )


class MatchingTests(unittest.TestCase):
    def test_single_strong_match(self):
        results = match_changes([make_change()], [make_evidence()])
        self.assertEqual(results[0].status, "matched")
        self.assertFalse(results[0].approved)
        self.assertTrue(results[0].evidence[0].strong)

    def test_time_only_is_uncertain(self):
        results = match_changes(
            [make_change()],
            [make_evidence(actor="someone-else", text="unrelated change")],
        )
        self.assertEqual(results[0].status, "uncertain")
        self.assertIn("time-proximate", results[0].reasons[0])

    def test_no_evidence_is_unmatched(self):
        results = match_changes([make_change()], [])
        self.assertEqual(results[0].status, "unmatched")
        self.assertEqual(results[0].evidence, ())
        self.assertFalse(results[0].approved)

    def test_multiple_strong_matches_are_ambiguous(self):
        results = match_changes(
            [make_change()],
            [make_evidence(minutes=5), make_evidence(minutes=20, ref="PR #2")],
        )
        self.assertEqual(results[0].status, "uncertain")
        self.assertIn("multiple strong", results[0].reasons[0])

    def test_failed_deployment_is_not_matched(self):
        results = match_changes(
            [make_change()],
            [
                make_evidence(
                    kind="deployment",
                    state="failure",
                    ref="deployment 7",
                )
            ],
        )
        self.assertEqual(results[0].status, "uncertain")
        self.assertIn("did not succeed", results[0].reasons[0])
        self.assertEqual(results[0].evidence[0].signals, ("actor", "resource", "deployment failure"))

    def test_unknown_deployment_status_is_not_matched(self):
        results = match_changes(
            [make_change()],
            [
                make_evidence(
                    kind="deployment",
                    state="unknown",
                    ref="deployment 8",
                )
            ],
        )
        self.assertEqual(results[0].status, "uncertain")
        self.assertIn("not a confirmed success", results[0].reasons[0])

    def test_successful_deployment_matches(self):
        results = match_changes(
            [make_change()],
            [
                make_evidence(
                    kind="deployment",
                    state="success",
                    ref="deployment 9",
                )
            ],
        )
        self.assertEqual(results[0].status, "matched")

    def test_actor_alias(self):
        change = make_change(actor="GitHubActionsRole", actor_ids=("GitHubActionsRole",))
        results = match_changes(
            [change],
            [make_evidence(actor="octocat")],
            actor_pairs=parse_actor_pairs(["octocat=GitHubActionsRole"]),
        )
        self.assertEqual(results[0].status, "matched")

    def test_tolerance_boundary(self):
        inside = match_changes([make_change()], [make_evidence(minutes=90)])
        outside = match_changes([make_change()], [make_evidence(minutes=91)])
        self.assertEqual(inside[0].status, "matched")
        self.assertEqual(outside[0].status, "unmatched")

    def test_invalid_actor_map(self):
        with self.assertRaises(ValueError):
            parse_actor_pairs(["missing-equals"])


if __name__ == "__main__":
    unittest.main()
