import unittest
from datetime import datetime, timedelta, timezone

from cloud_change_context.matching import (
    is_generic_identifier,
    match_changes,
    parse_actor_pairs,
)
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


class GenericNameTests(unittest.TestCase):
    def test_generic_identifiers(self):
        for value in ("app", "dev", "prod-api", "dev-role", "web-sg", "logs", "my"):
            with self.subTest(value=value):
                self.assertTrue(is_generic_identifier(value))

    def test_specific_identifiers(self):
        for value in (
            "acme-logs",
            "payments-deploy",
            "sg-0abc123def",
            "arn:aws:s3:::acme-logs",
            "role/payments-deploy",
            "123456789012",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_generic_identifier(value))

    def test_generic_name_alone_cannot_produce_a_match(self):
        change = make_change(resource_ids=("app",))
        results = match_changes(
            [change], [make_evidence(text="Fix app crash on login")]
        )
        self.assertEqual(results[0].status, "uncertain")
        self.assertIn("generic resource name", results[0].reasons[0])
        self.assertFalse(results[0].evidence[0].resource_match)
        self.assertIn("generic resource name", results[0].evidence[0].signals)

    def test_specific_name_wins_over_a_generic_one(self):
        change = make_change(resource_ids=("app", "acme-logs"))
        results = match_changes([change], [make_evidence(text="app crash; harden acme-logs")])
        self.assertEqual(results[0].status, "matched")

    def test_identifier_must_have_word_boundaries(self):
        change = make_change(resource_ids=("acme-logs",))
        results = match_changes([change], [make_evidence(text="harden acme-logs2")])
        self.assertEqual(results[0].status, "uncertain")


class EvidenceAvailabilityTests(unittest.TestCase):
    def test_not_queried_says_so(self):
        results = match_changes([make_change()], [], evidence_checked=False)
        self.assertEqual(results[0].status, "unmatched")
        self.assertIn("not queried", results[0].reasons[0])
        self.assertNotIn("no PR or deployment within", results[0].reasons[0])

    def test_unavailable_source_is_not_reported_as_confirmed_absence(self):
        results = match_changes(
            [make_change()], [], unavailable_sources=["pull request", "deployment"]
        )
        self.assertEqual(results[0].status, "unmatched")
        self.assertIn("pull request and deployment evidence could not be retrieved", results[0].reasons[0])

    def test_match_carries_a_note_when_a_source_was_unavailable(self):
        results = match_changes(
            [make_change()], [make_evidence()], unavailable_sources=["deployment"]
        )
        self.assertEqual(results[0].status, "matched")
        self.assertEqual(len(results[0].reasons), 2)
        self.assertIn("deployment evidence could not be retrieved", results[0].reasons[1])

    def test_default_reason_is_unchanged(self):
        results = match_changes([make_change()], [])
        self.assertEqual(results[0].reasons, ("no PR or deployment within +/-90 minutes",))


class TimeWindowTests(unittest.TestCase):
    def test_long_deployment_matches_a_change_near_its_end(self):
        evidence = Evidence(
            kind="deployment",
            ref="deployment 5",
            title="main",
            url="",
            actor="harsh",
            time=NOW - timedelta(minutes=120),
            state="success",
            text="deploy acme-logs",
            finished=NOW - timedelta(minutes=5),
        )
        results = match_changes([make_change()], [evidence])
        self.assertEqual(results[0].status, "matched")
        self.assertEqual(results[0].evidence[0].delta_minutes, 5)

    def test_change_during_a_deployment_has_zero_distance(self):
        evidence = Evidence(
            kind="deployment",
            ref="deployment 5",
            title="main",
            url="",
            actor="harsh",
            time=NOW - timedelta(minutes=30),
            state="success",
            text="deploy acme-logs",
            finished=NOW + timedelta(minutes=30),
        )
        results = match_changes([make_change()], [evidence])
        self.assertEqual(results[0].evidence[0].delta_minutes, 0)

    def test_finds_the_one_nearby_item_among_many_far_ones(self):
        far = [
            make_evidence(minutes=1000 + n, text="harden acme-logs", ref=f"PR #{n}")
            for n in range(500)
        ] + [
            make_evidence(minutes=-1000 - n, text="harden acme-logs", ref=f"PR #{n + 500}")
            for n in range(500)
        ]
        near = make_evidence(minutes=7, ref="PR #near")
        results = match_changes([make_change()], far + [near])
        self.assertEqual(results[0].status, "matched")
        self.assertEqual(results[0].evidence[0].evidence.ref, "PR #near")

    def test_ties_keep_input_order(self):
        first = make_evidence(minutes=10, actor="x", text="nothing", ref="PR #1")
        second = make_evidence(minutes=-10, actor="x", text="nothing", ref="PR #2")
        results = match_changes([make_change()], [second, first])
        self.assertEqual(
            [item.evidence.ref for item in results[0].evidence], ["PR #2", "PR #1"]
        )

    def test_window_edges_are_inclusive_for_both_sides(self):
        before = match_changes([make_change()], [make_evidence(minutes=-90)])
        after = match_changes([make_change()], [make_evidence(minutes=90)])
        beyond = match_changes([make_change()], [make_evidence(minutes=-91)])
        self.assertEqual(before[0].status, "matched")
        self.assertEqual(after[0].status, "matched")
        self.assertEqual(beyond[0].status, "unmatched")


if __name__ == "__main__":
    unittest.main()
