import io
import re
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.request import Request

from cloud_change_context import github
from cloud_change_context.github import (
    GitHubAuthError,
    GitHubError,
    GitHubRateLimitError,
    fetch_deployments,
    fetch_pull_requests,
    validate_repo,
)

T = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)


def iso(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def pull(number, merged=T, updated=None, merged_at=True):
    return {
        "number": number,
        "title": f"PR {number}",
        "body": "",
        "head": {"ref": "feature"},
        "user": {"login": "octocat"},
        "html_url": f"https://github.com/o/r/pull/{number}",
        "updated_at": iso(updated or merged),
        "merged_at": iso(merged) if merged_at else None,
    }


def deployment(deployment_id, created, sha=None):
    return {
        "id": deployment_id,
        "sha": sha or f"sha{deployment_id}",
        "ref": "main",
        "environment": "prod",
        "creator": {"login": "octocat"},
        "created_at": iso(created),
    }


def page_of(path):
    return int(re.search(r"[?&]page=(\d+)", path).group(1))


class GitHubInputTests(unittest.TestCase):
    def test_valid_repo(self):
        validate_repo("acme/payments-infra")

    def test_rejects_path_injection(self):
        for value in ("acme", "acme/repo/extra", "../repo", "acme/..", "acme/repo?x=1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_repo(value)


class PullRequestFetchTests(unittest.TestCase):
    start = T - timedelta(hours=1)
    end = T + timedelta(hours=1)

    def fetch(self, api, **kwargs):
        notes = []
        with patch("cloud_change_context.github._api", side_effect=api) as mocked:
            found = fetch_pull_requests(
                "o/r", None, self.start, self.end, 30, notes=notes, **kwargs
            )
        return found, notes, mocked

    def test_stops_when_older_than_window_without_warning(self):
        def api(path, token):
            if page_of(path) == 1:
                return [pull(n) for n in range(1, 101)]
            return [pull(900, merged=T - timedelta(hours=5))]

        found, notes, mocked = self.fetch(api)
        self.assertEqual(len(found), 100)
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(notes, [])

    def test_page_cap_is_reported(self):
        def api(path, token):
            base = (page_of(path) - 1) * 100
            return [pull(base + n) for n in range(1, 101)]

        found, notes, mocked = self.fetch(api, max_pages=2)
        self.assertEqual(len(found), 200)
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(len(notes), 1)
        self.assertIn("stopped after 2 pages", notes[0])

    def test_short_page_means_end_of_data(self):
        found, notes, mocked = self.fetch(lambda path, token: [pull(1), pull(2)])
        self.assertEqual(len(found), 2)
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(notes, [])

    def test_unmerged_and_out_of_range_are_ignored(self):
        items = [
            pull(1, merged_at=False),
            pull(2, merged=T + timedelta(hours=3)),
            pull(3),
        ]
        found, _, _ = self.fetch(lambda path, token: items)
        self.assertEqual([item.ref for item in found], ["PR #3"])


class DeploymentFetchTests(unittest.TestCase):
    start = T
    end = T + timedelta(hours=1)

    def fetch(self, routes, **kwargs):
        notes = []
        calls = []

        def api(path, token):
            calls.append(path)
            return routes(path)

        with patch("cloud_change_context.github._api", side_effect=api):
            found = fetch_deployments(
                "o/r", "token", self.start, self.end, 30, notes=notes, **kwargs
            )
        return found, notes, calls

    def test_details_go_to_the_deployments_nearest_the_window(self):
        listing = [
            deployment(3, T + timedelta(minutes=80)),
            deployment(2, T - timedelta(minutes=20)),
            deployment(1, T + timedelta(minutes=30)),
        ]

        def routes(path):
            if "/statuses" in path:
                return [{"state": "success", "created_at": iso(T + timedelta(minutes=31))}]
            if "/commits/" in path:
                return {"commit": {"message": "deploy it"}}
            return listing

        found, notes, calls = self.fetch(routes, detail_limit=1)
        status_calls = [path for path in calls if "/statuses" in path]
        self.assertEqual(status_calls, ["/repos/o/r/deployments/1/statuses"])
        by_ref = {item.ref: item for item in found}
        self.assertEqual(by_ref["deployment 1"].state, "success")
        self.assertEqual(by_ref["deployment 2"].state, "unknown")
        self.assertTrue(any("only 1 of 3" in note for note in notes))

    def test_one_bad_commit_does_not_disable_the_rest(self):
        listing = [
            deployment(1, T + timedelta(minutes=10), sha="aaa"),
            deployment(2, T + timedelta(minutes=20), sha="bbb"),
        ]

        def routes(path):
            if "/statuses" in path:
                return [{"state": "success", "created_at": iso(T + timedelta(minutes=50))}]
            if path.endswith("/commits/aaa"):
                raise GitHubError("GitHub repository not found, or the token cannot read it.")
            if path.endswith("/commits/bbb"):
                return {"commit": {"message": "touch acme-logs"}}
            return listing

        found, notes, _ = self.fetch(routes)
        by_ref = {item.ref: item for item in found}
        self.assertIn("acme-logs", by_ref["deployment 2"].text)
        self.assertTrue(any("commit message for 1 deployment" in note for note in notes))

    def test_rate_limit_stops_detail_lookups_and_is_reported(self):
        listing = [
            deployment(1, T + timedelta(minutes=10)),
            deployment(2, T + timedelta(minutes=20)),
        ]

        def routes(path):
            if "/statuses" in path:
                raise GitHubRateLimitError("GitHub API rate limit exceeded.")
            return listing

        found, notes, calls = self.fetch(routes)
        self.assertEqual(len(found), 2)
        self.assertEqual(len([p for p in calls if "/statuses" in p]), 1)
        self.assertTrue(any("stopped early" in note for note in notes))

    def test_finish_time_comes_from_terminal_status_only(self):
        created = T + timedelta(minutes=10)
        done = T + timedelta(minutes=40)

        def routes_for(state):
            def routes(path):
                if "/statuses" in path:
                    return [{"state": state, "created_at": iso(done)}]
                if "/commits/" in path:
                    return {"commit": {"message": ""}}
                return [deployment(1, created)]

            return routes

        finished, _, _ = self.fetch(routes_for("success"))
        running, _, _ = self.fetch(routes_for("in_progress"))
        self.assertEqual(finished[0].finished, done)
        self.assertIsNone(running[0].finished)

    def test_page_cap_is_reported(self):
        def routes(path):
            base = (page_of(path) - 1) * 100
            if "/statuses" in path or "/commits/" in path:
                return []
            return [deployment(base + n, T + timedelta(minutes=5)) for n in range(1, 101)]

        found, notes, _ = self.fetch(routes, max_pages=1, detail_limit=0)
        self.assertEqual(len(found), 100)
        self.assertTrue(any("stopped after 1 pages" in note for note in notes))


class RedirectTests(unittest.TestCase):
    def redirect(self, newurl, url="https://api.github.com/repos/o/r/pulls"):
        handler = github._SafeRedirectHandler()
        request = Request(url, headers={"Authorization": "Bearer secret", "Accept": "x"})
        return handler.redirect_request(request, io.BytesIO(b""), 301, "Moved", Message(), newurl)

    def test_token_is_kept_on_same_host(self):
        new = self.redirect("https://api.github.com/repositories/1/pulls")
        self.assertEqual(new.get_header("Authorization"), "Bearer secret")

    def test_token_is_dropped_on_another_host(self):
        new = self.redirect("https://example.com/elsewhere")
        self.assertIsNone(new.get_header("Authorization"))
        self.assertEqual(new.get_header("Accept"), "x")

    def test_plain_http_redirect_is_refused(self):
        self.assertIsNone(self.redirect("http://api.github.com/repositories/1/pulls"))


class ApiErrorTests(unittest.TestCase):
    def call_with_error(self, code, body=b"{}", remaining=None):
        headers = Message()
        if remaining is not None:
            headers["X-RateLimit-Remaining"] = remaining
        error = HTTPError("https://api.github.com/x", code, "err", headers, io.BytesIO(body))
        opener = MagicMock()
        opener.open.side_effect = error
        with patch("cloud_change_context.github._OPENER", opener):
            github._api("/x", "s3cr3t-token-value")

    def test_rate_limit_via_header(self):
        with self.assertRaises(GitHubRateLimitError):
            self.call_with_error(403, remaining="0")

    def test_secondary_rate_limit_via_message(self):
        with self.assertRaises(GitHubRateLimitError):
            self.call_with_error(429, b'{"message": "You have exceeded a secondary rate limit"}')

    def test_bad_token(self):
        with self.assertRaises(GitHubAuthError):
            self.call_with_error(401)

    def test_not_found_is_a_plain_error(self):
        with self.assertRaises(GitHubError) as caught:
            self.call_with_error(404)
        self.assertNotIsInstance(caught.exception, (GitHubRateLimitError, GitHubAuthError))
        self.assertNotIn("s3cr3t", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
