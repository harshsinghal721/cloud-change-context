from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .models import Evidence

BASE_URL = "https://api.github.com"
PAGE_SIZE = 100
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+$")
_TERMINAL_STATES = frozenset({"success", "failure", "error", "inactive"})


class GitHubError(Exception):
    """A safe, user-facing GitHub API error. Never includes the token."""


class GitHubRateLimitError(GitHubError):
    """The GitHub API rate limit was hit; further calls would fail the same way."""


class GitHubAuthError(GitHubError):
    """GitHub rejected the token; further calls would fail the same way."""


class _SafeRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only over HTTPS and never send the token to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlparse(newurl)
        if target.scheme != "https":
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and target.hostname != urlparse(req.full_url).hostname:
            for store in (new.headers, new.unredirected_hdrs):
                for name in [key for key in store if key.lower() == "authorization"]:
                    del store[name]
        return new


_OPENER = build_opener(_SafeRedirectHandler)


def validate_repo(repo: str) -> None:
    parts = repo.split("/")
    if (
        len(parts) != 2
        or not _REPO_PATTERN.match(repo)
        or any(part in (".", "..") for part in parts)
    ):
        raise ValueError("--repo must look like owner/name")


def fetch_pull_requests(
    repo: str,
    token: str | None,
    start: datetime,
    end: datetime,
    tolerance_minutes: int,
    max_pages: int = 5,
    notes: list[str] | None = None,
) -> list[Evidence]:
    """Fetch merged pull requests near the window. Read-only GET requests.

    Anything that makes the result incomplete is appended to ``notes`` (if given) so the
    caller can surface it; the return value stays a plain list.
    """
    validate_repo(repo)
    notes = notes if notes is not None else []
    earliest = start - timedelta(minutes=tolerance_minutes)
    latest = end + timedelta(minutes=tolerance_minutes)
    found: dict[int, Evidence] = {}
    exhausted = True

    for page in range(1, max_pages + 1):
        data = _api(
            f"/repos/{repo}/pulls?state=closed&sort=updated&direction=desc"
            f"&per_page={PAGE_SIZE}&page={page}",
            token,
        )
        if not isinstance(data, list) or not data:
            exhausted = False
            break

        oldest_update: datetime | None = None
        for item in data:
            if not isinstance(item, dict):
                continue
            updated = _parse_iso(item.get("updated_at"))
            if updated and (oldest_update is None or updated < oldest_update):
                oldest_update = updated

            merged = _parse_iso(item.get("merged_at"))
            number = item.get("number")
            if merged and earliest <= merged <= latest and isinstance(number, int):
                found.setdefault(number, _pull_request_evidence(item, merged))

        if (oldest_update and oldest_update < earliest) or len(data) < PAGE_SIZE:
            exhausted = False
            break

    if exhausted:
        notes.append(
            f"Pull request listing stopped after {max_pages} pages "
            f"({max_pages * PAGE_SIZE} items); older merged PRs in the window may be "
            "missing. Use a narrower window."
        )
    return list(found.values())


def fetch_deployments(
    repo: str,
    token: str | None,
    start: datetime,
    end: datetime,
    tolerance_minutes: int,
    max_pages: int = 5,
    detail_limit: int | None = None,
    notes: list[str] | None = None,
) -> list[Evidence]:
    """Fetch deployments near the window plus their latest status and commit message.

    Status and commit details cost extra requests, so only ``detail_limit`` deployments
    (those closest to the window first) get them; the rest keep an ``unknown`` state and
    can only ever be "uncertain". Every shortfall is appended to ``notes``.
    """
    validate_repo(repo)
    notes = notes if notes is not None else []
    earliest = start - timedelta(minutes=tolerance_minutes)
    latest = end + timedelta(minutes=tolerance_minutes)
    candidates: list[tuple[datetime, dict[str, Any]]] = []
    seen: set[int] = set()
    exhausted = True

    for page in range(1, max_pages + 1):
        data = _api(
            f"/repos/{repo}/deployments?per_page={PAGE_SIZE}&page={page}", token
        )
        if not isinstance(data, list) or not data:
            exhausted = False
            break

        oldest_created: datetime | None = None
        for item in data:
            if not isinstance(item, dict):
                continue
            created = _parse_iso(item.get("created_at"))
            if created and (oldest_created is None or created < oldest_created):
                oldest_created = created

            deployment_id = item.get("id")
            if (
                created
                and earliest <= created <= latest
                and isinstance(deployment_id, int)
                and deployment_id not in seen
            ):
                seen.add(deployment_id)
                candidates.append((created, item))

        if (oldest_created and oldest_created < earliest) or len(data) < PAGE_SIZE:
            exhausted = False
            break

    if exhausted:
        notes.append(
            f"Deployment listing stopped after {max_pages} pages "
            f"({max_pages * PAGE_SIZE} items); older deployments in the window may be "
            "missing. Use a narrower window."
        )

    # Spend the limited detail requests on the deployments closest to the window.
    candidates.sort(key=lambda pair: _outside_window(pair[0], start, end))
    limit = detail_limit if detail_limit is not None else (20 if token else 5)

    commit_cache: dict[str, str] = {}
    blocked = False
    status_failures = 0
    commit_failures = 0
    evidence: list[Evidence] = []

    for index, (created, item) in enumerate(candidates):
        deployment_id = item["id"]
        in_detail_range = index < limit

        state = "unknown"
        finished: datetime | None = None
        if in_detail_range and not blocked:
            try:
                states = _api(f"/repos/{repo}/deployments/{deployment_id}/statuses", token)
                if isinstance(states, list) and states and isinstance(states[0], dict):
                    latest_status = states[0]
                    state = str(latest_status.get("state") or "unknown")
                    if state in _TERMINAL_STATES:
                        done = _parse_iso(latest_status.get("created_at"))
                        if done and done > created:
                            finished = done
            except (GitHubRateLimitError, GitHubAuthError) as exc:
                blocked = True
                notes.append(f"Deployment details stopped early: {exc}")
            except GitHubError:
                status_failures += 1

        commit_message = ""
        sha = str(item.get("sha") or "")
        if in_detail_range and not blocked and sha:
            if sha not in commit_cache:
                try:
                    commit = _api(f"/repos/{repo}/commits/{quote(sha, safe='')}", token)
                    message = _dict(_dict(commit).get("commit")).get("message")
                    commit_cache[sha] = str(message or "")[:5000]
                except (GitHubRateLimitError, GitHubAuthError) as exc:
                    blocked = True
                    commit_cache[sha] = ""
                    notes.append(f"Deployment details stopped early: {exc}")
                except GitHubError:
                    commit_cache[sha] = ""
                    commit_failures += 1
            commit_message = commit_cache[sha]

        ref = str(item.get("ref") or "")
        environment = str(item.get("environment") or "")
        payload = _dict(item.get("payload"))
        description = str(item.get("description") or payload.get("description") or "")
        creator = _dict(item.get("creator"))
        text = " ".join(
            part for part in (ref, description, commit_message) if part
        )[:20000]

        evidence.append(
            Evidence(
                kind="deployment",
                ref=f"deployment {deployment_id}",
                title=ref or f"deployment {deployment_id}",
                url=f"https://github.com/{repo}/deployments/{deployment_id}",
                actor=str(creator.get("login") or ""),
                time=created,
                state=state,
                text=text,
                detail=environment or "unknown environment",
                finished=finished,
            )
        )

    skipped = len(candidates) - limit
    if skipped > 0 and not blocked:
        hint = "" if token else " Set GITHUB_TOKEN to raise the limit."
        notes.append(
            f"Status and commit message were read for only {limit} of {len(candidates)} "
            f"deployments; the other {skipped} have an unknown status and can only be "
            f"'uncertain'.{hint}"
        )
    if status_failures:
        notes.append(
            f"Could not read the status of {status_failures} deployment(s); "
            "they stay 'unknown'."
        )
    if commit_failures:
        notes.append(
            f"Could not read the commit message for {commit_failures} deployment(s)."
        )
    return evidence


def _outside_window(when: datetime, start: datetime, end: datetime) -> float:
    if when < start:
        return (start - when).total_seconds()
    if when > end:
        return (when - end).total_seconds()
    return 0.0


def _pull_request_evidence(item: dict[str, Any], merged: datetime) -> Evidence:
    number = item.get("number")
    head = _dict(item.get("head"))
    user = _dict(item.get("user"))
    title = str(item.get("title") or f"PR #{number}")
    body = str(item.get("body") or "")
    head_ref = str(head.get("ref") or "")
    text = " ".join(part for part in (title, body, head_ref) if part)[:20000]
    return Evidence(
        kind="pull_request",
        ref=f"PR #{number}",
        title=title,
        url=str(item.get("html_url") or ""),
        actor=str(user.get("login") or ""),
        time=merged,
        state="merged",
        text=text,
        detail=f"merged {_iso(merged)}",
    )


def _api(path: str, token: str | None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"cloud-change-context/{__version__}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(f"{BASE_URL}{path}", headers=headers, method="GET")
    try:
        with _OPENER.open(request, timeout=30) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        message = ""
        try:
            payload = json.loads(exc.read().decode("utf-8", "replace"))
            if isinstance(payload, dict):
                message = str(payload.get("message") or "")
        except (ValueError, OSError):
            pass
        remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
        if exc.code == 401:
            raise GitHubAuthError(
                "GitHub rejected the token (401). Check GITHUB_TOKEN."
            ) from None
        if exc.code in (403, 429) and (
            remaining == "0" or "rate limit" in message.lower()
        ):
            raise GitHubRateLimitError(
                "GitHub API rate limit exceeded. Set GITHUB_TOKEN or wait for the limit to reset."
            ) from None
        if exc.code == 404:
            raise GitHubError(
                "GitHub repository not found, or the token cannot read it."
            ) from None
        suffix = f": {message}" if message else ""
        raise GitHubError(f"GitHub API error {exc.code}{suffix}") from None
    except URLError as exc:
        raise GitHubError(f"GitHub API unreachable: {exc.reason}") from None
    except TimeoutError:
        raise GitHubError("GitHub API request timed out.") from None

    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise GitHubError("GitHub returned an invalid JSON response.") from None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
