from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .models import Evidence

BASE_URL = "https://api.github.com"
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+$")


class GitHubError(Exception):
    """A safe, user-facing GitHub API error. Never includes the token."""


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
) -> list[Evidence]:
    """Fetch merged pull requests near the window. Read-only GET requests."""
    validate_repo(repo)
    earliest = start - timedelta(minutes=tolerance_minutes)
    latest = end + timedelta(minutes=tolerance_minutes)
    found: dict[int, Evidence] = {}

    for page in range(1, max_pages + 1):
        data = _api(
            f"/repos/{repo}/pulls?state=closed&sort=updated&direction=desc"
            f"&per_page=100&page={page}",
            token,
        )
        if not isinstance(data, list) or not data:
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

        if oldest_update and oldest_update < earliest:
            break

    return list(found.values())


def fetch_deployments(
    repo: str,
    token: str | None,
    start: datetime,
    end: datetime,
    tolerance_minutes: int,
    max_pages: int = 5,
) -> list[Evidence]:
    """Fetch deployments near the window plus their latest status and commit message."""
    validate_repo(repo)
    earliest = start - timedelta(minutes=tolerance_minutes)
    latest = end + timedelta(minutes=tolerance_minutes)
    candidates: list[dict[str, Any]] = []
    seen: set[int] = set()

    for page in range(1, max_pages + 1):
        data = _api(f"/repos/{repo}/deployments?per_page=100&page={page}", token)
        if not isinstance(data, list) or not data:
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
                candidates.append(item)

        if oldest_created and oldest_created < earliest:
            break

    detail_limit = 20 if token else 5
    commit_cache: dict[str, str] = {}
    status_enabled = True
    commit_enabled = True
    evidence: list[Evidence] = []

    for index, item in enumerate(candidates):
        deployment_id = item["id"]
        created = _parse_iso(item.get("created_at"))
        if not created:
            continue

        state = "unknown"
        commit_message = ""
        if index < detail_limit and status_enabled:
            try:
                states = _api(f"/repos/{repo}/deployments/{deployment_id}/statuses", token)
                if isinstance(states, list) and states and isinstance(states[0], dict):
                    state = str(states[0].get("state") or "unknown")
            except GitHubError:
                status_enabled = False

        sha = str(item.get("sha") or "")
        if index < detail_limit and commit_enabled and sha:
            if sha not in commit_cache:
                try:
                    commit = _api(f"/repos/{repo}/commits/{quote(sha, safe='')}", token)
                    message = _dict(_dict(commit).get("commit")).get("message")
                    commit_cache[sha] = str(message or "")[:5000]
                except GitHubError:
                    commit_cache[sha] = ""
                    commit_enabled = False
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
            )
        )

    return evidence


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
        "User-Agent": "cloud-change-context/0.1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(f"{BASE_URL}{path}", headers=headers, method="GET")
    try:
        with urlopen(request, timeout=30) as response:
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
            raise GitHubError("GitHub rejected the token (401). Check GITHUB_TOKEN.") from None
        if exc.code == 403 and remaining == "0":
            raise GitHubError(
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
