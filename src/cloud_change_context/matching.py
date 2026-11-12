from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from .models import Change, ChangeMatch, Evidence, MatchedEvidence, MatchStatus

# Words that say what something is, not which one it is. A resource whose name is made
# only of these (and very short fragments) appears in countless unrelated PR texts, so
# a hit on it is recorded but never counts as a resource match.
COMMON_NAME_WORDS = frozenset(
    {
        "access", "admin", "administrator", "api", "app", "apps", "assets", "backup",
        "backups", "bucket", "buckets", "build", "common", "data", "default", "demo",
        "deploy", "deployment", "dev", "example", "external", "files", "function",
        "global", "group", "groups", "infra", "infrastructure", "internal", "lambda",
        "log", "logs", "main", "master", "network", "policies", "policy", "private",
        "prod", "production", "public", "qa", "read", "readonly", "role", "roles",
        "root", "sandbox", "security", "service", "services", "shared", "stage",
        "staging", "static", "storage", "temp", "terraform", "test", "testing", "tests",
        "tmp", "uat", "user", "users", "web", "write",
    }
)

_SEGMENT_SPLIT = re.compile(r"[-_.]")


def is_generic_identifier(value: str) -> bool:
    """True when every dash/underscore/dot segment is a short fragment or a common word."""
    segments = [part for part in _SEGMENT_SPLIT.split(value.strip().lower()) if part]
    if not segments:
        return True
    return all(len(part) < 4 or part in COMMON_NAME_WORDS for part in segments)


def parse_actor_pairs(values: Iterable[str]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for value in values:
        left, separator, right = value.partition("=")
        if not separator or not left.strip() or not right.strip():
            raise ValueError("actor map entries must look like github_login=cloudtrail_identity")
        pairs.append((left.strip(), right.strip()))
    return tuple(pairs)


def match_changes(
    changes: Sequence[Change],
    evidence: Sequence[Evidence],
    tolerance_minutes: int = 90,
    actor_pairs: Sequence[tuple[str, str]] = (),
    *,
    evidence_checked: bool = True,
    unavailable_sources: Sequence[str] = (),
) -> list[ChangeMatch]:
    """Correlate every change with nearby GitHub evidence.

    A change is only "matched" when exactly one candidate has actor, resource and
    a successful/merged state. Everything weaker stays "uncertain"; no evidence
    stays "unmatched". Nothing is ever approved.

    ``evidence_checked`` is False when GitHub was never queried, and
    ``unavailable_sources`` names evidence kinds that could not be retrieved. Both only
    change the wording of the reasons, so an absence of evidence is never described as a
    confirmed absence when the tool could not look.
    """
    aliases = tuple(
        (_normalize(left), _normalize(right))
        for left, right in actor_pairs
        if _normalize(left) and _normalize(right)
    )
    unavailable = tuple(unavailable_sources)
    tolerance = timedelta(minutes=tolerance_minutes)

    # Index evidence once: sort by start time so each change only looks at a time window.
    spans = [_span(item) for item in evidence]
    order = sorted(range(len(evidence)), key=lambda index: spans[index][0])
    starts = [spans[index][0] for index in order]
    longest = max((end - start for start, end in spans), default=timedelta(0))
    texts = [item.text.lower() for item in evidence]
    actors = [_normalize(item.actor) for item in evidence]

    results: list[ChangeMatch] = []
    for change in changes:
        change_ids = {
            _normalize(value) for value in change.actor_identifiers if _normalize(value)
        }
        tokens = _resource_tokens(change)

        low = bisect_left(starts, change.time - tolerance - longest)
        high = bisect_right(starts, change.time + tolerance)
        found: list[tuple[int, MatchedEvidence]] = []
        for position in range(low, high):
            index = order[position]
            delta = _distance_minutes(spans[index], change.time)
            if delta > tolerance_minutes:
                continue
            specific, generic = _resource_hit(tokens, texts[index])
            found.append(
                (
                    index,
                    MatchedEvidence(
                        evidence=evidence[index],
                        actor_match=_actor_matches(actors[index], change_ids, aliases),
                        resource_match=specific,
                        delta_minutes=int(round(delta)),
                        resource_generic=generic and not specific,
                    ),
                )
            )

        found.sort(key=lambda pair: (not pair[1].strong, pair[1].delta_minutes, pair[0]))
        candidates = [item for _, item in found]
        strong = [item for item in candidates if item.strong]

        status: MatchStatus
        if len(strong) == 1:
            status = "matched"
            reasons = ["single time/actor/resource match"]
        elif len(strong) > 1:
            status = "uncertain"
            reasons = ["multiple strong matches; ambiguous, manual review required"]
        elif candidates:
            status = "uncertain"
            reasons = [_weak_reason(candidates[0], tolerance_minutes)]
        else:
            status = "unmatched"
            reasons = [
                _unmatched_reason(tolerance_minutes, evidence_checked, unavailable)
            ]
        if status != "unmatched" and unavailable:
            reasons.append(_unavailable_note(unavailable))

        shown = strong if status == "matched" else candidates[:5]
        results.append(
            ChangeMatch(
                change=change,
                status=status,
                reasons=tuple(reasons),
                evidence=tuple(shown),
                approved=False,
            )
        )

    return results


def _unmatched_reason(
    tolerance_minutes: int, evidence_checked: bool, unavailable: Sequence[str]
) -> str:
    if not evidence_checked:
        return (
            "GitHub evidence was not queried (no --repo), so this says nothing "
            "about whether a PR or deployment exists"
        )
    if unavailable:
        return (
            f"no PR or deployment found within +/-{tolerance_minutes} minutes, but "
            f"{_join(unavailable)} evidence could not be retrieved, so absence is not confirmed"
        )
    return f"no PR or deployment within +/-{tolerance_minutes} minutes"


def _unavailable_note(unavailable: Sequence[str]) -> str:
    return f"note: {_join(unavailable)} evidence could not be retrieved; other candidates may exist"


def _join(values: Sequence[str]) -> str:
    return " and ".join(values)


def _weak_reason(candidate: MatchedEvidence, tolerance_minutes: int) -> str:
    if candidate.actor_match and candidate.resource_match and not candidate.state_ok:
        if candidate.evidence.kind == "deployment":
            state = candidate.evidence.state or "unknown"
            if state in ("failure", "error"):
                return (
                    "actor and resource matched, but the deployment did not succeed; "
                    "manual review required"
                )
            return (
                "actor and resource matched, but deployment status is not a confirmed "
                "success; manual review required"
            )
    if candidate.actor_match and candidate.resource_generic:
        return (
            "actor matched, but only a generic resource name appeared in the evidence; "
            "not enough to confirm the resource"
        )
    if candidate.actor_match and not candidate.resource_match:
        return "actor matched, but the resource was not found in GitHub evidence"
    if candidate.resource_match and not candidate.actor_match:
        return "resource matched, but the actor did not match"
    return (
        f"time-proximate evidence only (within +/-{tolerance_minutes} minutes); "
        "actor and resource were not matched"
    )


def _span(item: Evidence) -> tuple[datetime, datetime]:
    start = item.time
    end = item.finished if item.finished and item.finished > start else start
    return start, end


def _distance_minutes(span: tuple[datetime, datetime], when: datetime) -> float:
    start, end = span
    if start <= when <= end:
        return 0.0
    return min(abs((when - start).total_seconds()), abs((when - end).total_seconds())) / 60


def _actor_matches(
    normalized: str,
    identifiers: set[str],
    aliases: Sequence[tuple[str, str]],
) -> bool:
    if not normalized:
        return False
    if normalized in identifiers:
        return True
    for left, right in aliases:
        if (normalized == left and right in identifiers) or (
            normalized == right and left in identifiers
        ):
            return True
    return False


def _resource_tokens(change: Change) -> tuple[str, ...]:
    tokens: list[str] = []
    seen: set[str] = set()
    for value in change.resource_identifiers:
        token = value.strip().lower()
        if len(token) < 3 or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tuple(tokens)


def _resource_hit(tokens: Sequence[str], text_lower: str) -> tuple[bool, bool]:
    """Return (specific hit, generic-only hit) for already-lowercased text."""
    generic = False
    for token in tokens:
        if token not in text_lower or not _contains_bounded(token, text_lower):
            continue
        if is_generic_identifier(token):
            generic = True
        else:
            return True, generic
    return False, generic


def _resource_matches(change: Change, text: str) -> bool:
    return _resource_hit(_resource_tokens(change), text.lower())[0]


_BOUNDARY = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")


def _contains_bounded(token: str, text: str) -> bool:
    """Substring search where neither neighbour may be [a-z0-9]."""
    start = 0
    width = len(token)
    while True:
        index = text.find(token, start)
        if index < 0:
            return False
        before = text[index - 1] if index > 0 else ""
        after = text[index + width] if index + width < len(text) else ""
        if before not in _BOUNDARY and after not in _BOUNDARY:
            return True
        start = index + 1


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
