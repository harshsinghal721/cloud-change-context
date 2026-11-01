from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from .models import Change, ChangeMatch, Evidence, MatchedEvidence


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
) -> list[ChangeMatch]:
    """Correlate every change with nearby GitHub evidence.

    A change is only "matched" when exactly one candidate has actor, resource and
    a successful/merged state. Everything weaker stays "uncertain"; no evidence
    stays "unmatched". Nothing is ever approved.
    """
    aliases = tuple(
        (_normalize(left), _normalize(right))
        for left, right in actor_pairs
        if _normalize(left) and _normalize(right)
    )

    results: list[ChangeMatch] = []
    for change in changes:
        candidates: list[MatchedEvidence] = []
        for item in evidence:
            delta = abs((item.time - change.time).total_seconds()) / 60
            if delta <= tolerance_minutes:
                candidates.append(
                    MatchedEvidence(
                        evidence=item,
                        actor_match=_actor_matches(item.actor, change, aliases),
                        resource_match=_resource_matches(change, item.text),
                        delta_minutes=int(round(delta)),
                    )
                )

        candidates.sort(key=lambda item: (not item.strong, item.delta_minutes))
        strong = [item for item in candidates if item.strong]

        if len(strong) == 1:
            status = "matched"
            reasons = ("single time/actor/resource match",)
        elif len(strong) > 1:
            status = "uncertain"
            reasons = ("multiple strong matches; ambiguous, manual review required",)
        elif candidates:
            status = "uncertain"
            reasons = (_weak_reason(candidates[0], tolerance_minutes),)
        else:
            status = "unmatched"
            reasons = (f"no PR or deployment within +/-{tolerance_minutes} minutes",)

        shown = strong if status == "matched" else candidates[:5]
        results.append(
            ChangeMatch(
                change=change,
                status=status,
                reasons=reasons,
                evidence=tuple(shown),
                approved=False,
            )
        )

    return results


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
    if candidate.actor_match and not candidate.resource_match:
        return "actor matched, but the resource was not found in GitHub evidence"
    if candidate.resource_match and not candidate.actor_match:
        return "resource matched, but the actor did not match"
    return (
        f"time-proximate evidence only (within +/-{tolerance_minutes} minutes); "
        "actor and resource were not matched"
    )


def _actor_matches(
    actor: str,
    change: Change,
    aliases: Sequence[tuple[str, str]],
) -> bool:
    normalized = _normalize(actor)
    if not normalized:
        return False
    identifiers = {
        _normalize(value) for value in change.actor_identifiers if _normalize(value)
    }
    if normalized in identifiers:
        return True
    for left, right in aliases:
        if (normalized == left and right in identifiers) or (
            normalized == right and left in identifiers
        ):
            return True
    return False


def _resource_matches(change: Change, text: str) -> bool:
    haystack = text.lower()
    for value in change.resource_identifiers:
        token = value.strip().lower()
        if len(token) < 3:
            continue
        pattern = rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])"
        if re.search(pattern, haystack):
            return True
    return False


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
