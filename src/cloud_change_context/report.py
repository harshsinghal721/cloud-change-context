from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__
from .models import ChangeMatch, MatchedEvidence


@dataclass(frozen=True)
class ReportMeta:
    start: datetime
    end: datetime
    generated_at: datetime
    region: str
    repo: str | None
    tolerance_minutes: int
    warnings: tuple[str, ...]


def render(matches: list[ChangeMatch], meta: ReportMeta, fmt: str = "text") -> str:
    if fmt == "json":
        return _render_json(matches, meta)
    if fmt == "markdown":
        return _render_markdown(matches, meta)
    return _render_text(matches, meta)


def _render_text(matches: list[ChangeMatch], meta: ReportMeta) -> str:
    lines = [
        f"Cloud Change Context {__version__} - AWS change report",
        f"Generated: {_iso(meta.generated_at)}",
        f"Window:    {_iso(meta.start)} -> {_iso(meta.end)} (UTC)",
        f"Region:    {clean_text(meta.region)}",
        f"Repo:      {clean_text(meta.repo or 'not configured')}",
        f"Tolerance: +/-{meta.tolerance_minutes} minutes",
        "",
        'IMPORTANT: "matched" means matching evidence was found. It is not approval.',
        "This tool never approves, modifies, or remediates cloud resources.",
        "",
    ]

    if not matches:
        lines.append("No tracked AWS changes found in this window.")
    for index, match in enumerate(matches, start=1):
        change = match.change
        lines.append(
            f"{index}. [{match.status.upper()}] {_iso(change.time)}  {clean_text(change.resource)}"
        )
        lines.append(f"   Change: {clean_text(change.summary)}")
        lines.append(f"   Actor:  {clean_text(change.actor)}")
        lines.append(
            f"   Event:  {change.event_name} ({change.event_id})"
        )
        lines.append(f"   Match:  {clean_text('; '.join(match.reasons))}")
        if match.evidence:
            lines.append("   Evidence:")
            for item in match.evidence:
                lines.append(f"     - {_evidence_text(item)}")
        else:
            lines.append("   Evidence: none")
        lines.append("")

    if meta.warnings:
        lines.append("Warnings:")
        lines.extend(f" - {clean_text(warning)}" for warning in meta.warnings)
        lines.append("")

    counts = _counts(matches)
    lines.append(
        f"Summary: {len(matches)} change(s) - matched: {counts['matched']}, "
        f"uncertain: {counts['uncertain']}, unmatched: {counts['unmatched']}"
    )
    lines.append("Approval granted: no (read-only tool)")
    return "\n".join(lines) + "\n"


def _render_markdown(matches: list[ChangeMatch], meta: ReportMeta) -> str:
    lines = [
        "# Cloud Change Context - AWS change report",
        "",
        f"- **Generated:** {_iso(meta.generated_at)}",
        f"- **Window:** {_iso(meta.start)} -> {_iso(meta.end)} (UTC)",
        f"- **Region:** {clean_text(meta.region)}",
        f"- **Repo:** {clean_text(meta.repo or 'not configured')}",
        f"- **Tolerance:** +/-{meta.tolerance_minutes} minutes",
        "",
        "> **matched** means matching evidence was found. It is not approval.",
        "> This tool never approves, modifies, or remediates cloud resources.",
        "",
    ]

    if meta.warnings:
        lines.append("## Warnings")
        lines.append("")
        lines.extend(f"- {_md(warning)}" for warning in meta.warnings)
        lines.append("")

    lines.extend(
        [
            "## Changes",
            "",
            "| Time (UTC) | Resource | Change | Actor | Match | Evidence |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    if not matches:
        lines.append("| - | - | No tracked AWS changes found | - | - | - |")
    for match in matches:
        change = match.change
        evidence = "<br>".join(_evidence_md(item) for item in match.evidence)
        lines.append(
            "| "
            + " | ".join(
                [
                    _iso(change.time),
                    _md(change.resource),
                    _md(change.summary),
                    _md(change.actor),
                    f"**{match.status}**<br>{_md('; '.join(match.reasons))}",
                    evidence or "none",
                ]
            )
            + " |"
        )

    counts = _counts(matches)
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total: {len(matches)}",
            f"- Matched: {counts['matched']}",
            f"- Uncertain: {counts['uncertain']}",
            f"- Unmatched: {counts['unmatched']}",
            "- Approval granted: **no** (read-only tool)",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_json(matches: list[ChangeMatch], meta: ReportMeta) -> str:
    counts = _counts(matches)
    payload = {
        "tool": {"name": "cloud-change-context", "version": __version__},
        "generated_at": _iso(meta.generated_at),
        "window": {
            "start": _iso(meta.start),
            "end": _iso(meta.end),
        },
        "region": meta.region,
        "repo": meta.repo,
        "tolerance_minutes": meta.tolerance_minutes,
        "warnings": [clean_text(warning) for warning in meta.warnings],
        "approval_granted": False,
        "summary": {**counts, "total": len(matches)},
        "changes": [
            {
                "event_id": match.change.event_id,
                "time": _iso(match.change.time),
                "resource": match.change.resource,
                "change": match.change.summary,
                "actor": match.change.actor,
                "event_source": match.change.event_source,
                "event_name": match.change.event_name,
                "account": match.change.account,
                "region": match.change.region,
                "status": match.status,
                "approved": False,
                "reasons": list(match.reasons),
                "evidence": [
                    {
                        "kind": item.evidence.kind,
                        "ref": item.evidence.ref,
                        "title": item.evidence.title,
                        "url": item.evidence.url,
                        "actor": item.evidence.actor,
                        "time": _iso(item.evidence.time),
                        "state": item.evidence.state,
                        "detail": item.evidence.detail,
                        "actor_match": item.actor_match,
                        "resource_match": item.resource_match,
                        "delta_minutes": item.delta_minutes,
                        "signals": list(item.signals),
                    }
                    for item in match.evidence
                ],
            }
            for match in matches
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _evidence_text(item: MatchedEvidence) -> str:
    evidence = item.evidence
    title = f' "{clean_text(evidence.title)}"' if evidence.title and evidence.title != evidence.ref else ""
    details = list(item.signals)
    if evidence.kind == "pull_request":
        details.append("merged")
    if not details:
        details.append("time only")
    if evidence.kind == "deployment" and evidence.detail:
        details.append(clean_text(evidence.detail))
    label = f"{evidence.ref}{title} ({', '.join(details)}; {item.delta_minutes} min)"
    return f"{label} -> {evidence.url}" if evidence.url else label


def _evidence_md(item: MatchedEvidence) -> str:
    evidence = item.evidence
    label = _md(evidence.ref)
    if evidence.title and evidence.title != evidence.ref:
        label += f" - {_md(evidence.title)}"
    link = f"[{label}]({evidence.url})" if evidence.url else label
    details = list(item.signals)
    if evidence.kind == "pull_request":
        details.append("merged")
    if not details:
        details.append("time only")
    suffix = f", {item.delta_minutes} min"
    return f"{link} ({', '.join(details)}{suffix})"


def _counts(matches: list[ChangeMatch]) -> dict[str, int]:
    counts = {"matched": 0, "uncertain": 0, "unmatched": 0}
    for match in matches:
        counts[match.status] += 1
    return counts


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def clean_text(value: object) -> str:
    return " ".join(_CONTROL_CHARS.sub(" ", str(value)).split())


def _md(value: object) -> str:
    return (
        clean_text(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

