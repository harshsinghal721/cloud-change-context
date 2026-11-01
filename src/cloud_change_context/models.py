from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

MatchStatus = Literal["matched", "uncertain", "unmatched"]
EvidenceKind = Literal["pull_request", "deployment"]


@dataclass(frozen=True)
class Change:
    """A normalized CloudTrail event. Raw request bodies are deliberately not kept."""

    event_id: str
    time: datetime
    actor: str
    actor_identifiers: tuple[str, ...]
    event_source: str
    event_name: str
    resource: str
    resource_identifiers: tuple[str, ...]
    summary: str
    account: str | None = None
    region: str | None = None


@dataclass(frozen=True)
class Evidence:
    """A GitHub PR or deployment that happened near a change."""

    kind: EvidenceKind
    ref: str
    title: str
    url: str
    actor: str
    time: datetime
    state: str
    text: str = ""
    detail: str = ""


@dataclass(frozen=True)
class MatchedEvidence:
    evidence: Evidence
    actor_match: bool
    resource_match: bool
    delta_minutes: int

    @property
    def state_ok(self) -> bool:
        if self.evidence.kind == "pull_request":
            return self.evidence.state == "merged"
        return self.evidence.state == "success"

    @property
    def strong(self) -> bool:
        return self.actor_match and self.resource_match and self.state_ok

    @property
    def signals(self) -> tuple[str, ...]:
        signals = []
        if self.actor_match:
            signals.append("actor")
        if self.resource_match:
            signals.append("resource")
        if self.evidence.kind == "deployment":
            signals.append(f"deployment {self.evidence.state or 'unknown'}")
        return tuple(signals)


@dataclass(frozen=True)
class ChangeMatch:
    change: Change
    status: MatchStatus
    reasons: tuple[str, ...]
    evidence: tuple[MatchedEvidence, ...]
    approved: bool = False
