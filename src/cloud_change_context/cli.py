from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

from . import __version__
from .cloudtrail import CloudTrailError, fetch_changes
from .github import (
    GitHubError,
    fetch_deployments,
    fetch_pull_requests,
    validate_repo,
)
from .matching import match_changes, parse_actor_pairs
from .report import ReportMeta, clean_text, render

MAX_CLOUDTRAIL_RANGE = timedelta(days=90)


def build_parser() -> argparse.ArgumentParser:
    default_region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    parser = argparse.ArgumentParser(
        prog="ccx",
        description=(
            "Correlate AWS security-sensitive CloudTrail changes with GitHub "
            "pull requests and deployments. Read-only."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    report = subparsers.add_parser(
        "report", help="build a change-to-evidence report"
    )
    report.add_argument(
        "--start",
        type=_parse_datetime,
        help="ISO 8601 start time (default: 24 hours before --end)",
    )
    report.add_argument(
        "--end",
        type=_parse_datetime,
        help="ISO 8601 end time (default: now)",
    )
    report.add_argument(
        "--region",
        action="append",
        default=None,
        metavar="REGION",
        help=(
            "AWS region for S3/EC2 events; repeat to read several regions "
            f"(default: {default_region})"
        ),
    )
    report.add_argument(
        "--profile", help="AWS profile name from the standard credential chain"
    )
    report.add_argument("--repo", help="GitHub repository as owner/name")
    report.add_argument(
        "--tolerance-minutes",
        type=int,
        default=90,
        help="maximum distance between a change and evidence (default: 90)",
    )
    report.add_argument(
        "--actor-map",
        action="append",
        default=[],
        metavar="GITHUB_LOGIN=CLOUDTRAIL_IDENTITY",
        help="map an actor when CloudTrail and GitHub use different names (repeatable)",
    )
    report.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="report format (default: text)",
    )
    report.add_argument(
        "--max-events",
        type=int,
        default=2000,
        help="safety cap on tracked CloudTrail events (default: 2000)",
    )
    report.add_argument(
        "--max-deployment-details",
        type=int,
        default=None,
        metavar="N",
        help=(
            "how many deployments get a status/commit lookup "
            "(default: 20 with a token, 5 without)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_output()
    parser = build_parser()
    args = parser.parse_args(argv)

    end = args.end or datetime.now(timezone.utc)
    start = args.start or (end - timedelta(hours=24))
    if start >= end:
        parser.error("--start must be earlier than --end")
    if end - start > MAX_CLOUDTRAIL_RANGE:
        parser.error("CloudTrail LookupEvents supports at most 90 days per query")
    if args.tolerance_minutes < 1 or args.tolerance_minutes > 1440:
        parser.error("--tolerance-minutes must be between 1 and 1440")
    if args.max_events < 1:
        parser.error("--max-events must be at least 1")
    if args.max_deployment_details is not None and args.max_deployment_details < 0:
        parser.error("--max-deployment-details must not be negative")

    default_region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    regions = list(dict.fromkeys(r.strip() for r in (args.region or []) if r.strip()))
    if not regions:
        regions = [default_region]

    try:
        actor_pairs = parse_actor_pairs(args.actor_map)
    except ValueError as exc:
        parser.error(str(exc))

    repo = args.repo.strip() if args.repo else None
    if repo:
        try:
            validate_repo(repo)
        except ValueError as exc:
            parser.error(str(exc))

    warnings: list[str] = []
    try:
        changes, aws_warnings = fetch_changes(
            start=start,
            end=end,
            region=regions,
            profile=args.profile,
            max_events=args.max_events,
        )
    except CloudTrailError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    warnings.extend(aws_warnings)

    evidence = []
    unavailable: list[str] = []
    if repo:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            warnings.append(
                "GITHUB_TOKEN/GH_TOKEN not set; using unauthenticated GitHub API "
                "(60 requests/hour)."
            )
        try:
            evidence.extend(
                fetch_pull_requests(
                    repo,
                    token,
                    start,
                    end,
                    args.tolerance_minutes,
                    notes=warnings,
                )
            )
        except GitHubError as exc:
            unavailable.append("pull request")
            warnings.append(f"Pull request evidence unavailable: {exc}")
        try:
            evidence.extend(
                fetch_deployments(
                    repo,
                    token,
                    start,
                    end,
                    args.tolerance_minutes,
                    detail_limit=args.max_deployment_details,
                    notes=warnings,
                )
            )
        except GitHubError as exc:
            unavailable.append("deployment")
            warnings.append(f"Deployment evidence unavailable: {exc}")
    else:
        warnings.append("No --repo given; GitHub evidence was not queried.")

    matches = match_changes(
        changes,
        evidence,
        tolerance_minutes=args.tolerance_minutes,
        actor_pairs=actor_pairs,
        evidence_checked=bool(repo),
        unavailable_sources=unavailable,
    )
    meta = ReportMeta(
        start=start,
        end=end,
        generated_at=datetime.now(timezone.utc),
        region=", ".join(regions),
        repo=repo,
        tolerance_minutes=args.tolerance_minutes,
        warnings=tuple(warnings),
    )

    for warning in warnings:
        print(f"warning: {clean_text(warning)}", file=sys.stderr)
    sys.stdout.write(render(matches, meta, args.format))
    return 0


def _configure_output() -> None:
    # Reports can contain non-ASCII PR titles; write UTF-8 even when redirected on Windows.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid ISO 8601 datetime: {value!r}"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
