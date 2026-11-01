# Cloud Change Context

[![Tests](https://github.com/harshsinghal721/cloud-change-context/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/harshsinghal721/cloud-change-context/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Correlate AWS security-sensitive changes with GitHub pull requests and CI/CD deployments.

Cloud Change Context helps answer one question for every tracked CloudTrail event:

> What changed, who changed it, and what PR or successful deployment provides evidence for that change?

It is **read-only**. It never approves, modifies, or remediates cloud resources.

## What v0.1 tracks

- IAM policy changes: inline policies, managed policy attachments, policy versions, trust policies, and permissions boundaries.
- EC2 security group changes: inbound/outbound rule changes, group creation/deletion, rule modifications, and rule descriptions.
- S3 public-access changes: bucket policies, bucket ACLs, public access block settings, and static website hosting.

Sources: AWS CloudTrail `LookupEvents` and the GitHub REST API.

## What it does not do

- No automatic approval or remediation.
- No CloudFormation/Terraform drift detection.
- No policy semantics or public-exposure evaluation. S3 policy changes are labelled for review, not judged safe or unsafe.
- No extra cloud providers, dashboards, or AI fixes in this version.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
source .venv/bin/activate
pip install -e .
```

This installs the `ccx` command.

## Credentials

### AWS

Use the standard AWS credential chain: environment variables, shared config/profile, SSO, or an instance role. The tool only calls `cloudtrail:LookupEvents`.

```bash
export AWS_PROFILE=security-audit
# or: aws sso login --profile security-audit
```

The minimum IAM policy is in [docs/read-only-iam.md](docs/read-only-iam.md). No S3 or EC2 read permissions are needed because resource names come from CloudTrail.

### GitHub

Set a token in the environment (`GITHUB_TOKEN` or `GH_TOKEN`). The token is never written to disk, passed on the command line, or included in the report.

```powershell
$env:GITHUB_TOKEN = "<fine-grained-token>"
```

A fine-grained token needs read access to **Metadata**, **Pull requests**, **Contents**, and **Deployments**. Public repositories work without a token, but the unauthenticated rate limit is 60 requests/hour.

## Usage

```bash
ccx report --region us-east-1 --repo owner/name \
  --start 2026-10-30T00:00:00Z --end 2026-10-31T00:00:00Z
```

Default window is the last 24 hours. IAM is global, so IAM events are read from `us-east-1`; S3 and EC2 events come from `--region`.

Markdown or JSON output:

```bash
ccx report --region us-east-1 --repo owner/name --format markdown > report.md
ccx report --region us-east-1 --repo owner/name --format json > report.json
```

Useful options:

| Option | Meaning |
| --- | --- |
| `--start`, `--end` | ISO 8601 UTC window. CloudTrail supports at most 90 days per query. |
| `--region` | Region for S3 and EC2 events. Defaults to `AWS_REGION`, `AWS_DEFAULT_REGION`, or `us-east-1`. |
| `--profile` | Named AWS profile from the standard credential chain. |
| `--repo` | GitHub `owner/name`. Without it, every change is `unmatched`. |
| `--tolerance-minutes` | Maximum time distance for evidence. Default `90`. |
| `--actor-map` | Map a GitHub login to a CloudTrail identity. Repeatable. |
| `--format` | `text`, `markdown`, or `json`. |
| `--max-events` | Safety cap on tracked CloudTrail events. Default `2000`. |

### Actor mapping

CloudTrail often records a CI role while GitHub records a human or bot login. Map the two names explicitly:

```bash
ccx report ... --actor-map octocat=GitHubActionsRole
```

The order is `github_login=cloudtrail_identity`; either side can be the value used by the other system. Matching is case-insensitive and ignores punctuation.

## Labels

| Label | Meaning |
| --- | --- |
| `matched` | Exactly one nearby candidate has actor, resource, and a merged PR or successful deployment. |
| `uncertain` | Evidence exists, but a signal is missing or multiple candidates are equally strong. Human review required. |
| `unmatched` | No PR or deployment was found inside the tolerance window. |

**`matched` is not approval.** A matched change only has correlated evidence. The tool always reports `Approval granted: no` and `approved: false` in JSON. A missing or failed match is never treated as approved.

Exit code `0` means the report was generated. It does not mean every change is approved or matched. A CloudTrail query failure exits with code `2`.

See [docs/matching.md](docs/matching.md) for the full rules.

## Example report

See [examples/sample-report.md](examples/sample-report.md).

Each row contains the resource, change summary, actor, time, match status, and links to matching PRs/deployments. JSON includes event IDs, reasons, per-evidence signals, deployment state, and time delta.

## Security model

- Read-only AWS call: `cloudtrail:LookupEvents`. No S3, EC2, IAM, or remediation APIs are called.
- GitHub access is GET-only over HTTPS.
- AWS credentials come from the standard chain and are never persisted or printed.
- `GITHUB_TOKEN`/`GH_TOKEN` is read from the environment only.
- Raw CloudTrail request bodies are not retained. Policy documents and other request payloads are not written to reports.
- Report fields are sanitized for terminal/markdown output.
- A deployment must have a confirmed successful status to produce a `matched` label. Failed or unknown deployments stay `uncertain`.
- A PR must be merged to produce a `matched` label. The tool does not verify review approvals or branch protection.

Resource names and actor identities in a report are still sensitive operational data. Treat generated reports accordingly.

## Limitations

- CloudTrail `LookupEvents` covers management events, not data-plane events, only the last 90 days, and recent events may take a few minutes to appear.
- One AWS region per run, plus global IAM events from `us-east-1`.
- GitHub PR/deployment listing is capped at 5 pages (500 items each). Use a narrower window for very busy repositories.
- Correlation is heuristic. Actor names, resource names, and commit/PR text must contain usable identifiers. Aliases may be required.
- Security group changes reported by name only are not resolved to a group ID (that would need extra EC2 permissions).
- A merged PR or successful deployment is evidence of process, not proof that the deployed state matches the intended change.

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

Project layout:

```text
src/cloud_change_context/
  cli.py          command-line entry point
  cloudtrail.py   CloudTrail read + normalization
  github.py       GitHub PR/deployment evidence
  matching.py     actor/resource/time correlation
  models.py       core data types
  report.py       text, markdown, JSON output
tests/            offline unit tests
docs/             matching rules and least-privilege setup
examples/         sample report
```

## License

MIT
