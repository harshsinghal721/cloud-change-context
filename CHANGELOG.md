# Changelog

## Unreleased

### Fixed

- A change is no longer reported as "no PR or deployment within ..." when GitHub was never queried (`--repo` missing) or a source failed to load. The reason now says what could not be checked.
- A resource named only with generic words (`app`, `prod-api`, `logs`) can no longer produce a resource match by appearing anywhere in a PR's text.
- The GitHub page cap (500 items) and the deployment detail limit now produce warnings instead of silently dropping evidence.
- One failed commit or status lookup no longer disables all later lookups; only rate-limit and bad-token errors stop them.
- Deployments closest to the report window get the limited status/commit lookups first.
- `CreateSecurityGroup` events resolve the group ID from the response; `ModifySecurityGroupRules` shows the rules it changed; security-group sources use `groups` and no longer list the account ID as a source.
- The "malformed events skipped" warning is no longer lost when the event cap is reached, and the cap warning says how many lookups were not run.
- IAM summaries for events with missing names read `unknown` instead of a blank.
- ARNs and the IAM lookup region follow the partition (`aws`, `aws-cn`, `aws-us-gov`) instead of being hard-coded to `aws` / `us-east-1`.
- The text report sanitizes the event ID and evidence URLs like every other field.
- The GitHub token is never forwarded to another host on a redirect, and non-HTTPS redirects are refused.

### Changed

- CloudTrail is queried by event name (22 IAM lookups plus 16 per region) instead of scanning every event from IAM, EC2 and S3 and filtering locally. This is much faster on busy accounts and slightly slower on very quiet ones.
- Matching indexes evidence by time and skips most substring work; 2,000 changes against 300 PRs went from about 37 s to about 4 s in a worst-case benchmark.
- Deployment time is the span from creation to its latest terminal status, so a change made near the end of a long pipeline can match it.
- The user agent now uses the package version.

### Added

- `--region` can be repeated to read several regions.
- `--max-deployment-details` controls how many deployments get a status and commit lookup.
- Tests for GitHub pagination, caps, limits, rate limiting and redirects, for `fetch_changes` (with a fake AWS client), and for the new matching rules (25 tests became 86).
- `mypy` configuration and a `dev` extra; CI now runs Python 3.10 to 3.13 and a type check.

### Notes

- The security-group request layouts for `ModifySecurityGroupRules` and `groups` were implemented tolerantly from CloudTrail's documented shapes and have not been checked against live events.
