# Matching rules

The goal is honest correlation, not an automatic approval system.

## Inputs

For the selected window:

1. CloudTrail management events for tracked IAM, EC2 security group, and S3 public-access operations.
2. Merged pull requests whose `merged_at` falls within the window plus tolerance.
3. Deployments whose `created_at` falls within the window plus tolerance, with their latest status and commit message when available.

## Signals

A candidate is any PR or deployment within `± tolerance_minutes` of the change time.

### Time

```
|evidence_time - change_time| <= tolerance
```

The default tolerance is 90 minutes. PR time is `merged_at`; deployment time is `created_at`.

### Actor

The GitHub actor (`user.login` for a PR, `creator.login` for a deployment) is normalized by lowercasing and removing non-alphanumeric characters. It must match one of the CloudTrail identities:

- IAM user name
- assumed-role name and session name
- ARN segments
- session issuer name
- service principal

Punctuation variants such as `harsh.sharma`, `harsh-sharma`, and `HarshSharma` normalize to the same value.

If the systems use unrelated names, add an alias:

```bash
ccx report ... --actor-map octocat=GitHubActionsRole
```

The alias maps a GitHub login to a CloudTrail identity. It works in either direction and only affects actor matching; resource and time matching are still required.

### Resource

Each tracked event produces a small set of resource identifiers: bucket name and ARN, security group ID/name and ARN, role/user/group name, policy name and ARN. The identifiers are searched in:

- PR title, body, and head branch name
- deployment ref, description, and commit message

Matching is case-insensitive and requires non-alphanumeric boundaries around the identifier. A three-character minimum avoids matching tiny strings.

Example: `acme-payments-logs` matches in `harden acme-payments-logs bucket` but not in `acme-payments-logs2`.

### State

- PR evidence must be merged.
- Deployment evidence must have latest status `success` for a strong match. `failure`, `error`, `pending`, or unknown status cannot produce `matched`.

## Labels

A candidate is **strong** when all of these are true:

1. Within the time tolerance.
2. Actor matches.
3. Resource matches.
4. Evidence state is merged PR or successful deployment.

Then:

| Condition | Label |
| --- | --- |
| Exactly one strong candidate | `matched` |
| More than one strong candidate | `uncertain` (ambiguous) |
| Candidates exist but none strong | `uncertain` |
| No candidates in the window | `unmatched` |

For `uncertain`, the reason states what was missing, for example:

- actor matched, resource not found
- resource matched, actor did not match
- time-proximate evidence only
- deployment did not succeed
- multiple strong matches; manual review required

## Evidence shown

- `matched`: only the single strong candidate is shown.
- `uncertain`: up to five nearby candidates, sorted by strength and time distance.
- `unmatched`: no evidence links.

## Fail-closed behavior

- No evidence never means approved.
- Failed or unknown deployments never produce `matched`.
- Ambiguity never produces `matched`.
- The report always contains `approval_granted: false` and every change contains `approved: false`.

## Known false positives and negatives

- A bucket name that is a prefix of another bucket can still match inside branch text. Actor and time are also required.
- A PR body may mention a resource it does not actually change. The tool correlates evidence; it does not diff the deployed result.
- A CI role shared by many humans makes actor matching weak unless an alias or resource name disambiguates it.
- Deployments without readable commit messages or with unavailable statuses remain `uncertain`.
- Very busy repositories may exceed the GitHub page cap, so some evidence may be missing. Narrow the window.
