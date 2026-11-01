# Cloud Change Context - AWS change report

- **Generated:** 2026-10-31T12:05:00Z
- **Window:** 2026-10-31T09:00:00Z -> 2026-10-31T12:00:00Z (UTC)
- **Region:** us-east-1
- **Repo:** acme/payments-infra
- **Tolerance:** +/-60 minutes

> **matched** means matching evidence was found. It is not approval.
> This tool never approves, modifies, or remediates cloud resources.

## Changes

| Time (UTC) | Resource | Change | Actor | Match | Evidence |
| --- | --- | --- | --- | --- | --- |
| 2026-10-31T09:15:00Z | arn:aws:s3:::acme-payments-logs | Updated S3 public access block settings (enabled: blockPublicAcls, blockPublicPolicy) | harsh.sharma | **matched**<br>single time/actor/resource match | [PR #184 - Harden payments log bucket](https://github.com/acme/payments-infra/pull/184) (actor, resource, merged, 7 min) |
| 2026-10-31T09:35:00Z | role/payments-deploy | Attached managed policy arn:aws:iam::123456789012:policy/PaymentsDeploy to role payments-deploy | GitHubActionsRole | **matched**<br>single time/actor/resource match | [deployment 9182 - main](https://github.com/acme/payments-infra/deployments/9182) (actor, resource, deployment success, 5 min) |
| 2026-10-31T10:50:00Z | sg-0abc123def4567890 | Authorized inbound security group rule(s): tcp 22 from 0.0.0.0/0 | alice | **unmatched**<br>no PR or deployment within +/-60 minutes | none |
| 2026-10-31T11:50:00Z | arn:aws:s3:::acme-public-assets | Set a bucket policy (review for public principals) | bob | **uncertain**<br>actor matched, but the resource was not found in GitHub evidence | [PR #186 - Update bucket policy](https://github.com/acme/payments-infra/pull/186) (actor, merged, 5 min) |

## Summary

- Total: 4
- Matched: 2
- Uncertain: 1
- Unmatched: 1
- Approval granted: **no** (read-only tool)

