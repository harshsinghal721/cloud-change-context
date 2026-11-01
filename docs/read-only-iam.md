# Read-only access setup

## AWS IAM policy

The tool only needs `cloudtrail:LookupEvents`. `LookupEvents` does not support resource-level permissions, so the resource is `*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadCloudTrailEventsOnly",
      "Effect": "Allow",
      "Action": ["cloudtrail:LookupEvents"],
      "Resource": "*"
    }
  ]
}
```

No S3, EC2, IAM, or write actions are used. The tool does not call `DescribeSecurityGroups`; security group IDs and names come from the CloudTrail event itself.

Use the standard credential chain:

```bash
export AWS_PROFILE=security-audit
aws sso login --profile security-audit
ccx report --profile security-audit ...
```

Do not put access keys in this repository or in a report command line.

## GitHub token

Use a fine-grained token scoped to the target repository with read-only permissions:

- Metadata: read
- Pull requests: read
- Contents: read (for deployment commit messages)
- Deployments: read

Set it only in the environment:

```powershell
$env:GITHUB_TOKEN = "<token>"
```

For public repositories a token can be omitted, but unauthenticated requests are limited to 60 per hour and deployment details may be incomplete.

The token is sent in an `Authorization` header, never in a URL, and is never included in the generated report or error messages.
