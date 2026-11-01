from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .models import Change


class CloudTrailError(Exception):
    """A safe, user-facing CloudTrail query error."""


IAM_EVENTS = frozenset(
    {
        "PutRolePolicy",
        "DeleteRolePolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "PutGroupPolicy",
        "DeleteGroupPolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "CreatePolicy",
        "DeletePolicy",
        "CreatePolicyVersion",
        "DeletePolicyVersion",
        "SetDefaultPolicyVersion",
        "UpdateAssumeRolePolicy",
        "PutRolePermissionsBoundary",
        "DeleteRolePermissionsBoundary",
        "PutUserPermissionsBoundary",
        "DeleteUserPermissionsBoundary",
    }
)

S3_EVENTS = frozenset(
    {
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketWebsite",
        "DeleteBucketWebsite",
    }
)

EC2_EVENTS = frozenset(
    {
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "ModifySecurityGroupRules",
        "UpdateSecurityGroupRuleDescriptionsIngress",
        "UpdateSecurityGroupRuleDescriptionsEgress",
    }
)

_HANDLERS = {
    "iam.amazonaws.com": IAM_EVENTS,
    "s3.amazonaws.com": S3_EVENTS,
    "ec2.amazonaws.com": EC2_EVENTS,
}

_ARN_NOISE = {"arn", "aws", "sts", "iam", "assumed-role", "user", "role", "federated-user"}


def parse_event(raw: dict[str, Any]) -> Change | None:
    """Convert one raw CloudTrail event into a Change, or None if not tracked."""
    if not isinstance(raw, dict):
        return None

    source = _str(raw.get("eventSource"))
    name = _str(raw.get("eventName"))
    if not source or source not in _HANDLERS or name not in _HANDLERS[source]:
        return None

    identity = _dict(raw.get("userIdentity"))
    account = (
        _str(raw.get("recipientAccountId"))
        or _str(identity.get("accountId"))
        or None
    )
    region = _str(raw.get("awsRegion")) or None
    actor, actor_ids = _identity(identity)
    params = _dict(raw.get("requestParameters"))
    response = _dict(raw.get("responseElements"))

    if source == "iam.amazonaws.com":
        resource, resource_ids, summary = _iam_event(name, params, response, account)
    elif source == "s3.amazonaws.com":
        resource, resource_ids, summary = _s3_event(name, params)
    else:
        resource, resource_ids, summary = _security_group_event(
            name, params, response, account, region
        )

    resource_values = list(resource_ids)
    if not resource.startswith("unknown"):
        resource_values.append(resource)

    return Change(
        event_id=_str(raw.get("eventID")) or "unknown-event",
        time=_parse_time(raw.get("eventTime")),
        actor=actor,
        actor_identifiers=_clean_ids([] if actor == "unknown" else [actor, *actor_ids]),
        event_source=source,
        event_name=name,
        resource=resource,
        resource_identifiers=_clean_ids(resource_values),
        summary=summary,
        account=account,
        region=region,
    )


def fetch_changes(
    start: datetime,
    end: datetime,
    region: str,
    profile: str | None = None,
    max_events: int = 2000,
) -> tuple[list[Change], list[str]]:
    """Read tracked CloudTrail events. This function only calls lookup_events."""
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        raise CloudTrailError(
            "boto3 is required. Install with: pip install cloud-change-context"
        ) from None

    queries = [("us-east-1", "iam.amazonaws.com")]
    queries.append((region, "ec2.amazonaws.com"))
    queries.append((region, "s3.amazonaws.com"))

    changes: list[Change] = []
    warnings: list[str] = []
    parse_errors = 0

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        config = Config(
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra="cloud-change-context/0.1.0",
        )
        for query_region, source in queries:
            client = session.client("cloudtrail", region_name=query_region, config=config)
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "StartTime": start,
                    "EndTime": end,
                    "LookupAttributes": [
                        {"AttributeKey": "EventSource", "AttributeValue": source}
                    ],
                    "MaxResults": 50,
                }
                if token:
                    kwargs["NextToken"] = token
                response = client.lookup_events(**kwargs)

                for item in response.get("Events", []):
                    payload = item.get("CloudTrailEvent")
                    if isinstance(payload, str):
                        try:
                            payload = json.loads(payload)
                        except json.JSONDecodeError:
                            parse_errors += 1
                            continue
                    try:
                        change = parse_event(payload)
                    except (TypeError, ValueError, KeyError):
                        parse_errors += 1
                        continue
                    if change is None:
                        continue
                    if len(changes) >= max_events:
                        warnings.append(
                            f"CloudTrail event cap ({max_events}) reached; "
                            "the report is incomplete."
                        )
                        return sorted(changes, key=lambda c: c.time), warnings
                    changes.append(change)

                token = response.get("NextToken")
                if not token:
                    break
    except (BotoCoreError, ClientError) as exc:
        raise CloudTrailError(f"CloudTrail lookup failed: {exc}") from None
    except CloudTrailError:
        raise
    except Exception as exc:  # credential/config errors from session setup
        raise CloudTrailError(f"CloudTrail query failed: {exc}") from None

    if parse_errors:
        warnings.append(f"Skipped {parse_errors} malformed CloudTrail event(s).")

    return sorted(changes, key=lambda c: c.time), warnings


def _iam_event(
    name: str, params: dict[str, Any], response: dict[str, Any], account: str | None
) -> tuple[str, list[str], str]:
    role = _str(params.get("roleName"))
    user = _str(params.get("userName"))
    group = _str(params.get("groupName"))
    policy_name = _str(params.get("policyName"))
    policy_arn = _str(params.get("policyArn"))
    boundary = _str(params.get("permissionsBoundary"))
    version_id = _str(params.get("versionId"))

    policy = _dict(response.get("policy"))
    policy_arn = policy_arn or _str(policy.get("arn"))
    version = _dict(response.get("policyVersion"))
    version_id = version_id or _str(version.get("versionId"))
    if not policy_name and policy_arn:
        policy_name = policy_arn.rsplit("/", 1)[-1]

    if role:
        resource = f"role/{role}"
    elif user:
        resource = f"user/{user}"
    elif group:
        resource = f"group/{group}"
    elif policy_arn:
        resource = policy_arn
    elif policy_name:
        resource = f"policy/{policy_name}"
    else:
        resource = "unknown IAM resource"

    target = role or user or group or policy_arn or policy_name or "unknown target"
    policy_label = policy_arn or policy_name or "unknown policy"

    if name == "PutRolePolicy":
        summary = f'Created or updated inline policy "{policy_name or "unknown"}" on role {role}'
    elif name == "PutUserPolicy":
        summary = f'Created or updated inline policy "{policy_name or "unknown"}" on user {user}'
    elif name == "PutGroupPolicy":
        summary = f'Created or updated inline policy "{policy_name or "unknown"}" on group {group}'
    elif name == "DeleteRolePolicy":
        summary = f'Deleted inline policy "{policy_name or "unknown"}" from role {role}'
    elif name == "DeleteUserPolicy":
        summary = f'Deleted inline policy "{policy_name or "unknown"}" from user {user}'
    elif name == "DeleteGroupPolicy":
        summary = f'Deleted inline policy "{policy_name or "unknown"}" from group {group}'
    elif name == "AttachRolePolicy":
        summary = f"Attached managed policy {policy_label} to role {role}"
    elif name == "DetachRolePolicy":
        summary = f"Detached managed policy {policy_label} from role {role}"
    elif name == "AttachUserPolicy":
        summary = f"Attached managed policy {policy_label} to user {user}"
    elif name == "DetachUserPolicy":
        summary = f"Detached managed policy {policy_label} from user {user}"
    elif name == "AttachGroupPolicy":
        summary = f"Attached managed policy {policy_label} to group {group}"
    elif name == "DetachGroupPolicy":
        summary = f"Detached managed policy {policy_label} from group {group}"
    elif name == "CreatePolicy":
        summary = f'Created managed policy "{policy_name or "unknown"}"'
    elif name == "DeletePolicy":
        summary = f"Deleted managed policy {policy_label}"
    elif name == "CreatePolicyVersion":
        summary = f"Created a new version of policy {policy_label}"
        if params.get("setAsDefault") is True:
            summary += " and set it as the default"
    elif name == "DeletePolicyVersion":
        summary = f"Deleted version {version_id or 'unknown'} of policy {policy_label}"
    elif name == "SetDefaultPolicyVersion":
        summary = f"Set default version of policy {policy_label} to {version_id or 'unknown'}"
    elif name == "UpdateAssumeRolePolicy":
        summary = f"Updated the trust policy for role {role or 'unknown'}"
    elif name == "PutRolePermissionsBoundary":
        summary = f"Set permissions boundary {boundary or 'unknown'} on role {role}"
    elif name == "DeleteRolePermissionsBoundary":
        summary = f"Removed the permissions boundary from role {role}"
    elif name == "PutUserPermissionsBoundary":
        summary = f"Set permissions boundary {boundary or 'unknown'} on user {user}"
    elif name == "DeleteUserPermissionsBoundary":
        summary = f"Removed the permissions boundary from user {user}"
    else:
        summary = f"{name} on {target}"

    identifiers = [role, user, group, policy_name, policy_arn, boundary]
    if account and role:
        identifiers.append(f"arn:aws:iam::{account}:role/{role}")
    if account and user:
        identifiers.append(f"arn:aws:iam::{account}:user/{user}")
    return resource, identifiers, summary


def _s3_event(
    name: str, params: dict[str, Any]
) -> tuple[str, list[str], str]:
    bucket = _str(params.get("bucketName")) or "unknown-bucket"
    arn = f"arn:aws:s3:::{bucket}"

    if name == "PutBucketPolicy":
        summary = "Set a bucket policy (review for public principals)"
    elif name == "DeleteBucketPolicy":
        summary = "Deleted the bucket policy"
    elif name == "PutBucketAcl":
        summary = "Updated the bucket ACL (review for public grants)"
    elif name == "PutBucketPublicAccessBlock":
        config = _dict(params.get("publicAccessBlockConfiguration"))
        enabled = sorted(key for key, value in config.items() if value is True)
        if config:
            summary = "Updated S3 public access block settings"
            summary += f" (enabled: {', '.join(enabled) if enabled else 'none'})"
        else:
            summary = "Updated S3 public access block settings"
    elif name == "DeleteBucketPublicAccessBlock":
        summary = "Removed S3 public access block settings (public access may be possible)"
    elif name == "PutBucketWebsite":
        summary = "Enabled or updated static website hosting"
    elif name == "DeleteBucketWebsite":
        summary = "Disabled static website hosting"
    else:
        summary = f"{name} on bucket {bucket}"

    return arn, [bucket, arn, f"s3://{bucket}"], summary


def _security_group_event(
    name: str,
    params: dict[str, Any],
    response: dict[str, Any],
    account: str | None,
    region: str | None,
) -> tuple[str, list[str], str]:
    group = _dict(response.get("securityGroup"))
    group_id = _str(params.get("groupId")) or _str(group.get("groupId"))
    group_name = _str(params.get("groupName")) or _str(group.get("groupName"))

    if group_id:
        resource = group_id
    elif group_name:
        resource = f"security-group/{group_name}"
    else:
        resource = "unknown security group"

    labels = {
        "AuthorizeSecurityGroupIngress": "Authorized inbound security group rule(s)",
        "AuthorizeSecurityGroupEgress": "Authorized outbound security group rule(s)",
        "RevokeSecurityGroupIngress": "Revoked inbound security group rule(s)",
        "RevokeSecurityGroupEgress": "Revoked outbound security group rule(s)",
        "CreateSecurityGroup": "Created security group",
        "DeleteSecurityGroup": "Deleted security group",
        "ModifySecurityGroupRules": "Modified security group rules",
        "UpdateSecurityGroupRuleDescriptionsIngress": (
            "Updated inbound security group rule description(s)"
        ),
        "UpdateSecurityGroupRuleDescriptionsEgress": (
            "Updated outbound security group rule description(s)"
        ),
    }
    summary = labels.get(name, f"{name} on {resource}")
    details = _rule_details(params)
    if details:
        summary = f"{summary}: {details}"

    identifiers = [group_id, group_name]
    if account and region and group_id:
        identifiers.append(f"arn:aws:ec2:{region}:{account}:security-group/{group_id}")
    return resource, identifiers, summary


def _rule_details(params: dict[str, Any]) -> str:
    items = _aws_list(params.get("ipPermissions"))[:3]
    details: list[str] = []
    for item in items:
        permission = _dict(item)
        protocol = _str(permission.get("ipProtocol")) or "?"
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")
        if protocol in ("-1", "all"):
            port = "all"
        elif from_port is None and to_port is None:
            port = ""
        elif from_port == to_port:
            port = str(from_port)
        else:
            start_port = from_port if from_port is not None else "*"
            end_port = to_port if to_port is not None else "*"
            port = f"{start_port}-{end_port}"

        sources: list[str] = []
        for key, field in (
            ("ipRanges", "cidrIp"),
            ("ipv6Ranges", "cidrIpv6"),
            ("prefixListIds", "prefixListId"),
            ("userIdGroupPairs", "groupId"),
            ("userIdGroupPairs", "userId"),
        ):
            for source in _aws_list(permission.get(key)):
                value = _str(_dict(source).get(field))
                if value:
                    sources.append(value)

        label = f"{protocol} {port}".strip()
        if sources:
            label += f" from {', '.join(dict.fromkeys(sources))}"
        details.append(label)

    all_items = _aws_list(params.get("ipPermissions"))
    if len(all_items) > 3:
        details.append(f"+{len(all_items) - 3} more rule(s)")
    return "; ".join(details)


def _identity(identity: dict[str, Any]) -> tuple[str, list[str]]:
    identifiers: list[str] = []
    issuer = _dict(_dict(identity.get("sessionContext")).get("sessionIssuer"))
    arn = _str(identity.get("arn"))

    for value in (
        identity.get("userName"),
        identity.get("principalId"),
        identity.get("invokedBy"),
        arn,
        issuer.get("userName"),
        issuer.get("arn"),
    ):
        _add(identifiers, value)

    if arn:
        for segment in re.split(r"[/:]", arn):
            if segment and segment not in _ARN_NOISE:
                _add(identifiers, segment)

    principal = _str(identity.get("principalId"))
    if ":" in principal:
        _add(identifiers, principal.split(":", 1)[1])

    for value in list(identifiers):
        if "@" in value:
            _add(identifiers, value.split("@", 1)[0])

    actor = _str(identity.get("userName"))
    if not actor:
        actor = _str(issuer.get("userName"))
    if not actor and ":assumed-role/" in arn:
        actor = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    if not actor and arn:
        actor = arn.rsplit("/", 1)[-1]
    if not actor:
        actor = _str(identity.get("invokedBy")) or "unknown"
    return actor, identifiers


def _add(values: list[str], value: Any) -> None:
    text = _str(value)
    if text:
        values.append(text)


def _clean_ids(values: list[Any]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _str(value)
        if len(text) < 3 or text.lower() in seen:
            continue
        seen.add(text.lower())
        result.append(text)
    return tuple(result)


def _aws_list(value: Any) -> list[Any]:
    items = _dict(value).get("items")
    return items if isinstance(items, list) else []


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif value:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    else:
        raise ValueError("CloudTrail event has no eventTime")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
