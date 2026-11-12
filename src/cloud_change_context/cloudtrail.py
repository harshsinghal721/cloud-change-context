from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from . import __version__
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

# IAM is global; its events are recorded in one fixed region per partition.
_IAM_REGIONS = {
    "aws": "us-east-1",
    "aws-cn": "cn-north-1",
    "aws-us-gov": "us-gov-west-1",
}

_ARN_NOISE = {"arn", "aws", "sts", "iam", "assumed-role", "user", "role", "federated-user"}

_IAM_TEMPLATES = {
    "PutRolePolicy": 'Created or updated inline policy "{policy_name}" on role {role}',
    "PutUserPolicy": 'Created or updated inline policy "{policy_name}" on user {user}',
    "PutGroupPolicy": 'Created or updated inline policy "{policy_name}" on group {group}',
    "DeleteRolePolicy": 'Deleted inline policy "{policy_name}" from role {role}',
    "DeleteUserPolicy": 'Deleted inline policy "{policy_name}" from user {user}',
    "DeleteGroupPolicy": 'Deleted inline policy "{policy_name}" from group {group}',
    "AttachRolePolicy": "Attached managed policy {policy_label} to role {role}",
    "DetachRolePolicy": "Detached managed policy {policy_label} from role {role}",
    "AttachUserPolicy": "Attached managed policy {policy_label} to user {user}",
    "DetachUserPolicy": "Detached managed policy {policy_label} from user {user}",
    "AttachGroupPolicy": "Attached managed policy {policy_label} to group {group}",
    "DetachGroupPolicy": "Detached managed policy {policy_label} from group {group}",
    "CreatePolicy": 'Created managed policy "{policy_name}"',
    "DeletePolicy": "Deleted managed policy {policy_label}",
    "CreatePolicyVersion": "Created a new version of policy {policy_label}",
    "DeletePolicyVersion": "Deleted version {version_id} of policy {policy_label}",
    "SetDefaultPolicyVersion": "Set default version of policy {policy_label} to {version_id}",
    "UpdateAssumeRolePolicy": "Updated the trust policy for role {role}",
    "PutRolePermissionsBoundary": "Set permissions boundary {boundary} on role {role}",
    "DeleteRolePermissionsBoundary": "Removed the permissions boundary from role {role}",
    "PutUserPermissionsBoundary": "Set permissions boundary {boundary} on user {user}",
    "DeleteUserPermissionsBoundary": "Removed the permissions boundary from user {user}",
}


def partition_for(region: str | None) -> str:
    """Map a region name to its AWS partition (used to build correct ARNs)."""
    name = (region or "").lower()
    if name.startswith("cn-"):
        return "aws-cn"
    if name.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


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
    partition = partition_for(region)
    actor, actor_ids = _identity(identity)
    params = _dict(raw.get("requestParameters"))
    response = _dict(raw.get("responseElements"))

    if source == "iam.amazonaws.com":
        resource, resource_ids, summary = _iam_event(
            name, params, response, account, partition
        )
    elif source == "s3.amazonaws.com":
        resource, resource_ids, summary = _s3_event(name, params, partition)
    else:
        resource, resource_ids, summary = _security_group_event(
            name, params, response, account, region, partition
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


def plan_queries(regions: Sequence[str]) -> list[tuple[str, str]]:
    """The (region, event name) lookups needed to cover every tracked event.

    Looking events up by name keeps CloudTrail from returning every read-only call
    (``GetRole``, ``DescribeInstances``, ...) just to have them thrown away.
    """
    queries: list[tuple[str, str]] = []
    for partition in dict.fromkeys(partition_for(region) for region in regions):
        iam_region = _IAM_REGIONS.get(partition, "us-east-1")
        queries.extend((iam_region, name) for name in sorted(IAM_EVENTS))
    for region in regions:
        queries.extend((region, name) for name in sorted(EC2_EVENTS))
        queries.extend((region, name) for name in sorted(S3_EVENTS))
    return list(dict.fromkeys(queries))


def fetch_changes(
    start: datetime,
    end: datetime,
    region: str | Sequence[str],
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

    regions = _regions(region)
    queries = plan_queries(regions)

    changes: list[Change] = []
    seen_ids: set[str] = set()
    warnings: list[str] = []
    parse_errors = 0

    def finish() -> tuple[list[Change], list[str]]:
        if parse_errors:
            warnings.append(f"Skipped {parse_errors} malformed CloudTrail event(s).")
        return sorted(changes, key=lambda change: change.time), warnings

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        config = Config(
            retries={"max_attempts": 5, "mode": "standard"},
            user_agent_extra=f"cloud-change-context/{__version__}",
        )
        clients: dict[str, Any] = {}
        for done, (query_region, event_name) in enumerate(queries):
            if query_region not in clients:
                clients[query_region] = session.client(
                    "cloudtrail", region_name=query_region, config=config
                )
            client = clients[query_region]
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "StartTime": start,
                    "EndTime": end,
                    "LookupAttributes": [
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
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
                    if change.event_id != "unknown-event":
                        if change.event_id in seen_ids:
                            continue
                        seen_ids.add(change.event_id)
                    if len(changes) >= max_events:
                        remaining = len(queries) - done - 1
                        warnings.append(
                            f"CloudTrail event cap ({max_events}) reached while reading "
                            f"{event_name} in {query_region}; {remaining} later lookup(s) "
                            "were not run, so the report is incomplete."
                        )
                        return finish()
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

    return finish()


def _regions(region: str | Sequence[str]) -> list[str]:
    values = [region] if isinstance(region, str) else list(region)
    regions = list(dict.fromkeys(value.strip() for value in values if value and value.strip()))
    if not regions:
        raise CloudTrailError("At least one AWS region is required.")
    return regions


def _iam_event(
    name: str,
    params: dict[str, Any],
    response: dict[str, Any],
    account: str | None,
    partition: str = "aws",
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
    template = _IAM_TEMPLATES.get(name)
    if template is None:
        summary = f"{name} on {target}"
    else:
        summary = template.format(
            role=role or "unknown",
            user=user or "unknown",
            group=group or "unknown",
            policy_name=policy_name or "unknown",
            policy_label=policy_arn or policy_name or "unknown policy",
            boundary=boundary or "unknown",
            version_id=version_id or "unknown",
        )
    if name == "CreatePolicyVersion" and str(params.get("setAsDefault")).lower() == "true":
        summary += " and set it as the default"

    identifiers = [role, user, group, policy_name, policy_arn, boundary]
    if account and role:
        identifiers.append(f"arn:{partition}:iam::{account}:role/{role}")
    if account and user:
        identifiers.append(f"arn:{partition}:iam::{account}:user/{user}")
    return resource, identifiers, summary


def _s3_event(
    name: str, params: dict[str, Any], partition: str = "aws"
) -> tuple[str, list[str], str]:
    bucket = _str(params.get("bucketName")) or "unknown-bucket"
    arn = f"arn:{partition}:s3:::{bucket}"

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
    partition: str = "aws",
) -> tuple[str, list[str], str]:
    group = _dict(response.get("securityGroup"))
    group_id = (
        _str(params.get("groupId"))
        or _str(response.get("groupId"))  # CreateSecurityGroup answers at the top level
        or _str(group.get("groupId"))
        or _deep_str(params, "groupid")  # ModifySecurityGroupRules nests it in its request
    )
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
    if name == "ModifySecurityGroupRules":
        details = _modified_rule_details(params)
    else:
        details = _rule_details(params)
    if details:
        summary = f"{summary}: {details}"

    identifiers = [group_id, group_name]
    if account and region and group_id:
        identifiers.append(
            f"arn:{partition}:ec2:{region}:{account}:security-group/{group_id}"
        )
    return resource, identifiers, summary


_MAX_RULES_SHOWN = 3


def _port_label(protocol: str, from_port: Any, to_port: Any) -> str:
    if protocol in ("-1", "all"):
        return "all"
    if from_port is None and to_port is None:
        return ""
    if from_port == to_port:
        return str(from_port)
    start_port = from_port if from_port is not None else "*"
    end_port = to_port if to_port is not None else "*"
    return f"{start_port}-{end_port}"


def _rule_label(protocol: str, port: str, sources: list[str]) -> str:
    label = f"{protocol} {port}".strip()
    if sources:
        label += f" from {', '.join(dict.fromkeys(sources))}"
    return label


def _rule_details(params: dict[str, Any]) -> str:
    all_items = _aws_list(params.get("ipPermissions"))
    details: list[str] = []
    for item in all_items[:_MAX_RULES_SHOWN]:
        permission = _dict(item)
        protocol = _str(permission.get("ipProtocol")) or "?"
        port = _port_label(protocol, permission.get("fromPort"), permission.get("toPort"))

        sources: list[str] = []
        # CloudTrail names the security-group sources "groups"; "userIdGroupPairs" is the
        # SDK name. The account id (userId) is not a source, so it is not listed.
        for key, field in (
            ("ipRanges", "cidrIp"),
            ("ipv6Ranges", "cidrIpv6"),
            ("prefixListIds", "prefixListId"),
            ("groups", "groupId"),
            ("userIdGroupPairs", "groupId"),
        ):
            for source in _aws_list(permission.get(key)):
                value = _str(_dict(source).get(field))
                if value:
                    sources.append(value)
        details.append(_rule_label(protocol, port, sources))

    if len(all_items) > _MAX_RULES_SHOWN:
        details.append(f"+{len(all_items) - _MAX_RULES_SHOWN} more rule(s)")
    return "; ".join(details)


def _modified_rule_details(params: dict[str, Any]) -> str:
    """Summarize ModifySecurityGroupRules, whose rules sit in a nested request object.

    The nesting and key casing are matched loosely (case-insensitive, any depth) so a
    layout change in CloudTrail degrades to a shorter summary instead of an error.
    """
    rules = [rule for rule in _walk_dicts(params) if "ipprotocol" in _lower_keys(rule)]
    details: list[str] = []
    for rule in rules[:_MAX_RULES_SHOWN]:
        fields = _lower_keys(rule)
        protocol = _str(fields.get("ipprotocol")) or "?"
        port = _port_label(protocol, fields.get("fromport"), fields.get("toport"))
        sources: list[str] = []
        for key in ("cidripv4", "cidripv6", "prefixlistid"):
            value = _str(fields.get(key))
            if value:
                sources.append(value)
        referenced = fields.get("referencedgroupid")
        referenced_id = (
            _str(referenced)
            if isinstance(referenced, str)
            else _str(_lower_keys(_dict(referenced)).get("groupid"))
        )
        if referenced_id:
            sources.append(referenced_id)
        details.append(_rule_label(protocol, port, sources))
    if len(rules) > _MAX_RULES_SHOWN:
        details.append(f"+{len(rules) - _MAX_RULES_SHOWN} more rule(s)")
    return "; ".join(details)


def _walk_dicts(value: Any, depth: int = 0) -> list[dict[str, Any]]:
    """Every dict nested inside ``value`` (shallow depth limit; CloudTrail bodies are small)."""
    if depth > 8:
        return []
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        children: list[Any] = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        return found
    for child in children:
        found.extend(_walk_dicts(child, depth + 1))
    return found


def _lower_keys(value: dict[str, Any]) -> dict[str, Any]:
    return {str(key).lower(): item for key, item in value.items()}


def _deep_str(value: Any, key: str) -> str:
    """First non-empty string stored under ``key`` (case-insensitive) at any depth."""
    for found in _walk_dicts(value):
        text = _str(_lower_keys(found).get(key))
        if text:
            return text
    return ""


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
