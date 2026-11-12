import json
import sys
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from cloud_change_context.cloudtrail import (
    EC2_EVENTS,
    IAM_EVENTS,
    S3_EVENTS,
    CloudTrailError,
    fetch_changes,
    parse_event,
    partition_for,
    plan_queries,
)


def event(name, source, params=None, response=None, arn=None, user_name=None):
    raw = {
        "eventID": "event-1",
        "eventTime": "2026-10-31T10:00:00Z",
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": arn or "arn:aws:sts::123456789012:assumed-role/GitHubActionsRole/deploy",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": "GitHubActionsRole",
                    "arn": "arn:aws:iam::123456789012:role/GitHubActionsRole",
                }
            },
        },
        "requestParameters": params or {},
        "responseElements": response or {},
    }
    if user_name:
        raw["userIdentity"]["userName"] = user_name
    return raw


class CloudTrailParsingTests(unittest.TestCase):
    def test_iam_inline_policy_change(self):
        change = parse_event(
            event(
                "PutRolePolicy",
                "iam.amazonaws.com",
                {
                    "roleName": "deploy-role",
                    "policyName": "deploy-inline",
                    "policyDocument": "SECRET-DOCUMENT-BODY",
                },
            )
        )
        self.assertIsNotNone(change)
        self.assertEqual(change.resource, "role/deploy-role")
        self.assertIn('"deploy-inline"', change.summary)
        self.assertIn("deploy-role", change.resource_identifiers)
        self.assertNotIn("SECRET-DOCUMENT-BODY", repr(change))

    def test_s3_public_access_block_settings(self):
        change = parse_event(
            event(
                "PutBucketPublicAccessBlock",
                "s3.amazonaws.com",
                {
                    "bucketName": "acme-logs",
                    "publicAccessBlockConfiguration": {
                        "blockPublicAcls": True,
                        "ignorePublicAcls": False,
                        "blockPublicPolicy": True,
                        "restrictPublicBuckets": False,
                    },
                },
            )
        )
        self.assertIsNotNone(change)
        self.assertEqual(change.resource, "arn:aws:s3:::acme-logs")
        self.assertIn("blockPublicAcls", change.summary)
        self.assertIn("blockPublicPolicy", change.summary)
        self.assertNotIn("ignorePublicAcls", change.summary)

    def test_security_group_ingress_rule(self):
        change = parse_event(
            event(
                "AuthorizeSecurityGroupIngress",
                "ec2.amazonaws.com",
                {
                    "groupId": "sg-0123456789abcdef0",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 443,
                                "toPort": 443,
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                            }
                        ]
                    },
                },
            )
        )
        self.assertIsNotNone(change)
        self.assertEqual(change.resource, "sg-0123456789abcdef0")
        self.assertIn("tcp 443", change.summary)
        self.assertIn("0.0.0.0/0", change.summary)

    def test_assumed_role_identity_is_normalized(self):
        change = parse_event(
            event(
                "UpdateAssumeRolePolicy",
                "iam.amazonaws.com",
                {"roleName": "deploy-role"},
            )
        )
        self.assertIsNotNone(change)
        self.assertEqual(change.actor, "GitHubActionsRole")
        self.assertIn("GitHubActionsRole", change.actor_identifiers)

    def test_unknown_resource_is_not_a_match_token(self):
        change = parse_event(event("PutRolePolicy", "iam.amazonaws.com"))
        self.assertIsNotNone(change)
        self.assertEqual(change.resource, "unknown IAM resource")
        self.assertNotIn("unknown IAM resource", change.resource_identifiers)
        self.assertEqual(change.resource_identifiers, ())

    def test_untracked_event_is_ignored(self):
        self.assertIsNone(
            parse_event(event("DescribeInstances", "ec2.amazonaws.com"))
        )


class SecurityGroupParsingTests(unittest.TestCase):
    def test_create_security_group_reads_group_id_from_response(self):
        change = parse_event(
            event(
                "CreateSecurityGroup",
                "ec2.amazonaws.com",
                {"groupName": "web-sg"},
                {"_return": True, "groupId": "sg-0abc123def"},
            )
        )
        self.assertEqual(change.resource, "sg-0abc123def")
        self.assertIn("web-sg", change.resource_identifiers)

    def test_modify_security_group_rules_lists_the_rules(self):
        change = parse_event(
            event(
                "ModifySecurityGroupRules",
                "ec2.amazonaws.com",
                {
                    "ModifySecurityGroupRulesRequest": {
                        "GroupId": "sg-0abc123def",
                        "SecurityGroupRule": {
                            "items": [
                                {
                                    "SecurityGroupRuleId": "sgr-1",
                                    "SecurityGroupRule": {
                                        "IpProtocol": "tcp",
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "CidrIpv4": "0.0.0.0/0",
                                    },
                                }
                            ]
                        },
                    }
                },
            )
        )
        self.assertEqual(change.resource, "sg-0abc123def")
        self.assertIn("tcp 22 from 0.0.0.0/0", change.summary)

    def test_modify_security_group_rules_with_unexpected_shape_still_parses(self):
        change = parse_event(
            event("ModifySecurityGroupRules", "ec2.amazonaws.com", {"unexpected": [1, 2]})
        )
        self.assertEqual(change.summary, "Modified security group rules")

    def test_group_sources_use_group_id_not_account_id(self):
        change = parse_event(
            event(
                "AuthorizeSecurityGroupIngress",
                "ec2.amazonaws.com",
                {
                    "groupId": "sg-0abc123def",
                    "ipPermissions": {
                        "items": [
                            {
                                "ipProtocol": "tcp",
                                "fromPort": 443,
                                "toPort": 443,
                                "groups": {
                                    "items": [
                                        {"groupId": "sg-0fed321cba", "userId": "123456789012"}
                                    ]
                                },
                            }
                        ]
                    },
                },
            )
        )
        self.assertIn("from sg-0fed321cba", change.summary)
        self.assertNotIn("123456789012", change.summary)


class IamSummaryTests(unittest.TestCase):
    def test_missing_names_read_as_unknown_not_blank(self):
        change = parse_event(event("PutRolePolicy", "iam.amazonaws.com"))
        self.assertIn("role unknown", change.summary)

    def test_set_as_default_accepts_bool_and_string(self):
        for value in (True, "true"):
            with self.subTest(value=value):
                change = parse_event(
                    event(
                        "CreatePolicyVersion",
                        "iam.amazonaws.com",
                        {"policyArn": "arn:aws:iam::123456789012:policy/P", "setAsDefault": value},
                    )
                )
                self.assertTrue(change.summary.endswith("set it as the default"))


class PartitionTests(unittest.TestCase):
    def test_partition_for_region(self):
        self.assertEqual(partition_for("us-east-1"), "aws")
        self.assertEqual(partition_for("cn-north-1"), "aws-cn")
        self.assertEqual(partition_for("us-gov-west-1"), "aws-us-gov")
        self.assertEqual(partition_for(None), "aws")

    def test_arns_use_the_events_partition(self):
        raw = event("PutBucketPolicy", "s3.amazonaws.com", {"bucketName": "acme-logs"})
        raw["awsRegion"] = "cn-north-1"
        self.assertEqual(parse_event(raw).resource, "arn:aws-cn:s3:::acme-logs")

    def test_iam_is_read_from_the_partitions_iam_region(self):
        queries = plan_queries(["cn-north-1"])
        self.assertIn(("cn-north-1", "PutRolePolicy"), queries)
        self.assertNotIn(("us-east-1", "PutRolePolicy"), queries)


class QueryPlanTests(unittest.TestCase):
    def test_one_lookup_per_tracked_event_name(self):
        queries = plan_queries(["eu-west-1"])
        self.assertEqual(
            len(queries), len(IAM_EVENTS) + len(EC2_EVENTS) + len(S3_EVENTS)
        )
        self.assertEqual({region for region, name in queries if name in IAM_EVENTS}, {"us-east-1"})
        self.assertEqual({region for region, name in queries if name in S3_EVENTS}, {"eu-west-1"})

    def test_several_regions_read_iam_once(self):
        queries = plan_queries(["eu-west-1", "ap-south-1"])
        iam = [query for query in queries if query[1] in IAM_EVENTS]
        self.assertEqual(len(iam), len(IAM_EVENTS))
        for region in ("eu-west-1", "ap-south-1"):
            self.assertIn((region, "PutBucketPolicy"), queries)

    def test_duplicate_regions_are_collapsed(self):
        self.assertEqual(plan_queries(["eu-west-1", "eu-west-1"]), plan_queries(["eu-west-1"]))


class FakeCloudTrail:
    """Installs fake boto3/botocore modules that serve canned LookupEvents pages."""

    def __init__(self, data=None, error=None):
        self.data = data or {}
        self.error = error
        self.calls = []

    def modules(self):
        outer = self

        class ClientError(Exception):
            pass

        class BotoCoreError(Exception):
            pass

        class Client:
            def __init__(self, region):
                self.region = region

            def lookup_events(self, **kwargs):
                attribute = kwargs["LookupAttributes"][0]
                outer.calls.append((self.region, attribute["AttributeKey"], attribute["AttributeValue"]))
                if outer.error is not None:
                    raise ClientError("AccessDenied")
                pages = outer.data.get((self.region, attribute["AttributeValue"]), [])
                index = int(kwargs.get("NextToken") or 0)
                page = pages[index] if index < len(pages) else []
                response = {
                    "Events": [
                        {"CloudTrailEvent": e if isinstance(e, str) else json.dumps(e)}
                        for e in page
                    ]
                }
                if index + 1 < len(pages):
                    response["NextToken"] = str(index + 1)
                return response

        class Session:
            def __init__(self, profile_name=None):
                self.profile_name = profile_name

            def client(self, name, region_name=None, config=None):
                return Client(region_name)

        boto3 = types.ModuleType("boto3")
        boto3.Session = Session
        botocore = types.ModuleType("botocore")
        config = types.ModuleType("botocore.config")
        config.Config = lambda **kwargs: kwargs
        exceptions = types.ModuleType("botocore.exceptions")
        exceptions.ClientError = ClientError
        exceptions.BotoCoreError = BotoCoreError
        return {
            "boto3": boto3,
            "botocore": botocore,
            "botocore.config": config,
            "botocore.exceptions": exceptions,
        }

    def fetch(self, region="eu-west-1", **kwargs):
        start = datetime(2026, 10, 31, 9, 0, tzinfo=timezone.utc)
        end = datetime(2026, 10, 31, 11, 0, tzinfo=timezone.utc)
        with patch.dict(sys.modules, self.modules()):
            return fetch_changes(start, end, region, **kwargs)


def numbered_event(number, name="PutBucketPolicy", source="s3.amazonaws.com"):
    raw = event(name, source, {"bucketName": f"bucket-{number}"})
    raw["eventID"] = f"id-{number}"
    return raw


class FetchChangesTests(unittest.TestCase):
    def test_looks_events_up_by_name_never_by_source(self):
        fake = FakeCloudTrail()
        changes, warnings = fake.fetch()
        self.assertEqual(changes, [])
        self.assertEqual(warnings, [])
        self.assertEqual({key for _, key, _ in fake.calls}, {"EventName"})
        self.assertEqual(len(fake.calls), len(IAM_EVENTS) + len(EC2_EVENTS) + len(S3_EVENTS))

    def test_follows_pagination(self):
        fake = FakeCloudTrail(
            {("eu-west-1", "PutBucketPolicy"): [[numbered_event(1)], [numbered_event(2)]]}
        )
        changes, _ = fake.fetch()
        self.assertEqual(sorted(c.event_id for c in changes), ["id-1", "id-2"])

    def test_duplicate_event_ids_are_dropped(self):
        fake = FakeCloudTrail(
            {("eu-west-1", "PutBucketPolicy"): [[numbered_event(1), numbered_event(1)]]}
        )
        changes, _ = fake.fetch()
        self.assertEqual(len(changes), 1)

    def test_malformed_events_are_counted(self):
        fake = FakeCloudTrail(
            {("eu-west-1", "PutBucketPolicy"): [["{not json", numbered_event(1)]]}
        )
        changes, warnings = fake.fetch()
        self.assertEqual(len(changes), 1)
        self.assertEqual(warnings, ["Skipped 1 malformed CloudTrail event(s)."])

    def test_event_cap_warns_and_keeps_the_malformed_count(self):
        fake = FakeCloudTrail(
            {
                ("us-east-1", "AttachGroupPolicy"): [["{not json"]],
                ("eu-west-1", "PutBucketPolicy"): [[numbered_event(1), numbered_event(2)]],
            }
        )
        changes, warnings = fake.fetch(max_events=1)
        self.assertEqual(len(changes), 1)
        self.assertTrue(any("event cap (1) reached" in w and "later lookup" in w for w in warnings))
        self.assertTrue(any("malformed" in w for w in warnings))

    def test_results_are_sorted_by_time(self):
        late = numbered_event(1)
        late["eventTime"] = "2026-10-31T10:30:00Z"
        early = numbered_event(2)
        early["eventTime"] = "2026-10-31T09:30:00Z"
        fake = FakeCloudTrail({("eu-west-1", "PutBucketPolicy"): [[late, early]]})
        changes, _ = fake.fetch()
        self.assertEqual([c.event_id for c in changes], ["id-2", "id-1"])

    def test_several_regions_are_all_read(self):
        fake = FakeCloudTrail(
            {
                ("eu-west-1", "PutBucketPolicy"): [[numbered_event(1)]],
                ("ap-south-1", "PutBucketPolicy"): [[numbered_event(2)]],
            }
        )
        changes, _ = fake.fetch(region=["eu-west-1", "ap-south-1"])
        self.assertEqual(sorted(c.event_id for c in changes), ["id-1", "id-2"])

    def test_aws_errors_become_cloudtrail_errors(self):
        with self.assertRaises(CloudTrailError) as caught:
            FakeCloudTrail(error=True).fetch()
        self.assertIn("CloudTrail lookup failed", str(caught.exception))

    def test_missing_boto3_is_a_clear_error(self):
        with patch.dict(sys.modules, {"boto3": None}):
            with self.assertRaises(CloudTrailError) as caught:
                fetch_changes(
                    datetime(2026, 10, 31, tzinfo=timezone.utc),
                    datetime(2026, 11, 1, tzinfo=timezone.utc),
                    "us-east-1",
                )
        self.assertIn("boto3", str(caught.exception))

    def test_empty_region_list_is_rejected(self):
        with self.assertRaises(CloudTrailError):
            FakeCloudTrail().fetch(region=[])


if __name__ == "__main__":
    unittest.main()
