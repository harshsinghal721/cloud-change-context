import unittest

from cloud_change_context.cloudtrail import parse_event


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


if __name__ == "__main__":
    unittest.main()
