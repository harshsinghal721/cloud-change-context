import unittest

from cloud_change_context.github import validate_repo


class GitHubInputTests(unittest.TestCase):
    def test_valid_repo(self):
        validate_repo("acme/payments-infra")

    def test_rejects_path_injection(self):
        for value in ("acme", "acme/repo/extra", "../repo", "acme/..", "acme/repo?x=1"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_repo(value)


if __name__ == "__main__":
    unittest.main()
