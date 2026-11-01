# Contributing

Thanks for helping improve Cloud Change Context. Bug reports, focused fixes, and narrowly scoped feature proposals are welcome.

## Before opening an issue

- Search existing issues for the same problem or proposal.
- For bugs, include the command used, expected behavior, actual behavior, Python version, and operating system.
- Remove AWS account IDs, resource names, tokens, credentials, and other sensitive values from logs or examples.
- Report security vulnerabilities privately using the process in [SECURITY.md](SECURITY.md), not in a public issue.

## Development setup

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

On Windows PowerShell, activate the environment with `\.venv\Scripts\Activate.ps1`.

The unit tests are intended to run without AWS or GitHub credentials. Keep cloud and GitHub access read-only, and avoid adding live-service calls to unit tests.

## Pull requests

- Keep each change focused and explain the user-visible behavior.
- Add or update tests for behavior changes.
- Update the README or docs when usage, permissions, matching rules, or limitations change.
- Preserve the read-only cloud behavior and the rule that `matched` is evidence, not approval.
- Never include real credentials, private customer data, or unredacted cloud reports.

GitHub Actions runs the unit test suite on pull requests.
