# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories for this repository. Do not open a public issue with exploit details.

Include the affected version, a minimal reproduction, and the impact. Do not include live AWS credentials or GitHub tokens in the report.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Design guarantees

- **Read-only cloud access.** The only AWS API call is `cloudtrail:LookupEvents`. GitHub access is GET-only over HTTPS.
- **No automatic approval.** A matched change is correlated evidence, not an approval. The tool cannot approve or remediate anything.
- **Token stays with GitHub.** Redirects are followed only over HTTPS, and the `Authorization` header is removed if a redirect points to a different host.
- **No credential persistence.** AWS credentials use the standard credential chain. `GITHUB_TOKEN`/`GH_TOKEN` is read from the environment. Neither is written to disk or printed.
- **No raw request bodies in reports.** CloudTrail policy documents and other request payloads are not retained in the report model.
- **Fail-closed matching.** Failed or unknown deployments, ambiguous candidates, and missing evidence never produce `matched`.
- **Output sanitization.** Control characters are stripped before terminal and markdown output; markdown table characters are escaped.

## Operational notes

- Generated reports contain resource names, actors, timestamps, and GitHub links. Treat them as sensitive operational data.
- If a GitHub token is exposed, revoke it immediately and generate a replacement.
- Run with the narrowest CloudTrail lookup permission and the narrowest GitHub repository/token scope.
- The tool does not verify GitHub branch protection, required reviews, or the actual deployed configuration. Pair it with your normal change-management controls.
