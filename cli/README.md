# SecretGuard

**Stop secrets before they leak.** Pre-commit hook blocks commits containing API keys, tokens, and credentials. 44 patterns. Live API verification. Git history audit. CI/CD integration.

```
  ✖ [CRITICAL]  GitHub Personal Access Token  (ghp_****gh01)
     → githubToken: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh01'
     VERIFIED ACTIVE — token is live and will be revoked

  Commit blocked by SecretGuard. Fix secrets above, then: git commit
```

## Install

```bash
npm install -g secretguard
```

Then set up in your repo:

```bash
cd your-project
secretguard init
```

This installs the pre-commit hook, creates `.secretguardignore`, and patches `.gitignore`.

## Commands

### `secretguard scan [path]`

Scan a directory or file for secrets.

```bash
secretguard scan .
secretguard scan src/config.js
secretguard scan --staged                    # only staged files (used by pre-commit hook)
secretguard scan . --format=json             # JSON output
secretguard scan . --format=sarif --output=results.sarif   # GitHub Code Scanning
secretguard scan . --fail-on=critical,high   # exit 1 on severity match
secretguard scan . --fix                     # show remediation steps
secretguard scan . --no-verify               # skip live API verification
```

### `secretguard audit`

Scan full git commit history. Shows commit hash, author, timestamp — for org-level forensics.

```bash
secretguard audit
secretguard audit --max-commits=1000
secretguard audit --since="6 months ago"
secretguard audit --format=json
```

### `secretguard hook install | uninstall`

Manually manage the pre-commit hook.

```bash
secretguard hook install
secretguard hook uninstall
```

### `secretguard init`

One-command setup: installs hook + creates `.secretguardignore` + patches `.gitignore`.

### `secretguard fix [path]`

Show remediation steps for all detected secrets.

### `secretguard baseline`

Suppress existing findings (false positives or secrets already in rotation queue).

```bash
secretguard baseline generate .    # scan and suppress current findings
secretguard baseline status        # list suppressed findings
secretguard baseline clear         # remove baseline, re-report all
```

New findings after baseline is created will still be blocked.

### `secretguard ci [platform]`

Print CI/CD config template.

```bash
secretguard ci github-actions
secretguard ci gitlab-ci
secretguard ci pre-commit-config
```

## What it detects (44 patterns)

| Category | Patterns |
|---|---|
| AWS | Access Key, Secret Key, Session Token |
| GitHub / GitLab | PAT, OAuth, App tokens, GitLab PAT |
| Google / Firebase | API Key, GCP Service Account JSON |
| AI Providers | OpenAI, Anthropic, HuggingFace, Cohere, Replicate |
| Cloud | Azure Storage Key, Azure SAS, DigitalOcean, Heroku, Vercel, Cloudflare, Databricks |
| Payments | Stripe secret + publishable, Shopify access + shared secret |
| Communication | Slack token, Slack webhook |
| Databases | Connection strings (Postgres, MySQL, MongoDB, Redis), Supabase service key |
| DevOps | Docker Hub, CircleCI, HashiCorp Vault, Doppler, Datadog, Okta |
| Other | JWT, PEM private key, SendGrid, Twilio, npm token, PostHog, Linear |

All prefix-specific patterns (AWS `AKIA`, GitHub `ghp_`, HuggingFace `hf_`, etc.) skip entropy checks — the prefix itself is precise. Generic patterns use Shannon entropy to filter low-entropy false positives.

## Live API Verification

SecretGuard makes safe read-only API calls to confirm whether detected secrets are still active:

- GitHub: `GET /user`
- Slack: `auth.test`
- Stripe: `GET /v1/charges`
- Google: Maps Geocoding API

Use `--no-verify` to skip. Verification results show inline:

```
VERIFIED ACTIVE — revoke immediately
✓ Verified inactive (key revoked or invalid)
```

## Notifications

Set environment variables to alert your team when secrets are detected:

```bash
# Slack
export SECRETGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Custom webhook (e.g. PagerDuty, internal tooling)
export SECRETGUARD_WEBHOOK_URL=https://your-server.com/alerts
export SECRETGUARD_WEBHOOK_TOKEN=optional-bearer-token
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install SecretGuard
  run: npm install -g secretguard

- name: Scan for secrets
  run: secretguard scan . --fail-on=critical,high --format=sarif --output=secretguard.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: secretguard.sarif
```

SARIF output integrates with GitHub Code Scanning for inline PR annotations.

### GitLab CI

```yaml
secret-scan:
  image: node:20-alpine
  script:
    - npm install -g secretguard
    - secretguard scan . --fail-on=critical,high
  only:
    - merge_requests
    - main
```

## Ignore patterns

Create `.secretguardignore` to skip files:

```
# paths/patterns to skip
test/fixtures/
*.example
*.sample
mock-data/
```

The pre-commit hook respects `.gitignore` automatically. Binary files, `node_modules`, `dist`, `.next`, and other build dirs are always skipped.

## Philosophy

SecretGuard is **prevention-first**, not detection-after-the-fact:

1. Pre-commit hook blocks the commit → developer must fix the secret before pushing
2. CI/CD scan catches anything that slipped through (e.g. `--no-verify` bypass)
3. `secretguard audit` scans history for secrets already in git — rotate those immediately
4. Slack/webhook notifications alert the team in real time

The output never includes the raw secret value. Matches are masked: `ghp_****YZ01`.

## Breach coverage

Patterns and remediations built from incidents including:
Toyota GitHub token (2023), HuggingFace/Lasso token dump (2023), Uber AWS+Stripe (2022), LastPass AWS (2022), Codecov CI (2021), CircleCI breach (2023), Samsung GitLab (2022), CISA AWS GovCloud (2026), Internet Archive config leak (2024), US Treasury/BeyondTrust OAuth (2024).

## License

MIT
