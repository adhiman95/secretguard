# SecretGuard

**Stop secrets before they leak.** Pre-commit hook blocks commits containing API keys, tokens, and credentials. 44 patterns. Live API verification. Git history audit. CI/CD integration.

```
  ✖ [CRITICAL]  GitHub Personal Access Token  (ghp_****gh01)
     → githubToken: 'ghp_FAKE_EXAMPLE_TOKEN_...'
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

## Quick Start

```bash
secretguard scan .                # scan current directory
secretguard scan --staged         # scan only staged files
secretguard scan --watch .       # watch mode — rescan on file save
secretguard audit                 # scan full git history
secretguard fix .                 # show remediation steps
```

## Commands

| Command | Description |
|---|---|
| `secretguard scan [path]` | Scan directory or file for secrets |
| `secretguard audit` | Scan full git commit history |
| `secretguard hook install` | Install pre-commit git hook |
| `secretguard hook uninstall` | Remove pre-commit git hook |
| `secretguard init` | One-command setup (hook + .gitignore + ignore file) |
| `secretguard fix [path]` | Show remediation steps |
| `secretguard baseline` | Suppress existing findings |
| `secretguard ci [platform]` | Print CI/CD config template |

### Scan Flags

| Flag | Description |
|---|---|
| `--staged` | Scan only git staged files |
| `--last-commit` | Scan last committed diff (catches `--no-verify` bypasses) |
| `--watch` | Watch mode — rescan on file save |
| `--fail-on=critical,high` | Exit 1 if severity matches (default: critical) |
| `--format=table\|json\|sarif` | Output format (default: table) |
| `--output=file.sarif` | Write output to file |
| `--fix` | Show remediation steps after scan |
| `--no-verify` | Skip live API verification |
| `--quiet` | Suppress banner/status messages |

## What It Detects (44 patterns)

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

## Live API Verification

SecretGuard makes safe read-only API calls to confirm whether detected secrets are still active:

- GitHub: `GET /user`
- Slack: `auth.test`
- Stripe: `GET /v1/charges`
- Google: Maps Geocoding API

```
VERIFIED ACTIVE — revoke immediately
✓ Verified inactive (key revoked or invalid)
```

Use `--no-verify` to skip (faster, works offline).

## Bypass Detection

When a developer uses `git commit --no-verify`, SecretGuard's post-commit hook scans the committed diff. If secrets are found:

1. Prints a loud `BYPASS DETECTED` warning
2. Fires Slack/webhook/email notification

```bash
secretguard scan --last-commit    # manually trigger bypass check
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

## Notifications

Set environment variables to alert your team:

```bash
# Slack
export SECRETGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Custom webhook (PagerDuty, internal tooling)
export SECRETGUARD_WEBHOOK_URL=https://your-server.com/alerts
export SECRETGUARD_WEBHOOK_TOKEN=optional-bearer-token

# Email (direct SMTP)
export SECRETGUARD_SMTP_HOST=smtp.gmail.com
export SECRETGUARD_EMAIL_TO=security@yourcompany.com
```

## VS Code Extension

Real-time secret detection in the editor. Scans as you type.

- Inline squiggles with severity levels
- Status bar indicator showing secret count
- Right-click → "SecretGuard: Ignore this finding"
- Command palette: `SecretGuard: Scan Workspace`

Install the `.vsix` from `vscode-extension/`:

```bash
code --install-extension vscode-extension/secretguard-1.0.0.vsix
```

## Dashboard

Web dashboard for monitoring scan findings across repos.

```bash
node server.js
# Open http://localhost:3000/dashboard
```

- Drag-drop JSON scan results
- Severity distribution charts
- Findings table with filters
- Bypass detection alerts

## Philosophy

SecretGuard is **prevention-first**:

1. **Pre-commit hook** — blocks commit if secrets found. Developer must fix before pushing.
2. **Post-commit bypass detection** — catches `--no-verify` commits and alerts the team.
3. **CI/CD scan** — catches anything that slipped through.
4. **History audit** — `secretguard audit` scans all commits for secrets already in git.

Raw secret values are never printed. All matches are masked: `ghp_****YZ01`.

## Project Structure

```
secretguard/
├── cli/                    # CLI tool (npm package)
│   ├── bin/secretguard.js  # Entry point
│   ├── lib/                # Core logic (scanner, patterns, reporter)
│   └── test/               # Test suite
├── vscode-extension/       # VS Code extension
│   ├── extension.js        # Extension entry point
│   └── lib/patterns.js     # 44 detection patterns
├── public/                 # Web frontend
│   ├── index.html          # Landing page
│   ├── dashboard.html      # Dashboard
│   └── docs.html           # Documentation
└── server.js               # Express API server
```

## License

MIT
