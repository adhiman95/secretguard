# SecretGuard — Secret Detection

**Catches API keys, tokens, and credentials as you type — before they ever reach git.**

Most developers leak secrets by accident. A hardcoded AWS key, a Stripe token left in a config file, a GitHub PAT committed to a repo. SecretGuard stops it at the earliest possible point: your editor.

## What it does

- **Real-time scanning** — detects secrets as you type, on every save
- **44 credential patterns** — AWS, GitHub, Stripe, OpenAI, Slack, Google, HuggingFace, Shopify, Okta, CircleCI, Linear, Supabase, and more
- **Inline warnings** — red underlines on the exact secret line, visible in Problems panel
- **Status bar indicator** — shows secret count at a glance
- **Right-click to ignore** — suppress known false positives instantly

## Credential types detected

AWS keys · GitHub tokens (ghp_, ghs_, gho_) · Stripe live/test keys · OpenAI keys · Slack tokens & webhooks · Google API keys · SendGrid · Twilio · HuggingFace · npm tokens · Docker Hub · Okta · Shopify · Firebase · Supabase · DigitalOcean · Heroku · CircleCI · Linear · Datadog · Private keys (RSA/EC/PEM) · Database URLs (PostgreSQL, MySQL, MongoDB) · JWT secrets · and more

## Works best with the CLI

Install the CLI for pre-commit hooks that block secrets from entering git entirely:

```bash
npm install -g secretguard-cli
cd your-project
secretguard init
```

This installs a git hook that prevents any commit containing secrets. The VS Code extension catches them even earlier — as you type.

## Breach history this tool covers

Built from real incidents: Toyota (2023), Uber (2022), Samsung (2023), CircleCI (2023), Codecov (2021), HuggingFace (2024), Internet Archive (2024), Okta (2024). These companies lost millions because a secret ended up in code. SecretGuard catches the exact patterns involved.

## Settings

| Setting | Default | Description |
|---|---|---|
| `secretguard.enableRealtimeScan` | `true` | Scan on every save |
| `secretguard.severity` | `critical, high, medium` | Which severities to show |
| `secretguard.cliPath` | `secretguard` | Path to CLI binary |
| `secretguard.showInlineMessages` | `true` | Inline decorations on secret lines |

## Commands

- `SecretGuard: Scan Current File` — manual scan
- `SecretGuard: Scan Workspace` — full project scan
- `SecretGuard: Ignore this finding` — suppress via right-click

## Links

- [GitHub](https://github.com/adhiman95/secretguard)
- [npm CLI](https://www.npmjs.com/package/secretguard-cli)
- [Report an issue](https://github.com/adhiman95/secretguard/issues)
