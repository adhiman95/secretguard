// Each pattern has: id, name, severity, regex, entropy threshold,
// verify function name (optional), remediation steps

const PATTERNS = [
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    severity: 'critical',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    entropy: 0, // prefix AKIA is precise enough; entropy on 20-char uppercase string unreliable
    verifier: 'aws',
    impact: 'Full AWS account access depending on IAM policy — S3 data exfiltration, EC2 spin-up for crypto mining, RDS access, cost fraud. Average breach cost: $1.5M (IBM 2024).',
    remediate: [
      'Go to AWS Console → IAM → Users → Security credentials',
      'Deactivate this access key immediately',
      'Create a new key pair',
      'Store in environment variable: export AWS_ACCESS_KEY_ID=<new-key>',
      'Run: aws iam delete-access-key --access-key-id <old-key>'
    ]
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    severity: 'critical',
    pattern: /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|aws[_\-.]?secret)\s*[=:]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    entropy: 4.5,
    verifier: 'aws',
    remediate: [
      'Rotate immediately via AWS Console → IAM → Security credentials',
      'Never commit .aws/credentials — add to .gitignore',
      'Use AWS Secrets Manager or environment variables instead'
    ]
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    severity: 'critical',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    entropy: 0, // distinctive gh*_ prefix makes regex precise
    verifier: 'github',
    impact: 'Read/write access to all repos the token owner can access. Attacker can clone private code, push malicious commits, steal CI/CD secrets, or pivot to cloud credentials stored in repo settings.',
    remediate: [
      'Go to GitHub → Settings → Developer settings → Personal access tokens',
      'Delete or regenerate this token immediately',
      'Use: export GITHUB_TOKEN=<new-token> or store in .env (gitignored)',
      'Consider using GitHub Actions secrets for CI workflows'
    ]
  },
  {
    id: 'github-oauth',
    name: 'GitHub OAuth Token',
    severity: 'critical',
    pattern: /gho_[A-Za-z0-9_]{36}/g,
    entropy: 0,
    verifier: 'github',
    remediate: [
      'Revoke OAuth token at GitHub → Settings → Applications',
      'Re-authenticate your application to get a new token'
    ]
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    severity: 'critical',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    entropy: 0,
    verifier: 'google',
    remediate: [
      'Go to Google Cloud Console → APIs & Services → Credentials',
      'Delete this API key and create a new one',
      'Restrict new key to specific APIs and IP ranges',
      'Store in environment variable: GOOGLE_API_KEY'
    ]
  },
  {
    id: 'stripe-secret',
    name: 'Stripe Secret Key',
    severity: 'critical',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    entropy: 0,
    verifier: 'stripe',
    impact: 'Full access to Stripe account: create charges on customer cards, exfiltrate all payment data, issue refunds, create payouts to attacker bank account, access PII of all customers.',
    remediate: [
      'Go to Stripe Dashboard → Developers → API keys',
      'Roll (rotate) this key immediately',
      'Store as environment variable: STRIPE_SECRET_KEY',
      'Check Stripe logs for any unauthorized charges'
    ]
  },
  {
    id: 'stripe-publishable',
    name: 'Stripe Publishable Key',
    severity: 'medium',
    pattern: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    entropy: 0,
    remediate: [
      'Publishable keys are less sensitive but still rotate if in private repo',
      'Store as environment variable: STRIPE_PUBLISHABLE_KEY'
    ]
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    severity: 'critical',
    pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,
    entropy: 0,
    verifier: 'slack',
    remediate: [
      'Go to api.slack.com/apps → Your App → OAuth & Permissions',
      'Revoke token and reinstall the app',
      'Store as environment variable: SLACK_TOKEN'
    ]
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    severity: 'high',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    entropy: 3.5,
    remediate: [
      'Go to Slack App → Incoming Webhooks → Revoke old URL',
      'Generate new webhook and update environment variable'
    ]
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token',
    severity: 'high',
    pattern: /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*/g,
    entropy: 4.0,
    remediate: [
      'Invalidate token by rotating the signing secret',
      'Change JWT_SECRET in your environment variables',
      'If stateful: add token to blocklist immediately'
    ]
  },
  {
    id: 'private-key',
    name: 'Private Key (PEM)',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    entropy: 0,
    impact: 'Allows impersonation of server/user, decryption of TLS traffic, SSH access to all servers that trust this key. If code-signing key: attacker can sign malicious releases as your org.',
    remediate: [
      'Revoke any certificates signed by this key',
      'Generate new key pair: ssh-keygen -t ed25519 -C "your@email"',
      'Store private keys ONLY in secure vaults (HashiCorp Vault, AWS Secrets Manager)',
      'Never commit private keys — add *.pem, *.key to .gitignore'
    ]
  },
  {
    id: 'password-hardcoded',
    name: 'Hardcoded Password',
    severity: 'high',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{6,})["']/gim,
    entropy: 3.0,
    remediate: [
      'Move to environment variable: PASSWORD=<value> in .env',
      'Add .env to .gitignore',
      'Use a secrets manager for production credentials',
      'Change the password if it was ever committed'
    ]
  },
  {
    id: 'db-connection-string',
    name: 'Database Connection String',
    severity: 'critical',
    pattern: /(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis|amqp):\/\/[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+/gi,
    entropy: 0,
    impact: 'Direct database access — dump all tables, PII, passwords, payment data. Drop tables. Use DB as pivot into internal network. GDPR/HIPAA breach exposure.',
    remediate: [
      'Rotate database password immediately',
      'Move connection string to environment variable: DATABASE_URL',
      'Audit database access logs for unauthorized queries',
      'Restrict DB network access to known IPs'
    ]
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    severity: 'critical',
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    entropy: 0,
    remediate: [
      'Go to SendGrid → Settings → API Keys → Delete this key',
      'Check sending logs for unauthorized emails',
      'Create new key with minimum required permissions'
    ]
  },
  {
    id: 'twilio-key',
    name: 'Twilio API Key',
    severity: 'critical',
    pattern: /SK[0-9a-fA-F]{32}/g,
    entropy: 0,
    remediate: [
      'Go to Twilio Console → Account → API Keys → Revoke key',
      'Check call/SMS logs for abuse'
    ]
  },
  {
    id: 'generic-api-key',
    name: 'Generic API Key Assignment',
    severity: 'high',
    pattern: /(?:api[_\-.]?key|apikey|api[_\-.]?secret|access[_\-.]?token)\s*[=:]\s*["']([A-Za-z0-9\-_\/+=]{20,80})["']/gi,
    entropy: 3.5,
    remediate: [
      'Move to environment variable',
      'Add .env to .gitignore',
      'Rotate the key in the respective service dashboard'
    ]
  },
  {
    id: 'generic-secret',
    name: 'Generic Secret Assignment',
    severity: 'medium',
    pattern: /(?:secret|token|auth[_\-.]?key)\s*[=:]\s*["']([A-Za-z0-9\-_\/+=]{16,80})["']/gi,
    entropy: 3.8,
    remediate: [
      'Move to environment variable or secrets manager',
      'Rotate the value in the respective service'
    ]
  },
  {
    id: 'npm-token',
    name: 'npm Access Token',
    severity: 'critical',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    entropy: 0,
    remediate: [
      'Go to npmjs.com → Access Tokens → Delete this token',
      'Generate new token with minimum required scope',
      'Store as NPM_TOKEN environment variable'
    ]
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    severity: 'critical',
    pattern: /sk-ant-[A-Za-z0-9\-_]{40,}/g,
    entropy: 0,
    remediate: [
      'Go to console.anthropic.com → API Keys → Delete this key',
      'Generate new key',
      'Store as ANTHROPIC_API_KEY environment variable'
    ]
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    severity: 'critical',
    pattern: /sk-(?:proj-)?[A-Za-z0-9]{48,}/g,
    entropy: 0,
    remediate: [
      'Go to platform.openai.com → API keys → Revoke this key',
      'Create new key',
      'Store as OPENAI_API_KEY environment variable'
    ]
  },

  // ── 2023 Lasso/HuggingFace breach — 1,500+ tokens exposed on GitHub
  {
    id: 'huggingface-token',
    name: 'HuggingFace API Token',
    severity: 'critical',
    pattern: /hf_[A-Za-z0-9]{34,}/g,
    entropy: 0,
    remediate: [
      'Go to huggingface.co → Settings → Access Tokens → Revoke token',
      'Check which orgs the token had access to (Meta Llama, etc.)',
      'Rotate any models or datasets that may have been tampered with',
      'Store as HUGGINGFACE_TOKEN environment variable'
    ]
  },

  // ── 2023 Mercedes breach — GitHub token gave full internal GitHub Enterprise access
  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Access Token',
    severity: 'critical',
    pattern: /glpat-[A-Za-z0-9\-_]{20}/g,
    entropy: 0,
    remediate: [
      'Go to GitLab → User Settings → Access Tokens → Revoke',
      'Audit all repositories the token had access to',
      'Check audit logs for unauthorized clones or pushes',
      'Store as GITLAB_TOKEN environment variable'
    ]
  },

  // ── 2024 Vercel new token format (introduced with secret scanning partnership)
  {
    id: 'vercel-token',
    name: 'Vercel API Token',
    severity: 'critical',
    pattern: /(?:vercel[_\-.]?token|VERCEL_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{24,})["']?/gi,
    entropy: 3.5,
    remediate: [
      'Go to vercel.com → Settings → Tokens → Delete token',
      'Generate new token with minimum required scope',
      'Store as VERCEL_TOKEN environment variable'
    ]
  },

  // ── 2024 Azure / Microsoft tokens (Treasury-style attacks target cloud)
  {
    id: 'azure-storage-key',
    name: 'Azure Storage Account Key',
    severity: 'critical',
    pattern: /AccountKey=[A-Za-z0-9+/]{88}==/g,
    entropy: 4.5,
    remediate: [
      'Go to Azure Portal → Storage Account → Access keys → Rotate key',
      'Use Managed Identity instead of storage account keys',
      'Store in Azure Key Vault, not environment variables'
    ]
  },
  {
    id: 'azure-sas-token',
    name: 'Azure SAS Token',
    severity: 'high',
    pattern: /(?:se|sv|sig)=[A-Za-z0-9%+/]{20,}&/g,
    entropy: 3.5,
    remediate: [
      'SAS tokens have expiry — check if still valid',
      'Revoke by rotating the storage account key it was derived from',
      'Use short-lived SAS tokens with minimum permissions'
    ]
  },

  // ── 2024/2025 Databricks tokens (major enterprise data breach vector)
  {
    id: 'databricks-token',
    name: 'Databricks API Token',
    severity: 'critical',
    pattern: /dapi[a-f0-9]{32}/g,
    entropy: 0,
    remediate: [
      'Go to Databricks workspace → User Settings → Developer → Access tokens → Revoke',
      'Check cluster access logs for unauthorized jobs',
      'Store as DATABRICKS_TOKEN environment variable'
    ]
  },

  // ── 2025 AI model provider keys (AI commit leak rate 2x baseline per Snyk 2025 report)
  {
    id: 'cohere-key',
    name: 'Cohere API Key',
    severity: 'critical',
    pattern: /[A-Za-z0-9]{40}(?=.*cohere)/gi,
    entropy: 4.0,
    remediate: [
      'Go to dashboard.cohere.com → API Keys → Revoke',
      'Generate new key',
      'Store as COHERE_API_KEY environment variable'
    ]
  },
  {
    id: 'replicate-token',
    name: 'Replicate API Token',
    severity: 'critical',
    pattern: /r8_[A-Za-z0-9]{40}/g,
    entropy: 0,
    remediate: [
      'Go to replicate.com → Account → API tokens → Delete',
      'Generate new token',
      'Store as REPLICATE_API_TOKEN environment variable'
    ]
  },

  // ── 2026 CISA AWS GovCloud leak — AWS keys used as sync mechanism
  {
    id: 'aws-session-token',
    name: 'AWS Session Token',
    severity: 'critical',
    pattern: /(?:aws[_\-.]?session[_\-.]?token|AWS_SESSION_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    entropy: 4.5,
    remediate: [
      'Session tokens expire automatically — but revoke parent IAM credentials immediately',
      'If using EC2/Lambda — switch to IAM roles, never hardcode session tokens',
      'Run: aws sts get-caller-identity to verify what the token can access'
    ]
  },

  // ── Supply chain: Docker Hub tokens (seen in CI pipeline breaches)
  {
    id: 'docker-auth',
    name: 'Docker Hub Auth Token',
    severity: 'high',
    pattern: /(?:docker[_\-.]?(?:token|password|auth|hub[_\-.]?token))\s*[=:]\s*["']([A-Za-z0-9\-_\.]{20,})["']/gi,
    entropy: 3.5,
    remediate: [
      'Go to hub.docker.com → Account Settings → Security → Delete access token',
      'Rotate Docker Hub password',
      'Use DOCKER_TOKEN environment variable in CI'
    ]
  },

  // ── PostHog, Doppler — added to GitHub secret scanning in 2025
  {
    id: 'posthog-key',
    name: 'PostHog API Key',
    severity: 'high',
    pattern: /phc_[A-Za-z0-9]{43}/g,
    entropy: 0,
    remediate: [
      'Go to PostHog → Project Settings → API Keys → Revoke',
      'Rotate project API key'
    ]
  },
  {
    id: 'doppler-token',
    name: 'Doppler Service Token',
    severity: 'critical',
    pattern: /dp\.st\.[A-Za-z0-9_\-]{44}/g,
    entropy: 0,
    remediate: [
      'Go to Doppler → Project → Config → Service Tokens → Revoke',
      'This token exposes ALL your Doppler secrets — rotate immediately'
    ]
  },

  // ── 2022/2023 Okta breaches (Lapsus$ group — Okta token gave SSO admin access to hundreds of orgs)
  {
    id: 'okta-token',
    name: 'Okta API Token',
    severity: 'critical',
    pattern: /SSWS[A-Za-z0-9_\-]{36,}/g,
    entropy: 0,
    remediate: [
      'Go to Okta Admin → Security → API → Tokens → Revoke this token',
      'Audit Okta system log for unauthorized SSO logins',
      'Okta tokens grant admin access to ALL SSO apps — treat as critical'
    ]
  },

  // ── DigitalOcean tokens (common for indie devs and startups)
  {
    id: 'digitalocean-token',
    name: 'DigitalOcean Personal Access Token',
    severity: 'critical',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    entropy: 0,
    remediate: [
      'Go to DigitalOcean → API → Tokens → Revoke token',
      'Audit Droplet access logs for unauthorized SSH or API calls',
      'Store as DIGITALOCEAN_TOKEN environment variable'
    ]
  },

  // ── Shopify access tokens (e-commerce platform, PCI-scope data)
  {
    id: 'shopify-token',
    name: 'Shopify Access Token',
    severity: 'critical',
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    entropy: 0,
    remediate: [
      'Go to Shopify Admin → Apps → Manage → Delete private app or revoke token',
      'Audit for unauthorized orders, customer data access, or webhook changes',
      'Store as SHOPIFY_ACCESS_TOKEN environment variable'
    ]
  },

  // ── Shopify shared secret (app credentials)
  {
    id: 'shopify-shared-secret',
    name: 'Shopify Shared Secret',
    severity: 'high',
    pattern: /shpss_[a-fA-F0-9]{32}/g,
    entropy: 0,
    remediate: [
      'Rotate shared secret in Shopify Partners → App → Credentials',
      'Store as SHOPIFY_API_SECRET environment variable'
    ]
  },

  // ── Firebase/GCP service account (exposed via Internet Archive Oct 2024, many startups)
  {
    id: 'firebase-service-account',
    name: 'Firebase/GCP Service Account Key',
    severity: 'critical',
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key_id"\s*:\s*"([a-f0-9]{40})"/gm,
    entropy: 0,
    remediate: [
      'Go to GCP Console → IAM & Admin → Service Accounts → Delete this key',
      'Generate new service account key with minimum IAM permissions',
      'Use Workload Identity Federation instead of service account JSON files',
      'Store key file OUTSIDE git repo and reference via GOOGLE_APPLICATION_CREDENTIALS'
    ]
  },

  // ── Datadog API key (enterprise monitoring — common breach vector in 2024)
  {
    id: 'datadog-api-key',
    name: 'Datadog API Key',
    severity: 'high',
    pattern: /(?:DD_API_KEY|datadog[_\-.]?api[_\-.]?key)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    entropy: 3.5,
    remediate: [
      'Go to Datadog → Organization Settings → API Keys → Revoke',
      'Create new key and update DD_API_KEY environment variable'
    ]
  },

  // ── Heroku API key (used in CI/CD pipelines, leaked in GitHub Actions logs)
  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    severity: 'critical',
    pattern: /(?:HEROKU_API_KEY|heroku[_\-.]?(?:api[_\-.]?)?key)\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    entropy: 0,
    remediate: [
      'Go to heroku.com → Account Settings → API Key → Regenerate',
      'Update HEROKU_API_KEY in all CI/CD pipelines',
      'Audit Heroku app deployments and config vars for unauthorized changes'
    ]
  },

  // ── CircleCI tokens (Jan 2023 breach — all secrets in CircleCI must be rotated)
  {
    id: 'circleci-token',
    name: 'CircleCI API Token',
    severity: 'critical',
    pattern: /(?:CIRCLE_TOKEN|circleci[_\-.]?(?:api[_\-.]?)?token)\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    entropy: 0,
    remediate: [
      'Go to CircleCI → User Settings → Personal API Tokens → Delete',
      'CRITICAL: The Jan 2023 CircleCI breach means any token committed pre-2023 is compromised',
      'Rotate ALL secrets that were stored in CircleCI environment variables',
      'Store as CIRCLE_TOKEN environment variable'
    ]
  },

  // ── Linear API key (project management — leaked gives read/write to all issues)
  {
    id: 'linear-api-key',
    name: 'Linear API Key',
    severity: 'high',
    pattern: /lin_api_[A-Za-z0-9]{36,}/g,
    entropy: 0,
    remediate: [
      'Go to Linear → Settings → API → Personal API keys → Revoke',
      'Generate new key and store as LINEAR_API_KEY environment variable'
    ]
  },

  // ── Supabase service role key (full DB bypass — RLS ignored)
  {
    id: 'supabase-service-key',
    name: 'Supabase Service Role Key',
    severity: 'critical',
    pattern: /(?:SUPABASE_SERVICE[_\-.]?(?:ROLE[_\-.]?)?KEY|supabase[_\-.]?service[_\-.]?(?:role[_\-.]?)?key)\s*[=:]\s*["']?(eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*)["']?/gi,
    entropy: 0,
    remediate: [
      'Go to Supabase → Project Settings → API → Rotate service role key',
      'Service role key BYPASSES Row Level Security — any exposure = full DB access',
      'Never use service role key in frontend code or committed config files'
    ]
  },

  // ── HashiCorp Vault tokens (used in enterprise, often leaked in CI logs)
  {
    id: 'hashicorp-vault-token',
    name: 'HashiCorp Vault Token',
    severity: 'critical',
    pattern: /(?:hvs|hvb|hvr)\.[A-Za-z0-9_\-]{90,}/g,
    entropy: 0,
    remediate: [
      'Run: vault token revoke <token>',
      'Audit vault audit logs for unauthorized access',
      'Use short-TTL tokens and vault agent for CI/CD'
    ]
  },

  // ── Cloudflare API tokens (infrastructure-level access)
  {
    id: 'cloudflare-token',
    name: 'Cloudflare API Token',
    severity: 'critical',
    pattern: /(?:cloudflare[_\-.]?(?:api[_\-.]?)?token|CF_API_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_\-]{40})["']?/gi,
    entropy: 4.5,
    remediate: [
      'Go to Cloudflare → My Profile → API Tokens → Revoke',
      'Cloudflare API tokens control DNS, WAF, and routing — treat as critical'
    ]
  }
];

// Shannon entropy — filter out low-entropy false positives
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

module.exports = { PATTERNS, shannonEntropy };
