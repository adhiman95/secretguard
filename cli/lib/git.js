const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');
const { scanContent } = require('./scanner');

function isGitRepo(dir) {
  try { execSync('git rev-parse --is-inside-work-tree', { cwd: dir, stdio: 'pipe' }); return true; }
  catch { return false; }
}

function getGitRoot() {
  try { return execSync('git rev-parse --show-toplevel', { encoding: 'utf8', stdio: 'pipe' }).trim(); }
  catch { return null; }
}

// Audit full git history — unique differentiator: scans ALL commits
function auditHistory(options = {}) {
  const root = getGitRoot();
  if (!root) throw new Error('Not inside a git repository');

  const maxCommits = options.maxCommits || 500;
  const since = options.since || '';

  let logCmd = `git log --oneline --format="%H %s" -n ${maxCommits}`;
  if (since) logCmd += ` --since="${since}"`;

  // Get full metadata: hash, author name, author email, timestamp, subject
  const logFull = execSync(
    `git log --format="%H\x1f%an\x1f%ae\x1f%ai\x1f%s" -n ${maxCommits}${since ? ` --since="${since}"` : ''}`,
    { encoding: 'utf8', cwd: root }
  ).trim().split('\n').filter(Boolean);

  const allFindings = [];
  const seen = new Set();

  for (const line of logFull) {
    const [hash, authorName, authorEmail, timestamp, ...msgParts] = line.split('\x1f');
    const msg = msgParts.join(' ');

    let diff;
    try {
      diff = execSync(`git show ${hash} --unified=0 --format=""`, { encoding: 'utf8', cwd: root, maxBuffer: 10 * 1024 * 1024 });
    } catch { continue; }

    const fileBlocks = diff.split(/^diff --git /m).slice(1);
    for (const block of fileBlocks) {
      const fileMatch = block.match(/^a\/(.+?) b\//);
      const filePath = fileMatch ? fileMatch[1] : 'unknown';
      let lineNum = 1;

      for (const line of block.split('\n')) {
        const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
        if (hunkMatch) { lineNum = parseInt(hunkMatch[1]); continue; }
        if (line.startsWith('+') && !line.startsWith('+++')) {
          const content = line.substring(1);
          const found = scanContent(content, filePath, {});
          for (const f of found) {
            f.line = lineNum;
            f.commit = hash.substring(0, 8);
            f.commitFull = hash;
            f.commitMsg = msg;
            f.authorName = authorName;
            f.authorEmail = authorEmail;
            f.timestamp = timestamp;
            const dedupeKey = `${f.ruleId}:${f.rawMatch}`;
            if (!seen.has(dedupeKey)) {
              seen.add(dedupeKey);
              allFindings.push(f);
            }
          }
          lineNum++;
        } else if (!line.startsWith('-')) {
          lineNum++;
        }
      }
    }
  }

  return { findings: allFindings, scannedCommits: logFull.length };
}

// Install pre-commit + post-commit hooks
function installHook(dir) {
  const hooksDir = path.join(dir || '.', '.git', 'hooks');
  if (!fs.existsSync(hooksDir)) {
    throw new Error('.git/hooks directory not found — are you in a git repo?');
  }

  // Pre-commit: block commits containing secrets
  const preCommitPath = path.join(hooksDir, 'pre-commit');
  const preCommitContent = `#!/bin/sh
# SecretGuard pre-commit hook
# Auto-installed by: secretguard hook install

if ! command -v secretguard >/dev/null 2>&1; then
  echo "[SecretGuard] CLI not found — skipping scan (install: npm i -g secretguard)"
  exit 0
fi

secretguard scan --staged --fail-on=critical,high
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "  Commit blocked by SecretGuard."
  echo "  Fix secrets above, then: git commit"
  echo "  To bypass (TEAM WILL BE NOTIFIED): git commit --no-verify"
  echo ""
fi

exit $EXIT_CODE
`;
  fs.writeFileSync(preCommitPath, preCommitContent, { mode: 0o755 });

  // Post-commit: catch --no-verify bypasses by scanning the just-committed diff
  const postCommitPath = path.join(hooksDir, 'post-commit');
  const postCommitContent = `#!/bin/sh
# SecretGuard post-commit bypass detector
# Auto-installed by: secretguard hook install
# Catches secrets committed via --no-verify

if ! command -v secretguard >/dev/null 2>&1; then
  exit 0
fi

secretguard scan --last-commit --fail-on=critical,high --quiet 2>/dev/null
if [ $? -ne 0 ]; then
  echo ""
  echo "  ╔═══════════════════════════════════════════════════╗"
  echo "  ║  WARNING: Secret committed to git history!        ║"
  echo "  ║  Team has been notified. Rotate keys immediately. ║"
  echo "  ╚═══════════════════════════════════════════════════╝"
  echo ""
  secretguard scan --last-commit --fail-on=critical,high 2>/dev/null
fi
exit 0
`;
  fs.writeFileSync(postCommitPath, postCommitContent, { mode: 0o755 });

  return preCommitPath;
}

function uninstallHook(dir) {
  const hookPath = path.join(dir || '.', '.git', 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) throw new Error('No pre-commit hook found');
  const content = fs.readFileSync(hookPath, 'utf8');
  if (!content.includes('SecretGuard')) throw new Error('Hook not managed by SecretGuard — not removing');
  fs.unlinkSync(hookPath);
  return hookPath;
}

// Generate CI config snippets
function getCITemplate(ci) {
  const templates = {
    'github-actions': `# .github/workflows/secretguard.yml
name: Secret Scan
on: [push, pull_request]

jobs:
  secretguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install SecretGuard
        run: npm install -g secretguard

      - name: Scan for secrets
        run: secretguard scan . --fail-on=critical,high --format=sarif --output=secretguard.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secretguard.sarif
`,
    'gitlab-ci': `# Add to your .gitlab-ci.yml
secret-scan:
  image: node:20-alpine
  stage: test
  script:
    - npm install -g secretguard
    - secretguard scan . --fail-on=critical,high
  only:
    - merge_requests
    - main
`,
    'pre-commit-config': `# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretguard
        name: SecretGuard Secret Scan
        entry: secretguard scan --staged --fail-on=critical,high
        language: node
        additional_dependencies: [secretguard]
        pass_filenames: false
`
  };

  return templates[ci] || Object.entries(templates).map(([k, v]) => `\n### ${k}\n\`\`\`yaml\n${v}\`\`\``).join('\n');
}

module.exports = { isGitRepo, getGitRoot, auditHistory, installHook, uninstallHook, getCITemplate };
