const fs = require('fs');
const path = require('path');
const { PATTERNS, shannonEntropy } = require('./patterns');

const SKIP_DIRS = new Set(['.git', 'node_modules', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv', 'vendor', 'coverage', '.nyc_output']);
const SKIP_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz', '.pdf', '.lock', '.md', '.mdx', '.rst', '.txt']);
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB

function shouldSkipPath(filePath) {
  const parts = filePath.split(/[/\\]/);
  for (const part of parts) {
    if (SKIP_DIRS.has(part)) return true;
  }
  const ext = path.extname(filePath).toLowerCase();
  return SKIP_EXTS.has(ext);
}

function loadGitignore(dir) {
  const gitignorePath = path.join(dir, '.gitignore');
  const ignored = new Set();
  if (fs.existsSync(gitignorePath)) {
    const lines = fs.readFileSync(gitignorePath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        ignored.add(trimmed.replace(/^\//, '').replace(/\/$/, ''));
      }
    }
  }
  return ignored;
}

function isGitignored(filePath, rootDir, ignored) {
  const rel = path.relative(rootDir, filePath).replace(/\\/g, '/');
  for (const pattern of ignored) {
    if (rel === pattern || rel.startsWith(pattern + '/') || rel.endsWith('/' + pattern) || path.basename(filePath) === pattern) {
      return true;
    }
  }
  return false;
}

function walkDir(dir, rootDir, ignored, files = []) {
  let entries;
  try { entries = fs.readdirSync(dir); } catch { return files; }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    if (shouldSkipPath(fullPath)) continue;
    if (isGitignored(fullPath, rootDir, ignored)) continue;

    let stat;
    try { stat = fs.statSync(fullPath); } catch { continue; }

    if (stat.isDirectory()) {
      walkDir(fullPath, rootDir, ignored, files);
    } else if (stat.isFile() && stat.size < MAX_FILE_SIZE) {
      files.push(fullPath);
    }
  }
  return files;
}

const TEST_PATH_PATTERNS = /(?:^|[/\\])(?:test|tests|__tests__|spec|specs|fixtures?|mocks?|__mocks__|stubs?)(?:[/\\]|$)|\.(?:test|spec|fixture|mock)\.[a-z]+$/i;

function isTestFile(filePath) {
  return TEST_PATH_PATTERNS.test(filePath);
}

function scanContent(content, filePath, options = {}) {
  const findings = [];
  const lines = content.split('\n');
  const inTestFile = isTestFile(filePath);

  for (const rule of PATTERNS) {
    if (options.severity && !options.severity.includes(rule.severity)) continue;

    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const matchStr = match[0];

      // Skip very short matches
      if (matchStr.length < 8) {
        if (regex.lastIndex === match.index) regex.lastIndex++;
        continue;
      }

      // Entropy check — skip low-entropy values (likely placeholders)
      if (rule.entropy > 0) {
        // Extract the actual secret value (capture group 1 if exists, else full match)
        const secretVal = match[1] || matchStr;
        const ent = shannonEntropy(secretVal);
        if (ent < rule.entropy) {
          if (regex.lastIndex === match.index) regex.lastIndex++;
          continue;
        }
      }

      // Skip obvious test/placeholder values
      const lower = matchStr.toLowerCase();
      const PLACEHOLDER_WORDS = ['example', 'placeholder', 'your-key', 'your_key', 'your-token', 'your_token',
        'your-secret', 'your_secret', 'xxxx', '****', 'changeme', 'change-me', 'replaceme', 'replace-me',
        'enter-your', 'add-your', 'put-your', 'insert-your', '<your', '<token', '<secret', '<key', '<api'];
      if (PLACEHOLDER_WORDS.some(w => lower.includes(w)) || matchStr.includes('<') || matchStr.includes('>') || matchStr.includes('{') || matchStr.includes('}')) {
        if (regex.lastIndex === match.index) regex.lastIndex++;
        continue;
      }

      const upToMatch = content.substring(0, match.index);
      const lineNumber = upToMatch.split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Skip commented lines (but NOT //registry.example.com style npm/URL lines)
      const trimmedLine = lineContent.trim();
      const isCodeComment = (trimmedLine.startsWith('// ') || trimmedLine.startsWith('//\t') || trimmedLine === '//') ||
        trimmedLine.startsWith('# ') || trimmedLine.startsWith('#\t') || trimmedLine === '#' ||
        trimmedLine.startsWith('* ') || trimmedLine.startsWith('<!--');
      if (isCodeComment) {
        if (regex.lastIndex === match.index) regex.lastIndex++;
        continue;
      }

      const masked = maskSecret(matchStr);

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        inTestFile: inTestFile || undefined,
        file: filePath,
        line: lineNumber,
        col: match.index - (upToMatch.lastIndexOf('\n') + 1) + 1,
        match: masked,
        rawMatch: matchStr,
        lineContent: lineContent.trim().substring(0, 200),
        entropy: rule.entropy > 0 ? shannonEntropy(match[1] || matchStr).toFixed(2) : null,
        hasVerifier: !!rule.verifier,
        verifier: rule.verifier,
        remediate: rule.remediate,
        impact: rule.impact
      });

      if (regex.lastIndex === match.index) regex.lastIndex++;
    }
  }

  return findings;
}

function maskSecret(str) {
  if (str.length <= 8) return '****';
  const show = Math.min(4, Math.floor(str.length * 0.15));
  return str.substring(0, show) + '****' + str.substring(str.length - show);
}

function scanFile(filePath, options = {}) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }
  return scanContent(content, filePath, options);
}

function loadBaseline(dir) {
  const baselineFile = path.join(dir, '.secretguardbaseline');
  if (!fs.existsSync(baselineFile)) return new Set();
  try {
    const data = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
    return new Set((data.suppressions || []).map(s => s.fingerprint));
  } catch { return new Set(); }
}

function isBaselineSuppressed(finding, baseline) {
  if (!baseline.size) return false;
  const fp = Buffer.from(`${finding.file}:${finding.line}:${finding.ruleId}:${finding.match}`).toString('base64');
  return baseline.has(fp);
}

function scanDirectory(dir, options = {}) {
  const rootDir = path.resolve(dir);
  const stat = fs.statSync(rootDir, { throwIfNoEntry: false });
  if (!stat) return { findings: [], scannedFiles: 0 };

  // Single file
  if (stat.isFile()) {
    const findings = scanFile(rootDir, options);
    return { findings, scannedFiles: 1 };
  }

  const ignored = loadGitignore(rootDir);
  const baseline = loadBaseline(rootDir);
  const files = walkDir(rootDir, rootDir, ignored);
  const allFindings = [];

  for (const file of files) {
    const findings = scanFile(file, options);
    for (const f of findings) {
      if (!isBaselineSuppressed(f, baseline)) allFindings.push(f);
    }
  }

  return { findings: allFindings, scannedFiles: files.length };
}

// Scan the last committed diff (catches --no-verify bypasses via post-commit hook)
function scanLastCommit() {
  const { execSync } = require('child_process');
  let diff;
  try {
    diff = execSync('git diff HEAD~1 HEAD --unified=0', { encoding: 'utf8', stdio: 'pipe' });
  } catch {
    // First commit: diff against empty tree
    try {
      diff = execSync('git diff --unified=0 $(git hash-object -t tree /dev/null) HEAD', { encoding: 'utf8', stdio: 'pipe' });
    } catch {
      return { findings: [], scannedFiles: 0 };
    }
  }
  return parseDiffToFindings(diff, { markBypassDetected: true });
}

function scanStaged() {
  const { execSync } = require('child_process');
  let stagedContent;
  try {
    stagedContent = execSync('git diff --cached --unified=0', { encoding: 'utf8' });
  } catch {
    return { findings: [], scannedFiles: 0 };
  }

  return parseDiffToFindings(stagedContent, {});
}

function parseDiffToFindings(diff, options = {}) {
  const findings = [];
  const fileBlocks = diff.split(/^diff --git /m).slice(1);

  for (const block of fileBlocks) {
    const fileMatch = block.match(/^a\/(.+?) b\//);
    const filePath = fileMatch ? fileMatch[1] : 'unknown';
    const addedLines = [];
    let lineNum = 1;

    for (const line of block.split('\n')) {
      const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
      if (hunkMatch) { lineNum = parseInt(hunkMatch[1]); continue; }
      if (line.startsWith('+') && !line.startsWith('+++')) {
        addedLines.push({ content: line.substring(1), lineNum });
        lineNum++;
      } else if (!line.startsWith('-')) {
        lineNum++;
      }
    }

    for (const { content, lineNum: ln } of addedLines) {
      const found = scanContent(content, filePath, {});
      for (const f of found) {
        f.line = ln;
        if (options.markBypassDetected) f.bypassDetected = true;
        findings.push(f);
      }
    }
  }

  return { findings, scannedFiles: fileBlocks.length };
}

module.exports = { scanFile, scanDirectory, scanStaged, scanLastCommit, scanContent };
