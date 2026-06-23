const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Secret detection patterns
const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key',
    severity: 'critical',
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: 'AWS Access Key ID detected'
  },
  {
    name: 'AWS Secret Key',
    severity: 'critical',
    pattern: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|aws[_\-]?secret)\s*[=:]\s*["']?([A-Za-z0-9\/\+=]{40})["']?/gi,
    description: 'AWS Secret Access Key detected'
  },
  {
    name: 'GitHub Token',
    severity: 'critical',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
    description: 'GitHub personal access token detected'
  },
  {
    name: 'Generic API Key',
    severity: 'high',
    pattern: /(?:api[_\-]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,64})["']?/gi,
    description: 'Generic API key assignment detected'
  },
  {
    name: 'Private Key',
    severity: 'critical',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    description: 'Private key block detected'
  },
  {
    name: 'Password in Code',
    severity: 'high',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{6,})["']/gi,
    description: 'Hardcoded password detected'
  },
  {
    name: 'JWT Token',
    severity: 'high',
    pattern: /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*/g,
    description: 'JSON Web Token detected'
  },
  {
    name: 'Slack Token',
    severity: 'critical',
    pattern: /xox[baprs]-[A-Za-z0-9\-]{10,}/g,
    description: 'Slack token detected'
  },
  {
    name: 'Google API Key',
    severity: 'critical',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API key detected'
  },
  {
    name: 'Stripe Key',
    severity: 'critical',
    pattern: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g,
    description: 'Stripe API key detected'
  },
  {
    name: 'Connection String',
    severity: 'high',
    pattern: /(?:mongodb|postgresql|mysql|redis):\/\/[^\s"'<>]+:[^\s"'<>@]+@[^\s"'<>]+/gi,
    description: 'Database connection string with credentials detected'
  },
  {
    name: 'Generic Secret',
    severity: 'medium',
    pattern: /(?:secret|token)\s*[=:]\s*["']([A-Za-z0-9\-_\/+=]{16,})["']/gi,
    description: 'Generic secret or token value detected'
  }
];

function scanCode(code, filename = '') {
  const findings = [];
  const lines = code.split('\n');

  for (const rule of SECRET_PATTERNS) {
    // Reset lastIndex for global patterns
    rule.pattern.lastIndex = 0;
    let match;
    const testPattern = new RegExp(rule.pattern.source, rule.pattern.flags);

    while ((match = testPattern.exec(code)) !== null) {
      // Find line number
      const upToMatch = code.substring(0, match.index);
      const lineNumber = upToMatch.split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';

      // Mask the secret value
      const masked = match[0].length > 8
        ? match[0].substring(0, 4) + '****' + match[0].substring(match[0].length - 4)
        : '****';

      findings.push({
        rule: rule.name,
        severity: rule.severity,
        description: rule.description,
        line: lineNumber,
        column: match.index - upToMatch.lastIndexOf('\n'),
        match: masked,
        lineContent: lineContent.trim().substring(0, 120),
        filename: filename || 'input'
      });

      // Prevent infinite loop on zero-length matches
      if (match.index === testPattern.lastIndex) testPattern.lastIndex++;
    }
  }

  return findings;
}

// API: scan text/code
app.post('/api/scan', (req, res) => {
  const { code, filename } = req.body;
  if (!code) return res.status(400).json({ error: 'No code provided' });

  const findings = scanCode(code, filename);
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    clean: findings.length === 0
  };

  res.json({ findings, summary, scannedAt: new Date().toISOString() });
});

// API: get supported patterns
app.get('/api/patterns', (req, res) => {
  res.json(SECRET_PATTERNS.map(p => ({
    name: p.name,
    severity: p.severity,
    description: p.description
  })));
});

// Named routes
app.get('/docs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'docs.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Ingest scan results from CLI (allows secretguard scan . --format=json | curl -X POST localhost:3000/api/ingest)
app.post('/api/ingest', (req, res) => {
  const { findings, summary, meta } = req.body;
  if (!findings || !Array.isArray(findings)) return res.status(400).json({ error: 'findings array required' });
  // In production this would persist to DB; here just acknowledge
  console.log(`[SecretGuard] Ingested ${findings.length} findings from ${meta?.repo || 'unknown'}`);
  res.json({ ok: true, ingested: findings.length });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SecretGuard running at http://localhost:${PORT}`);
});
