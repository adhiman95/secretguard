'use strict';

const vscode = require('vscode');
const { execSync, spawnSync } = require('child_process');
const path = require('path');

// Inline pattern engine — same patterns as CLI, no CLI subprocess needed for real-time
const { PATTERNS, shannonEntropy } = require('./lib/patterns');

let diagnosticCollection;
let statusBarItem;
let outputChannel;

function activate(context) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('secretguard');
  context.subscriptions.push(diagnosticCollection);

  outputChannel = vscode.window.createOutputChannel('SecretGuard');

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'secretguard.scanWorkspace';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);
  setStatus('idle');

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('secretguard.scanFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) scanDocument(doc);
    }),
    vscode.commands.registerCommand('secretguard.scanWorkspace', () => {
      scanWorkspace();
    }),
    vscode.commands.registerCommand('secretguard.ignoreRule', (ruleId, filePath, line) => {
      addToIgnoreFile(ruleId, filePath, line);
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration('secretguard');
      if (cfg.get('enableRealtimeScan')) scanDocument(doc);
    })
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration('secretguard');
      if (cfg.get('enableRealtimeScan')) scanDocument(doc);
    })
  );

  // Scan on change (debounced)
  let changeTimer;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      clearTimeout(changeTimer);
      changeTimer = setTimeout(() => {
        const cfg = vscode.workspace.getConfiguration('secretguard');
        if (cfg.get('enableRealtimeScan')) scanDocument(event.document);
      }, 800);
    })
  );

  // Scan open editors on startup
  vscode.workspace.textDocuments.forEach(doc => scanDocument(doc));
}

function scanDocument(document) {
  if (document.uri.scheme !== 'file') return;
  if (shouldSkipFile(document.fileName)) return;

  const content = document.getText();
  const findings = scanContent(content, document.fileName);
  const diagnostics = findings.map(f => findingToDiagnostic(f, document));

  diagnosticCollection.set(document.uri, diagnostics);
  updateStatusBar();
}

function scanWorkspace() {
  setStatus('scanning');
  diagnosticCollection.clear();

  const folders = vscode.workspace.workspaceFolders;
  if (!folders) { setStatus('idle'); return; }

  let total = 0;
  for (const folder of folders) {
    const results = runCLIScan(folder.uri.fsPath);
    for (const [filePath, findings] of Object.entries(results)) {
      const uri = vscode.Uri.file(filePath);
      const diagnostics = findings.map(f => {
        const range = new vscode.Range(
          new vscode.Position(Math.max(0, f.line - 1), Math.max(0, (f.col || 1) - 1)),
          new vscode.Position(Math.max(0, f.line - 1), 999)
        );
        return makeDiagnostic(range, f);
      });
      diagnosticCollection.set(uri, diagnostics);
      total += diagnostics.length;
    }
  }

  setStatus(total > 0 ? 'found' : 'clean', total);
  if (total > 0) {
    vscode.window.showWarningMessage(
      `SecretGuard: ${total} secret${total !== 1 ? 's' : ''} detected in workspace.`,
      'View Problems'
    ).then(action => {
      if (action === 'View Problems') vscode.commands.executeCommand('workbench.panel.markers.view.focus');
    });
  }
}

// Inline scan using same pattern engine as CLI (no subprocess needed, fast)
function scanContent(content, filePath) {
  const findings = [];
  const lines = content.split('\n');
  const SKIP_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz', '.pdf', '.lock']);
  const ext = path.extname(filePath).toLowerCase();
  if (SKIP_EXTS.has(ext)) return findings;

  const cfg = vscode.workspace.getConfiguration('secretguard');
  const allowedSeverities = cfg.get('severity') || ['critical', 'high', 'medium'];

  for (const rule of PATTERNS) {
    if (!allowedSeverities.includes(rule.severity)) continue;

    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match;

    while ((match = regex.exec(content)) !== null) {
      const matchStr = match[0];
      if (matchStr.length < 8) { if (regex.lastIndex === match.index) regex.lastIndex++; continue; }

      if (rule.entropy > 0) {
        const secretVal = match[1] || matchStr;
        if (shannonEntropy(secretVal) < rule.entropy) { if (regex.lastIndex === match.index) regex.lastIndex++; continue; }
      }

      const lower = matchStr.toLowerCase();
      if (lower.includes('example') || lower.includes('placeholder') || lower.includes('your-key') || lower.includes('xxxx') || matchStr.includes('****')) {
        if (regex.lastIndex === match.index) regex.lastIndex++; continue;
      }

      const upToMatch = content.substring(0, match.index);
      const lineNumber = upToMatch.split('\n').length;
      const lineContent = lines[lineNumber - 1] || '';
      const trimmedLine = lineContent.trim();

      const isComment = (trimmedLine.startsWith('// ') || trimmedLine.startsWith('//\t') || trimmedLine === '//') ||
        trimmedLine.startsWith('# ') || trimmedLine.startsWith('#\t') || trimmedLine === '#' ||
        trimmedLine.startsWith('* ') || trimmedLine.startsWith('<!--');
      if (isComment) { if (regex.lastIndex === match.index) regex.lastIndex++; continue; }

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        file: filePath,
        line: lineNumber,
        col: match.index - (upToMatch.lastIndexOf('\n') + 1) + 1,
        match: maskSecret(matchStr),
        remediate: rule.remediate
      });

      if (regex.lastIndex === match.index) regex.lastIndex++;
    }
  }

  return findings;
}

function findingToDiagnostic(finding, document) {
  const lineIdx = Math.max(0, finding.line - 1);
  const line = document.lineAt(Math.min(lineIdx, document.lineCount - 1));
  const range = new vscode.Range(lineIdx, 0, lineIdx, line.text.length);
  return makeDiagnostic(range, finding);
}

function makeDiagnostic(range, finding) {
  const severity = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information
  }[finding.severity] || vscode.DiagnosticSeverity.Warning;

  const msg = `[${finding.severity.toUpperCase()}] ${finding.ruleName} — ${finding.match}`;
  const diag = new vscode.Diagnostic(range, msg, severity);
  diag.source = 'SecretGuard';
  diag.code = {
    value: finding.ruleId,
    target: vscode.Uri.parse(`https://secretguard.dev/rules/${finding.ruleId}`)
  };

  // Attach remediation as related info
  if (finding.remediate?.length > 0) {
    diag.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(vscode.Uri.file(finding.file || ''), range),
        `Fix: ${finding.remediate[0]}`
      )
    ];
  }

  return diag;
}

// Run CLI for full workspace scan (catches files VS Code hasn't opened)
function runCLIScan(dir) {
  const cfg = vscode.workspace.getConfiguration('secretguard');
  const cliPath = cfg.get('cliPath') || 'secretguard';

  try {
    const result = spawnSync(cliPath, ['scan', dir, '--format=json', '--no-verify'], {
      encoding: 'utf8',
      timeout: 30000
    });
    const out = result.stdout?.trim();
    if (!out) return {};

    const data = JSON.parse(out);
    const byFile = {};
    for (const f of (data.findings || [])) {
      if (!byFile[f.file]) byFile[f.file] = [];
      byFile[f.file].push(f);
    }
    return byFile;
  } catch {
    return {};
  }
}

function addToIgnoreFile(ruleId, filePath, line) {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) return;

  const fs = require('fs');
  const ignorePath = path.join(workspaceRoot, '.secretguardignore');
  const rel = path.relative(workspaceRoot, filePath);

  const entry = `\n# Suppressed ${ruleId} on line ${line}\n${rel}`;
  fs.appendFileSync(ignorePath, entry);
  vscode.window.showInformationMessage(`SecretGuard: Added ${rel} to .secretguardignore`);
}

function shouldSkipFile(filePath) {
  const SKIP_DIRS = new Set(['.git', 'node_modules', '.next', 'dist', 'build', '__pycache__', '.venv', 'venv', 'vendor', 'coverage']);
  const parts = filePath.split(/[/\\]/);
  return parts.some(p => SKIP_DIRS.has(p));
}

function maskSecret(str) {
  if (str.length <= 8) return '****';
  const show = Math.min(4, Math.floor(str.length * 0.15));
  return str.substring(0, show) + '****' + str.substring(str.length - show);
}

function updateStatusBar() {
  let total = 0;
  diagnosticCollection.forEach((_, diags) => { total += diags.length; });
  setStatus(total > 0 ? 'found' : 'clean', total);
}

function setStatus(state, count = 0) {
  switch (state) {
    case 'idle':
      statusBarItem.text = '$(shield) SecretGuard';
      statusBarItem.tooltip = 'SecretGuard — click to scan workspace';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'scanning':
      statusBarItem.text = '$(sync~spin) SecretGuard: scanning...';
      statusBarItem.backgroundColor = undefined;
      break;
    case 'found':
      statusBarItem.text = `$(alert) SecretGuard: ${count} secret${count !== 1 ? 's' : ''}`;
      statusBarItem.tooltip = `${count} secret${count !== 1 ? 's' : ''} detected — click to rescan`;
      statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      break;
    case 'clean':
      statusBarItem.text = '$(shield) SecretGuard: clean';
      statusBarItem.tooltip = 'No secrets detected — click to rescan';
      statusBarItem.backgroundColor = undefined;
      break;
  }
}

function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}

module.exports = { activate, deactivate };
