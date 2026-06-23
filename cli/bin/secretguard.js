#!/usr/bin/env node
'use strict';

const args = process.argv.slice(2);
const cmd = args[0];

async function main() {
  // Lazy-load chalk (ESM)
  const chalk = (await import('chalk')).default;

  // Header — send to stderr for machine-readable formats so stdout is clean JSON/SARIF
  const machineFormat = args.includes('--format=json') || args.includes('--format=sarif');
  if (!['--version', '-v'].includes(cmd)) {
    const headerLog = machineFormat ? console.error : console.log;
    headerLog(chalk.bold.white('\n  SecretGuard') + chalk.dim(' v1.0.0 — stop secrets before they leak\n'));
  }

  switch (cmd) {
    case 'scan': return runScan(chalk);
    case 'hook': return runHook(chalk);
    case 'audit': return runAudit(chalk);
    case 'init': return runInit(chalk);
    case 'fix': return runFix(chalk);
    case 'ci': return runCI(chalk);
    case 'baseline': return runBaseline(chalk);
    case '--version': case '-v':
      console.log('1.0.0'); return;
    default:
      return printHelp(chalk);
  }
}

// ── SCAN ───────────────────────────────────────────────────────────
async function runScan(chalk) {
  const argv = parseArgs(args.slice(1));
  const target = argv._[0] || '.';
  const staged = argv.staged || false;
  const lastCommit = argv['last-commit'] || false;
  const watchMode = argv.watch || false;
  const quiet = argv.quiet || false;
  const failOn = (argv['fail-on'] || 'critical').split(',');
  const format = argv.format || 'table';
  const outputFile = argv.output || null;
  const noVerify = argv['no-verify'] || false;
  const showFix = argv.fix || false;
  const isMachine = format === 'json' || format === 'sarif';

  const { scanDirectory, scanStaged, scanLastCommit } = require('../lib/scanner');
  const { printTable, printRemediation, toJSON, toSARIF, buildSummary } = require('../lib/reporter');

  const log = isMachine ? console.error : (quiet ? () => {} : console.log);

  // Watch mode
  if (watchMode) {
    return runWatch(target, argv, chalk, log, failOn, isMachine);
  }

  let findings, scannedFiles, scannedLabel;

  if (lastCommit) {
    log(chalk.dim('  Scanning last commit (bypass detection)...\n'));
    ({ findings, scannedFiles } = scanLastCommit());
    scannedLabel = 'last commit diff';
  } else if (staged) {
    log(chalk.dim('  Scanning staged files...\n'));
    ({ findings, scannedFiles } = scanStaged());
    scannedLabel = 'staged files';
  } else {
    log(chalk.dim(`  Scanning ${target}...\n`));
    ({ findings, scannedFiles } = scanDirectory(target));
    scannedLabel = `${scannedFiles} files`;
  }

  const summary = buildSummary(findings);
  let verificationResults = {};

  // Live verification (skip if --no-verify)
  if (!noVerify && findings.some(f => f.hasVerifier)) {
    log(chalk.dim('  Verifying active secrets against provider APIs...\n'));
    const { verifySecret } = require('../lib/verify');
    for (const f of findings) {
      if (f.hasVerifier) {
        const result = await verifySecret(f);
        verificationResults[`${f.file}:${f.line}:${f.ruleId}`] = result;
      }
    }
  }

  if (format === 'json') {
    const out = toJSON(findings, summary, { scanned: scannedLabel, timestamp: new Date().toISOString() });
    if (outputFile) { require('fs').writeFileSync(outputFile, out); console.log(chalk.green(`  JSON written to ${outputFile}`)); }
    else console.log(out);
  } else if (format === 'sarif') {
    const out = toSARIF(findings);
    if (outputFile) { require('fs').writeFileSync(outputFile, out); console.log(chalk.green(`  SARIF written to ${outputFile}\n`)); }
    else console.log(out);
  } else {
    printTable(findings, summary, chalk, { verificationResults });
    if (showFix && findings.length > 0) printRemediation(findings, chalk);
  }

  if (findings.length === 0) {
    log(chalk.dim(`  Scanned ${scannedLabel}. No secrets found.\n`));
    process.exit(0);
  }

  // Send notifications if configured
  if (findings.length > 0 && (process.env.SECRETGUARD_SLACK_WEBHOOK || process.env.SECRETGUARD_WEBHOOK_URL || (process.env.SECRETGUARD_EMAIL_TO && process.env.SECRETGUARD_SMTP_HOST))) {
    const { notify, getGitContext } = require('../lib/notify');
    const ctx = getGitContext();
    if (lastCommit && findings.some(f => f.bypassDetected)) {
      ctx.bypassDetected = true;
      ctx.event = 'bypass_commit';
    }
    const notifyResults = await notify(findings, summary, ctx);
    for (const r of notifyResults) {
      if (r.status === 'sent') log(chalk.green(`  ✓ Notification sent via ${r.channel}`));
      else log(chalk.yellow(`  ⚠ Notification failed (${r.channel}): ${r.error || r.code}`));
    }
  }

  log(chalk.dim(`  Scanned ${scannedLabel}.`));

  const shouldFail = findings.some(f => failOn.includes(f.severity));
  if (shouldFail) {
    if (!argv.fix && findings.length > 0) {
      log(chalk.dim(`  Run ${chalk.white('secretguard fix')} for remediation steps.\n`));
    }
    process.exit(1);
  }
  process.exit(0);
}

// ── AUDIT ──────────────────────────────────────────────────────────
async function runAudit(chalk) {
  const argv = parseArgs(args.slice(1));
  const maxCommits = parseInt(argv['max-commits'] || '500');
  const since = argv.since || '';

  console.log(chalk.dim(`  Auditing git history (up to ${maxCommits} commits)...\n`));

  const { auditHistory } = require('../lib/git');
  const { printTable, printRemediation, toJSON, toSARIF, buildSummary } = require('../lib/reporter');

  let result;
  try { result = auditHistory({ maxCommits, since }); }
  catch (e) { console.log(chalk.red(`  Error: ${e.message}\n`)); process.exit(1); }

  const { findings, scannedCommits } = result;
  const summary = buildSummary(findings);
  const format = argv.format || 'table';

  if (format === 'json') { console.log(toJSON(findings, summary, { scannedCommits })); }
  else if (format === 'sarif') { console.log(toSARIF(findings)); }
  else {
    printTable(findings, summary, chalk);
    if (argv.fix && findings.length > 0) printRemediation(findings, chalk);
  }

  console.log(chalk.dim(`  Scanned ${scannedCommits} commits. ${summary.total} findings.\n`));

  if (findings.length > 0 && summary.critical + summary.high > 0) {
    console.log(chalk.yellow('  ⚠ Secrets found in git history remain accessible unless you rewrite history.'));
    console.log(chalk.dim('  Use git-filter-repo or BFG Repo Cleaner to purge them, then rotate all keys.\n'));
    process.exit(1);
  }
  process.exit(0);
}

// ── HOOK ───────────────────────────────────────────────────────────
async function runHook(chalk) {
  const subCmd = args[1];
  const { installHook, uninstallHook } = require('../lib/git');

  if (subCmd === 'install') {
    try {
      const p = installHook('.');
      console.log(chalk.green(`  ✓ Pre-commit hook installed at ${p}\n`));
      console.log(chalk.dim('  SecretGuard will now scan staged files before every commit.\n'));
    } catch (e) {
      console.log(chalk.red(`  Error: ${e.message}\n`));
      process.exit(1);
    }
  } else if (subCmd === 'uninstall') {
    try {
      uninstallHook('.');
      console.log(chalk.green('  ✓ Pre-commit hook removed\n'));
    } catch (e) {
      console.log(chalk.red(`  Error: ${e.message}\n`));
      process.exit(1);
    }
  } else {
    console.log('  Usage: secretguard hook install|uninstall\n');
  }
}

// ── INIT ───────────────────────────────────────────────────────────
async function runInit(chalk) {
  const { installHook, isGitRepo } = require('../lib/git');
  const fs = require('fs');

  console.log(chalk.bold('  Setting up SecretGuard...\n'));

  // 1. Git hook
  if (isGitRepo('.')) {
    try {
      installHook('.');
      console.log(chalk.green('  ✓') + ' Pre-commit hook installed');
    } catch (e) {
      console.log(chalk.yellow('  ⚠ Could not install hook: ' + e.message));
    }
  } else {
    console.log(chalk.yellow('  ⚠ Not a git repo — skipping hook install'));
  }

  // 2. .secretguardignore
  if (!fs.existsSync('.secretguardignore')) {
    fs.writeFileSync('.secretguardignore', [
      '# SecretGuard ignore file',
      '# Paths/patterns to skip during scanning',
      '*.test.js',
      '*.spec.js',
      'test/',
      'tests/',
      '__tests__/',
      '*.example',
      '*.sample',
    ].join('\n') + '\n');
    console.log(chalk.green('  ✓') + ' Created .secretguardignore');
  }

  // 3. .gitignore check
  const gitignore = fs.existsSync('.gitignore') ? fs.readFileSync('.gitignore', 'utf8') : '';
  const missing = [];
  for (const entry of ['.env', '.env.local', '.env.*.local', '*.pem', '*.key', '.aws/credentials']) {
    if (!gitignore.includes(entry)) missing.push(entry);
  }
  if (missing.length > 0) {
    fs.appendFileSync('.gitignore', '\n# Added by SecretGuard\n' + missing.join('\n') + '\n');
    console.log(chalk.green('  ✓') + ` Added ${missing.length} patterns to .gitignore (${missing.join(', ')})`);
  } else {
    console.log(chalk.green('  ✓') + ' .gitignore looks good');
  }

  console.log('\n' + chalk.bold('  SecretGuard ready.') + chalk.dim(' Run: secretguard scan .\n'));
}

// ── FIX ────────────────────────────────────────────────────────────
async function runFix(chalk) {
  const argv = parseArgs(args.slice(1));
  const target = argv._[0] || '.';

  const { scanDirectory } = require('../lib/scanner');
  const { printRemediation, buildSummary } = require('../lib/reporter');

  const { findings } = scanDirectory(target);
  const summary = buildSummary(findings);

  if (findings.length === 0) {
    console.log(chalk.green('  ✓ No secrets found — nothing to fix.\n'));
    return;
  }

  console.log(chalk.yellow(`  Found ${summary.total} secret${summary.total !== 1 ? 's' : ''}. Remediation steps:\n`));
  printRemediation(findings, chalk);

  console.log(chalk.dim('  After rotating all secrets, run: secretguard scan . to verify.\n'));
}

// ── WATCH ──────────────────────────────────────────────────────────
async function runWatch(target, argv, chalk, log, failOn, isMachine) {
  const fs = require('fs');
  const path = require('path');
  const { scanFile, scanDirectory } = require('../lib/scanner');
  const { printTable, buildSummary } = require('../lib/reporter');

  const watchTarget = path.resolve(target);
  log(chalk.bold(`\n  SecretGuard watching: ${watchTarget}\n`));
  log(chalk.dim('  Scanning on file save. Press Ctrl+C to stop.\n'));

  // Initial scan
  const { findings: initFindings } = scanDirectory(watchTarget);
  if (initFindings.length > 0) {
    const summary = buildSummary(initFindings);
    printTable(initFindings, summary, chalk, {});
  } else {
    log(chalk.green('  ✓ Clean — watching for changes...\n'));
  }

  const debounceMap = new Map();

  const onChange = (eventType, filename) => {
    if (!filename) return;
    const fullPath = path.join(watchTarget, filename);
    if (!fs.existsSync(fullPath)) return;

    // Debounce per file (300ms)
    clearTimeout(debounceMap.get(fullPath));
    debounceMap.set(fullPath, setTimeout(() => {
      const findings = scanFile(fullPath, {});
      if (findings.length > 0) {
        const summary = buildSummary(findings);
        log(chalk.yellow(`\n  [${new Date().toLocaleTimeString()}] Change detected: ${filename}`));
        printTable(findings, summary, chalk, {});
      } else {
        log(chalk.green(`  ✓ [${new Date().toLocaleTimeString()}] ${filename} — clean`));
      }
    }, 300));
  };

  try {
    fs.watch(watchTarget, { recursive: true }, onChange);
  } catch {
    // Fallback for systems without recursive watch support
    log(chalk.yellow('  Recursive watch not supported — watching top-level only.\n'));
    fs.watch(watchTarget, onChange);
  }

  // Keep alive
  await new Promise(() => {});
}

// ── BASELINE ───────────────────────────────────────────────────────
async function runBaseline(chalk) {
  const argv = parseArgs(args.slice(1));
  const subCmd = argv._[0] || 'generate';
  const baselineFile = '.secretguardbaseline';
  const fs = require('fs');

  if (subCmd === 'generate') {
    const target = argv._[1] || '.';
    const { scanDirectory } = require('../lib/scanner');
    const { buildSummary } = require('../lib/reporter');

    console.log(chalk.dim(`  Scanning ${target} to generate baseline...\n`));
    const { findings } = scanDirectory(target);
    const summary = buildSummary(findings);

    if (findings.length === 0) {
      console.log(chalk.green('  ✓ No findings — baseline not needed.\n'));
      return;
    }

    const baseline = {
      generated: new Date().toISOString(),
      note: 'SecretGuard baseline — findings below are suppressed. Review and remove when fixed.',
      suppressions: findings.map(f => ({
        ruleId: f.ruleId,
        file: f.file,
        line: f.line,
        fingerprint: Buffer.from(`${f.file}:${f.line}:${f.ruleId}:${f.match}`).toString('base64')
      }))
    };

    fs.writeFileSync(baselineFile, JSON.stringify(baseline, null, 2));
    console.log(chalk.yellow(`  ⚠ Baseline created: ${baselineFile}`));
    console.log(chalk.dim(`  ${summary.total} existing finding${summary.total !== 1 ? 's' : ''} suppressed.`));
    console.log(chalk.dim('  New findings will still be blocked. Remove entries from baseline when secrets are rotated.\n'));

  } else if (subCmd === 'status') {
    if (!fs.existsSync(baselineFile)) {
      console.log(chalk.dim('  No baseline file found. Run: secretguard baseline generate\n'));
      return;
    }
    const baseline = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
    console.log(chalk.yellow(`  Baseline: ${baselineFile}`));
    console.log(chalk.dim(`  Generated: ${baseline.generated}`));
    console.log(chalk.dim(`  Suppressions: ${baseline.suppressions.length}`));
    for (const s of baseline.suppressions) {
      console.log(chalk.dim(`    • ${s.file}:${s.line} [${s.ruleId}]`));
    }
    console.log('');

  } else if (subCmd === 'clear') {
    if (!fs.existsSync(baselineFile)) {
      console.log(chalk.dim('  No baseline file to clear.\n'));
      return;
    }
    fs.unlinkSync(baselineFile);
    console.log(chalk.green('  ✓ Baseline cleared — all findings will now be reported.\n'));

  } else {
    console.log('  Usage: secretguard baseline generate [path] | status | clear\n');
  }
}

// ── CI ─────────────────────────────────────────────────────────────
async function runCI(chalk) {
  const platform = args[1] || 'github-actions';
  const { getCITemplate } = require('../lib/git');
  const template = getCITemplate(platform);
  console.log(template);
  console.log(chalk.dim(`\n  Tip: secretguard ci github-actions|gitlab-ci|pre-commit-config\n`));
}

// ── HELP ───────────────────────────────────────────────────────────
function printHelp(chalk) {
  console.log(`  ${chalk.bold('Commands:')}

  ${chalk.white('secretguard scan [path]')}         Scan directory for secrets ${chalk.dim('(default: .)')}
    ${chalk.dim('--staged')}                       Scan only git staged files
    ${chalk.dim('--last-commit')}                  Scan last committed diff (catches --no-verify bypasses)
    ${chalk.dim('--watch')}                        Watch mode — rescan on file save
    ${chalk.dim('--fail-on=critical,high')}        Exit 1 if severity matches ${chalk.dim('(default: critical)')}
    ${chalk.dim('--format=table|json|sarif')}      Output format ${chalk.dim('(default: table)')}
    ${chalk.dim('--output=file.sarif')}            Write output to file
    ${chalk.dim('--fix')}                          Show remediation steps after scan
    ${chalk.dim('--no-verify')}                    Skip live API verification
    ${chalk.dim('--quiet')}                        Suppress banner/status (for scripts)

  ${chalk.white('secretguard audit')}               Scan full git commit history
    ${chalk.dim('--max-commits=500')}              Limit commits scanned ${chalk.dim('(default: 500)')}
    ${chalk.dim('--since="6 months ago"')}         Only scan commits since date
    ${chalk.dim('--format=table|json|sarif')}      Output format

  ${chalk.white('secretguard fix [path]')}          Show remediation steps for detected secrets

  ${chalk.white('secretguard hook install')}        Install pre-commit git hook
  ${chalk.white('secretguard hook uninstall')}      Remove pre-commit git hook

  ${chalk.white('secretguard init')}               Set up hook + .gitignore + ignore file

  ${chalk.white('secretguard ci [platform]')}       Print CI config template
    ${chalk.dim('Platforms:')} github-actions, gitlab-ci, pre-commit-config

  ${chalk.white('secretguard baseline generate [path]')}  Suppress existing findings (false positives)
  ${chalk.white('secretguard baseline status')}           Show suppressed findings
  ${chalk.white('secretguard baseline clear')}            Remove baseline (re-report all findings)

  ${chalk.dim('Examples:')}
  ${chalk.dim('$')} secretguard scan .
  ${chalk.dim('$')} secretguard scan --staged --fail-on=critical,high
  ${chalk.dim('$')} secretguard audit --since="1 year ago"
  ${chalk.dim('$')} secretguard scan . --format=sarif --output=results.sarif
  ${chalk.dim('$')} secretguard init
`);
}

// ── UTIL ───────────────────────────────────────────────────────────
function parseArgs(a) {
  const out = { _: [] };
  for (const arg of a) {
    if (arg.startsWith('--')) {
      const [k, ...v] = arg.slice(2).split('=');
      out[k] = v.length ? v.join('=') : true;
    } else {
      out._.push(arg);
    }
  }
  return out;
}

main().catch(e => { console.error(e.message); process.exit(1); });
