// Output: table (default), json, sarif (GitHub Code Scanning compatible)

function severityIcon(s) {
  return { critical: '✖', high: '⚠', medium: '◆', low: '◉' }[s] || '○';
}

function severityColor(s, chalk) {
  return { critical: chalk.red, high: chalk.yellow, medium: chalk.cyan, low: chalk.gray }[s] || chalk.white;
}

function printTable(findings, summary, chalk, options = {}) {
  const { verificationResults = {} } = options;

  if (findings.length === 0) {
    console.log(chalk.green('\n  ✓ No secrets detected — clean!\n'));
    return;
  }

  console.log('');

  // Group by file
  const byFile = {};
  for (const f of findings) {
    const key = f.file;
    if (!byFile[key]) byFile[key] = [];
    byFile[key].push(f);
  }

  for (const [file, filefindings] of Object.entries(byFile)) {
    console.log(chalk.underline(chalk.white('  ' + file)));

    for (const f of filefindings) {
      const col = severityColor(f.severity, chalk);
      const icon = severityIcon(f.severity);
      const sev = col(`[${f.severity.toUpperCase()}]`).padEnd(18);
      const loc = chalk.gray(`${f.line}:${f.col}`).padEnd(12);
      const name = chalk.white(f.ruleName);
      const matched = chalk.dim(`  (${f.match})`);

      console.log(`    ${col(icon)} ${sev} ${loc} ${name}${matched}`);

      if (f.lineContent) {
        console.log(`       ${chalk.dim('→')} ${chalk.gray(f.lineContent)}`);
      }

      if (f.inTestFile) {
        console.log(`       ${chalk.yellow('⚑ TEST FILE')} ${chalk.dim('found in test/fixture path — verify this is NOT a real credential before dismissing')}`);
      }

      if (f.bypassDetected) {
        console.log(`       ${chalk.bgRed.white(' BYPASS DETECTED ')} ${chalk.red('committed via --no-verify — was not blocked by pre-commit hook')}`);
      }

      if (f.entropy) {
        console.log(`       ${chalk.dim('entropy:')} ${chalk.cyan(f.entropy)}`);
      }

      // Blast radius
      if (f.impact) {
        console.log(`       ${chalk.dim('impact:')}  ${chalk.red(f.impact)}`);
      }

      // Verification result
      const vr = verificationResults[`${f.file}:${f.line}:${f.ruleId}`];
      if (vr) {
        if (vr.verified) {
          console.log(`       ${chalk.bgRed.white(' VERIFIED ACTIVE ')} ${chalk.red(vr.detail)}`);
        } else if (vr.status === 'inactive') {
          console.log(`       ${chalk.green('✓ Verified inactive')} (key revoked or invalid)`);
        }
      }

      if (f.commit) {
        console.log(`       ${chalk.dim('commit:')}  ${chalk.yellow(f.commitFull || f.commit)}`);
        console.log(`       ${chalk.dim('author:')}  ${chalk.white(f.authorName || '?')} ${chalk.dim('<' + (f.authorEmail || '?') + '>')}`);
        console.log(`       ${chalk.dim('time:')}    ${chalk.cyan(f.timestamp || '?')}`);
        console.log(`       ${chalk.dim('message:')} ${chalk.dim(f.commitMsg?.substring(0, 80))}`);
      }

      console.log('');
    }
  }

  // Summary bar
  console.log(chalk.dim('  ─'.repeat(36)));
  const parts = [`${chalk.bold(summary.total)} finding${summary.total !== 1 ? 's' : ''}`];
  if (summary.critical) parts.push(chalk.red(`${summary.critical} critical`));
  if (summary.high) parts.push(chalk.yellow(`${summary.high} high`));
  if (summary.medium) parts.push(chalk.cyan(`${summary.medium} medium`));
  if (summary.low) parts.push(chalk.gray(`${summary.low} low`));
  console.log('  ' + parts.join(chalk.dim('  ·  ')));
  console.log('');
}

function printRemediation(findings, chalk) {
  const seen = new Set();
  console.log(chalk.bold('\n  Remediation Steps\n'));

  for (const f of findings) {
    const key = f.ruleId;
    if (seen.has(key)) continue;
    seen.add(key);

    console.log(chalk.yellow(`  ${f.ruleName}`));
    for (let i = 0; i < f.remediate.length; i++) {
      console.log(chalk.dim(`    ${i + 1}.`) + ' ' + f.remediate[i]);
    }
    console.log('');
  }
}

function toJSON(findings, summary, meta = {}) {
  return JSON.stringify({ meta, summary, findings: findings.map(f => {
    const { rawMatch, ...safe } = f;
    return safe;
  }) }, null, 2);
}

function toSARIF(findings, toolVersion = '1.0.0') {
  // SARIF 2.1.0 — compatible with GitHub Code Scanning
  const rules = {};
  for (const f of findings) {
    if (!rules[f.ruleId]) {
      rules[f.ruleId] = {
        id: f.ruleId,
        name: f.ruleName.replace(/\s+/g, ''),
        shortDescription: { text: f.ruleName },
        fullDescription: { text: f.ruleName },
        defaultConfiguration: {
          level: { critical: 'error', high: 'error', medium: 'warning', low: 'note' }[f.severity] || 'warning'
        },
        properties: { tags: ['security', 'secret-detection'], precision: 'high', severity: f.severity }
      };
    }
  }

  const results = findings.map(f => ({
    ruleId: f.ruleId,
    message: { text: `${f.ruleName} detected in ${f.file}:${f.line}` },
    level: { critical: 'error', high: 'error', medium: 'warning', low: 'note' }[f.severity] || 'warning',
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.file.replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
        region: { startLine: f.line, startColumn: f.col }
      }
    }],
    fingerprints: { 'secretguard/v1': Buffer.from(`${f.file}:${f.line}:${f.ruleId}`).toString('base64') }
  }));

  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'SecretGuard',
          version: toolVersion,
          informationUri: 'https://secretguard.dev',
          rules: Object.values(rules)
        }
      },
      results
    }]
  }, null, 2);
}

function buildSummary(findings) {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    files: [...new Set(findings.map(f => f.file))].length
  };
}

module.exports = { printTable, printRemediation, toJSON, toSARIF, buildSummary };
