'use strict';

/**
 * Notification system — alert your team/clients the moment secrets are detected.
 * Supports: Slack webhook, custom HTTP webhook, console (always on)
 *
 * Configure via environment variables:
 *   SECRETGUARD_SLACK_WEBHOOK=https://hooks.slack.com/services/...
 *   SECRETGUARD_WEBHOOK_URL=https://your-server.com/alerts
 *   SECRETGUARD_WEBHOOK_TOKEN=bearer-token-for-your-webhook
 */

async function notify(findings, summary, context = {}) {
  const results = [];

  if (process.env.SECRETGUARD_SLACK_WEBHOOK) {
    results.push(await notifySlack(findings, summary, context));
  }

  if (process.env.SECRETGUARD_WEBHOOK_URL) {
    results.push(await notifyWebhook(findings, summary, context));
  }

  if (process.env.SECRETGUARD_EMAIL_TO && process.env.SECRETGUARD_SMTP_HOST) {
    results.push(await notifyEmail(findings, summary, context));
  }

  return results;
}

async function notifySlack(findings, summary, context) {
  const fetch = (await import('node-fetch')).default;
  const webhook = process.env.SECRETGUARD_SLACK_WEBHOOK;

  const criticalCount = summary.critical;
  const color = criticalCount > 0 ? '#ef4444' : summary.high > 0 ? '#f97316' : '#eab308';
  const icon = criticalCount > 0 ? ':rotating_light:' : ':warning:';

  // Group by file for compact display
  const fileGroups = {};
  for (const f of findings) {
    const key = f.file;
    if (!fileGroups[key]) fileGroups[key] = [];
    fileGroups[key].push(f);
  }

  const fields = Object.entries(fileGroups).slice(0, 8).map(([file, ffindings]) => ({
    type: 'mrkdwn',
    text: `*${file}*\n` + ffindings.map(f => {
      const loc = `${f.authorName ? `by *${f.authorName}* <${f.authorEmail}>` : ''}`;
      const time = f.timestamp ? ` at ${f.timestamp.substring(0, 16)}` : '';
      const commit = f.commit ? ` | commit \`${f.commit}\`` : '';
      return `• \`${f.severity.toUpperCase()}\` ${f.ruleName} — line ${f.line}${commit}${time ? '\n  ' + loc + time : ''}`;
    }).join('\n')
  }));

  const payload = {
    text: `${icon} *SecretGuard Alert* — ${summary.total} secret${summary.total !== 1 ? 's' : ''} detected${context.repo ? ` in \`${context.repo}\`` : ''}`,
    attachments: [{
      color,
      fields: [{
        title: 'Summary',
        value: [
          summary.critical ? `🔴 ${summary.critical} critical` : '',
          summary.high ? `🟠 ${summary.high} high` : '',
          summary.medium ? `🟡 ${summary.medium} medium` : '',
          `📁 ${summary.files} file${summary.files !== 1 ? 's' : ''} affected`
        ].filter(Boolean).join('  |  '),
        short: false
      }],
      blocks: fields.length > 0 ? undefined : undefined,
      footer: `SecretGuard | ${context.branch || 'local'} | ${new Date().toISOString()}`
    }]
  };

  try {
    const res = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000)
    });
    return { channel: 'slack', status: res.ok ? 'sent' : 'failed', code: res.status };
  } catch (e) {
    return { channel: 'slack', status: 'error', error: e.message };
  }
}

async function notifyWebhook(findings, summary, context) {
  const fetch = (await import('node-fetch')).default;
  const url = process.env.SECRETGUARD_WEBHOOK_URL;
  const token = process.env.SECRETGUARD_WEBHOOK_TOKEN;

  const payload = {
    event: 'secrets.detected',
    timestamp: new Date().toISOString(),
    context: {
      repo: context.repo || null,
      branch: context.branch || null,
      triggeredBy: context.triggeredBy || 'cli',
      ci: context.ci || null
    },
    summary,
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      severity: f.severity,
      file: f.file,
      line: f.line,
      match: f.match, // masked
      commit: f.commitFull || f.commit || null,
      authorName: f.authorName || null,
      authorEmail: f.authorEmail || null,
      timestamp: f.timestamp || null,
      remediate: f.remediate
    }))
  };

  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000)
    });
    return { channel: 'webhook', status: res.ok ? 'sent' : 'failed', code: res.status };
  } catch (e) {
    return { channel: 'webhook', status: 'error', error: e.message };
  }
}

async function notifyEmail(findings, summary, context) {
  // Uses raw SMTP via net module — no nodemailer dep required
  // Configure: SECRETGUARD_SMTP_HOST, SECRETGUARD_SMTP_PORT (default 587),
  //            SECRETGUARD_SMTP_USER, SECRETGUARD_SMTP_PASS,
  //            SECRETGUARD_EMAIL_TO, SECRETGUARD_EMAIL_FROM
  const net = require('net');
  const tls = require('tls');

  const host = process.env.SECRETGUARD_SMTP_HOST;
  const port = parseInt(process.env.SECRETGUARD_SMTP_PORT || '587');
  const user = process.env.SECRETGUARD_SMTP_USER || '';
  const pass = process.env.SECRETGUARD_SMTP_PASS || '';
  const to = process.env.SECRETGUARD_EMAIL_TO;
  const from = process.env.SECRETGUARD_EMAIL_FROM || `secretguard@${context.repo?.split('/')[0] || 'noreply'}.com`;

  const subject = `[SecretGuard] ${summary.total} secret${summary.total !== 1 ? 's' : ''} detected${context.repo ? ` in ${context.repo}` : ''}`;

  const findingLines = findings.slice(0, 20).map(f =>
    `  [${f.severity.toUpperCase()}] ${f.ruleName}\n  File: ${f.file}:${f.line}\n  Match: ${f.match}\n  Fix: ${f.remediate?.[0] || 'Rotate key immediately'}`
  ).join('\n\n');

  const body = [
    `SecretGuard Alert`,
    `=================`,
    ``,
    `${summary.critical ? `CRITICAL: ${summary.critical}  ` : ''}${summary.high ? `HIGH: ${summary.high}  ` : ''}${summary.medium ? `MEDIUM: ${summary.medium}` : ''}`,
    `Files affected: ${summary.files}`,
    `Repo: ${context.repo || 'local'}  Branch: ${context.branch || 'unknown'}`,
    ``,
    `Findings:`,
    `─────────`,
    findingLines,
    findings.length > 20 ? `\n  ... and ${findings.length - 20} more findings` : '',
    ``,
    `Run: secretguard fix  for full remediation steps.`
  ].join('\n');

  const message = [
    `From: SecretGuard <${from}>`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Content-Type: text/plain; charset=utf-8`,
    ``,
    body
  ].join('\r\n');

  return new Promise(resolve => {
    const timeout = setTimeout(() => resolve({ channel: 'email', status: 'error', error: 'timeout' }), 10000);

    try {
      const smtpLines = [];
      let step = 0;
      const b64creds = Buffer.from(`\x00${user}\x00${pass}`).toString('base64');

      const socket = net.connect(port, host);
      const send = (line) => socket.write(line + '\r\n');

      const upgrade = () => {
        const tlsSocket = tls.connect({ socket, host, rejectUnauthorized: false }, () => {
          socket.removeAllListeners();
          tlsSocket.on('data', onData);
          step = 3;
          if (user) send(`AUTH PLAIN ${b64creds}`);
          else { step = 5; send(`MAIL FROM:<${from}>`); }
        });
        return tlsSocket;
      };

      let tlsConn = null;

      const onData = (data) => {
        const line = data.toString().trim();
        if (step === 0 && line.startsWith('220')) { send(`EHLO secretguard`); step = 1; }
        else if (step === 1 && line.includes('250')) {
          if (line.includes('STARTTLS') || port === 587) { send('STARTTLS'); step = 2; }
          else { step = 3; if (user) send(`AUTH PLAIN ${b64creds}`); else { step = 5; send(`MAIL FROM:<${from}>`); } }
        }
        else if (step === 2 && line.startsWith('220')) { tlsConn = upgrade(); }
        else if (step === 3 && line.startsWith('235')) { step = 5; send(`MAIL FROM:<${from}>`); }
        else if (step === 3 && line.startsWith('5')) { step = 5; send(`MAIL FROM:<${from}>`); } // no auth
        else if (step === 5 && line.startsWith('250')) { send(`RCPT TO:<${to}>`); step = 6; }
        else if (step === 6 && line.startsWith('250')) { send('DATA'); step = 7; }
        else if (step === 7 && line.startsWith('354')) { send(message + '\r\n.'); step = 8; }
        else if (step === 8 && line.startsWith('250')) { send('QUIT'); clearTimeout(timeout); resolve({ channel: 'email', status: 'sent' }); }
        else if (line.startsWith('5')) { clearTimeout(timeout); resolve({ channel: 'email', status: 'failed', error: line }); socket.destroy(); }
      };

      socket.on('data', onData);
      socket.on('error', e => { clearTimeout(timeout); resolve({ channel: 'email', status: 'error', error: e.message }); });
    } catch (e) {
      clearTimeout(timeout);
      resolve({ channel: 'email', status: 'error', error: e.message });
    }
  });
}

// Get git context for notifications
function getGitContext() {
  const { execSync } = require('child_process');
  const run = (cmd) => { try { return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim(); } catch { return null; } };
  return {
    repo: run('git remote get-url origin'),
    branch: run('git rev-parse --abbrev-ref HEAD'),
    ci: process.env.CI ? (process.env.GITHUB_ACTIONS ? 'github-actions' : process.env.GITLAB_CI ? 'gitlab-ci' : 'ci') : null,
    triggeredBy: process.env.GITHUB_ACTOR || process.env.GITLAB_USER_LOGIN || 'local'
  };
}

module.exports = { notify, getGitContext };
