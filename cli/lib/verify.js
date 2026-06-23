// Live verification — confirms if detected secret is actually valid
// Differentiator: TruffleHog verifies, Gitleaks doesn't. We do both.

async function verifySecret(finding) {
  const { verifier, rawMatch, ruleId } = finding;
  if (!verifier || !rawMatch) return { verified: false, status: 'unverified' };

  try {
    switch (verifier) {
      case 'github': return await verifyGitHub(rawMatch);
      case 'aws': return await verifyAWS(rawMatch, ruleId);
      case 'slack': return await verifySlack(rawMatch);
      case 'stripe': return await verifyStripe(rawMatch);
      case 'google': return await verifyGoogle(rawMatch);
      default: return { verified: false, status: 'unverified' };
    }
  } catch {
    return { verified: false, status: 'error' };
  }
}

async function verifyGitHub(token) {
  const fetch = (await import('node-fetch')).default;
  const res = await fetch('https://api.github.com/user', {
    headers: { Authorization: `token ${token}`, 'User-Agent': 'SecretGuard/1.0' },
    signal: AbortSignal.timeout(5000)
  });
  if (res.status === 200) {
    const data = await res.json();
    return { verified: true, status: 'active', detail: `GitHub user: ${data.login}`, critical: true };
  }
  return { verified: false, status: 'inactive' };
}

async function verifySlack(token) {
  const fetch = (await import('node-fetch')).default;
  const res = await fetch('https://slack.com/api/auth.test', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(5000)
  });
  const data = await res.json();
  if (data.ok) {
    return { verified: true, status: 'active', detail: `Slack workspace: ${data.team}`, critical: true };
  }
  return { verified: false, status: 'inactive' };
}

async function verifyStripe(key) {
  const fetch = (await import('node-fetch')).default;
  const encoded = Buffer.from(key + ':').toString('base64');
  const res = await fetch('https://api.stripe.com/v1/charges?limit=1', {
    headers: { Authorization: `Basic ${encoded}` },
    signal: AbortSignal.timeout(5000)
  });
  if (res.status === 200) {
    const isLive = key.startsWith('sk_live_');
    return { verified: true, status: 'active', detail: isLive ? 'LIVE Stripe key — production access!' : 'Test Stripe key', critical: isLive };
  }
  return { verified: false, status: 'inactive' };
}

async function verifyGoogle(key) {
  const fetch = (await import('node-fetch')).default;
  const res = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${key}`, {
    signal: AbortSignal.timeout(5000)
  });
  const data = await res.json();
  if (data.status !== 'REQUEST_DENIED') {
    return { verified: true, status: 'active', detail: `Google API key active (status: ${data.status})`, critical: true };
  }
  return { verified: false, status: 'inactive' };
}

async function verifyAWS(match, ruleId) {
  // AWS verification requires both access key + secret — only flag as "possibly active"
  // Full STS verification requires secret key pair, which we may not have
  if (ruleId === 'aws-access-key') {
    return { verified: false, status: 'unverified', detail: 'AWS key format valid — use --verify-aws with secret key pair for live check' };
  }
  return { verified: false, status: 'unverified' };
}

module.exports = { verifySecret };
