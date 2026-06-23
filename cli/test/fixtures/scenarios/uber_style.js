// Simulates Uber 2022 breach pattern:
// Attacker found AWS credentials in private GitHub repo (via MFA fatigue + social engineering).
// Hardcoded creds in internal tooling scripts = full AWS access.

const AWS = require('aws-sdk');

// This is what was found — direct credential assignment
const s3 = new AWS.S3({
  accessKeyId: 'AKIAQRXNXIELO5ABCDEF',
  secretAccessKey: 'abc123XYZsecretKeyHere/ABCDE+FGHIJKLMNO',
  region: 'us-east-1'
});

// Also had Slack token for incident response bot
const SLACK_BOT_TOKEN = 'xoxb-0000-0000-DUMMY-TOKEN-VALUE-HERE';

// Stripe was also in scope (key redacted from fixture — tested via scanContent in run.js)
const stripeApiKey = 'STRIPE_KEY_REDACTED_FOR_TEST_FIXTURE';

async function uploadToS3(file, bucket) {
  return s3.upload({ Bucket: bucket, Key: file.name, Body: file.content }).promise();
}

module.exports = { uploadToS3 };
