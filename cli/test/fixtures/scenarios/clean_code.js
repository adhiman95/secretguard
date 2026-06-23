// This file is CLEAN — should produce zero findings
// Tests that SecretGuard does NOT produce false positives

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { S3Client } = require('@aws-sdk/client-s3');

// Correct: all secrets from environment variables
const s3 = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  // No credentials here — uses IAM role / env vars automatically
});

// Correct: JWT secret from env
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) throw new Error('JWT_SECRET environment variable is required');

// These look like secrets but are NOT — they are hash outputs, not keys
const sha256Hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const uuid = '550e8400-e29b-41d4-a716-446655440000';

// Placeholder/example strings — should NOT be flagged
const exampleKey = 'YOUR_API_KEY_HERE';
const testValue = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// Comments mentioning secrets — should NOT be flagged
// password should be stored in env vars, not in code
// Example: export API_KEY=your-actual-key-here

module.exports = { s3, stripe };
