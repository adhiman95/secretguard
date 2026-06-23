// Simulated leaky config file — DO NOT commit real secrets like this

const config = {
  // AWS credentials
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // Database
  database: 'postgresql://admin:SuperSecret123!@db.prod.example.com:5432/myapp',

  // Third party
  stripeKey: 'sk_live_FAKE_EXAMPLE_KEY_DO_NOT_USE_REAL',
  sendgridKey: 'SG.FAKEEXAMPLEKEY.FAKEEXAMPLEKEYXXXXXXXXXXXXXXXXXXXXXXXXXX',
  slackToken: 'xoxb-0000-FAKE-EXAMPLE-TOKEN-DO-NOT-USE',

  // Misc
  githubToken: 'ghp_FAKE_EXAMPLE_TOKEN_DO_NOT_USE_REAL',
  openaiKey: 'sk-proj-FAKE_EXAMPLE_KEY_DO_NOT_USE_REAL',
};

// Auth
const password = 'hunter2_production_db';
const jwtSecret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

module.exports = config;
