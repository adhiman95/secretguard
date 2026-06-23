// Simulated leaky config file — DO NOT commit real secrets like this

const config = {
  // AWS credentials
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // Database
  database: 'postgresql://admin:SuperSecret123!@db.prod.example.com:5432/myapp',

  // Third party
  stripeKey: 'STRIPE_KEY_REDACTED_FOR_TEST_FIXTURE',
  sendgridKey: 'SG.DUMMYKEY00000000000000.DUMMYKEY000000000000000000000000000000000000000000',
  slackToken: 'xoxb-0000-0000-DUMMY-TOKEN-VALUE-HERE',

  // Misc
  githubToken: 'ghp_DUMMY_TOKEN_VALUE_FOR_TESTING_PURPOSES',
  openaiKey: 'sk-proj-DUMMY_TOKEN_VALUE_FOR_TESTING_PURPOSES_00000',
};

// Auth
const password = 'hunter2_production_db';
const jwtSecret = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

module.exports = config;
