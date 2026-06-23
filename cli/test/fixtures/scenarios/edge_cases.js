// Edge cases — tests subtle detection scenarios

// 1. Secret split across variable assignment (some tools miss this)
const part1 = 'sk_live_FAKE_';
const stripeKey = part1 + 'EXAMPLEKEY000000000000'; // split — hard to detect statically

// 2. Secret in object destructuring
const { GITHUB_TOKEN: ghToken = 'ghp_FAKE_EXAMPLE_EDGE_CASE_00000' } = process.env;

// 3. Secret in template literal (should detect)
const authHeader = `Bearer ghp_FAKE_EXAMPLE_TEMPLATE_TOKEN_000`;

// 4. Multiline secret assignment
const awsSecret =
  'wJalrXUtnFEMI' +
  '/K7MDENG/bPxRfi'; // split string — static analysis can't fully reassemble

// 5. Secret in JSON config embedded in JS
const config = JSON.parse('{"api_key": "AIzaSyFAKE_EXAMPLE_GOOGLE_KEY_0000"}');

// 6. Secret in array
const keys = [
  'ghp_FAKE_EXAMPLE_ARRAY_TOKEN_0000',
  process.env.BACKUP_KEY
];

// 7. Secret assigned via ternary
const apiKey = process.env.NODE_ENV === 'test'
  ? 'sk_test_FAKE_EXAMPLE_TERNARY_KEY_000'
  : process.env.STRIPE_KEY;

// 8. Double-encoded looking value (not a real secret — high entropy string)
const notASecret = 'aGVsbG8gd29ybGQ='; // base64 of "hello world" — too short/low entropy

// 9. Private key header (always critical)
const fakePem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4mSa2zoNhwUFCfcPGWVHe38cPL1
-----END RSA PRIVATE KEY-----`;
