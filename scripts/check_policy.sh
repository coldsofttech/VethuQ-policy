#!/usr/bin/env bash
# Validate the example payloads and the live v1/policy.json (same checks as CI, minus the
# previous-commit sequence comparison, which CI does with git history).
set -euo pipefail
cd "$(dirname "$0")/.."

for f in examples/v1/*.payload.json; do
  python scripts/validate_policy.py payload "$f"
done
python scripts/validate_policy.py envelope v1/policy.json --keys-dir keys
