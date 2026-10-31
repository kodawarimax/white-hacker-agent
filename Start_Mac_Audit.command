#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "============================================================================"
echo "  🛡️ AI White Hacker Agent — 100点満点セキュリティ監査＆保守提案書生成"
echo "============================================================================"
echo ""
python3 "${SCRIPT_DIR}/white_hacker_runner.py" scan --target "${SCRIPT_DIR}" --include-host-audit --open
