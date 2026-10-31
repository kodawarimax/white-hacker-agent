#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "============================================================================"
echo "  🛡️ AI White Hacker Agent — 100点満点セキュリティ監査＆保守提案書生成"
echo "============================================================================"
echo ""

TARGET_DIR="${1:-}"
if [ -z "${TARGET_DIR}" ]; then
  if command -v osascript >/dev/null 2>&1 && [ -z "${CI:-}" ]; then
    TARGET_DIR="$(osascript -e 'try
      POSIX path of (choose folder with prompt "セキュリティ監査を行うアプリのフォルダを選択してください（キャンセル時は現在のフォルダ）")
    on error
      ""
    end try' 2>/dev/null || true)"
  fi
fi

if [ -z "${TARGET_DIR}" ]; then
  TARGET_DIR="${SCRIPT_DIR}"
fi

echo "[INFO] 監査対象フォルダ: ${TARGET_DIR}"
python3 "${SCRIPT_DIR}/white_hacker_runner.py" scan --target "${TARGET_DIR}" --open
