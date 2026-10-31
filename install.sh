#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_HOME="${HOME}/.white-hacker"
CLAUDE_AGENTS_DIR="${HOME}/.claude/agents"

echo "🛡️ AIホワイトハッカー (White Hacker Agent) をインストールしています..."

# 1. CLI本体の配置
mkdir -p "${INSTALL_HOME}"
cp "${SCRIPT_DIR}/white_hacker_runner.py" "${INSTALL_HOME}/white_hacker_runner.py"
chmod +x "${INSTALL_HOME}/white_hacker_runner.py"

# 2. Claude Code / Codex 用グローバルエージェント登録
mkdir -p "${CLAUDE_AGENTS_DIR}"
cp "${SCRIPT_DIR}/agents/white-hacker.md" "${CLAUDE_AGENTS_DIR}/white-hacker.md"

# 3. ワークスペースの .agents/agents がある場合はそちらにも登録
if [ -d "${PWD}/.agents/agents" ]; then
  cp "${SCRIPT_DIR}/agents/white-hacker-subagent.md" "${PWD}/.agents/agents/white-hacker.md"
  echo "  ✓ ワークスペース (.agents/agents/white-hacker.md) に登録しました"
fi

echo ""
echo "✅ インストール完了！"
echo "----------------------------------------------------------------"
echo "【すぐに試す（3秒デモ）】"
echo "  python3 ~/.white-hacker/white_hacker_runner.py demo"
echo ""
echo "【自分のアプリを検査する】"
echo "  python3 ~/.white-hacker/white_hacker_runner.py scan --target ./my-app"
echo "  python3 ~/.white-hacker/white_hacker_runner.py view --open"
echo ""
echo "【Claude Code / Codex / Antigravity から頼む】"
echo "  「white-hacker でこのフォルダの弱点を調べて直して」と話しかけてください。"
echo "----------------------------------------------------------------"
