#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_HOME="${HOME}/.white-hacker"
CLAUDE_AGENTS_DIR="${HOME}/.claude/agents"

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "${INSTALL_HOME}"
  rm -f "${CLAUDE_AGENTS_DIR}/white-hacker.md"
  echo "✅ AIホワイトハッカー (White Hacker Agent) をアンインストールしました。"
  exit 0
fi

if [ "${1:-}" = "--check" ]; then
  python3 "${SCRIPT_DIR}/white_hacker_runner.py" --help >/dev/null
  echo "✅ White Hacker Agent 動作確認 OK"
  exit 0
fi

echo "🛡️ AIホワイトハッカー (White Hacker Agent) をインストールしています..."

# 1. CLI本体の配置
mkdir -p "${INSTALL_HOME}"
cp "${SCRIPT_DIR}/white_hacker_runner.py" "${INSTALL_HOME}/white_hacker_runner.py"
chmod +x "${INSTALL_HOME}/white_hacker_runner.py"

# 2. Claude Code / Codex 用グローバルエージェント登録
mkdir -p "${CLAUDE_AGENTS_DIR}"
cp "${SCRIPT_DIR}/agents/white-hacker.md" "${CLAUDE_AGENTS_DIR}/white-hacker.md"

# 3. ワークスペースの .agents/agents または Antigravity (.agent/skills) がある場合はそちらにも登録
if [ -d "${PWD}/.agents/agents" ]; then
  cp "${SCRIPT_DIR}/agents/white-hacker-subagent.md" "${PWD}/.agents/agents/white-hacker.md"
  echo "  ✓ ワークスペース (.agents/agents/white-hacker.md) に登録しました"
fi
for skill_root in "${PWD}/.agent/skills" "${PWD}/.agents/skills"; do
  if [ -d "${skill_root}" ]; then
    mkdir -p "${skill_root}/white-hacker"
    cp "${SCRIPT_DIR}/agents/white-hacker.md" "${skill_root}/white-hacker/SKILL.md"
    echo "  ✓ Antigravity スキル (${skill_root}/white-hacker/SKILL.md) に登録しました"
  fi
done

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
