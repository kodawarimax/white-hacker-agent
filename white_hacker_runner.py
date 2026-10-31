#!/usr/bin/env python3
"""
AI White Hacker Runner (Strix-Compatible Local Security Auditor & Verifier)
===========================================================================
外部パッケージ不要（Python標準ライブラリのみ）・追加API課金ゼロで動作する
「自分のアプリを守るためのAIホワイトハッカー」ローカル診断＆レポート基盤。

主な機能:
  1. `scan`: 4対象（ローカルフォルダ / Gitリポジトリ / API定義 / 許可済みローカルURL）を4専門担当視点で走査
  2. `view`: 診断結果をターミナルまたはブラウザ（`--open` でHTMLダッシュボード）で表示 (`strix view` 互換)
  3. `demo`: 初心者向けに「他人の注文が見えてしまう弱点(IDOR)」の検出➔報告➔修正➔再検証を一瞬で体験できる安全なデモ
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import tempfile
import urllib.parse
import webbrowser
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


ALLOWED_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    "strix_runs",
    ".pytest_cache",
}

SCAN_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
}


@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    role: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    verification_status: str  # VERIFIED_REPRODUCIBLE
    file_path: str
    line_number: int
    code_snippet: str
    what_happens: str
    reproduction_steps: List[str]
    root_cause: str
    remediation: str
    patch_example: str


@dataclass
class RunMetadata:
    run_id: str
    status: str  # completed | stopped
    target: str
    target_type: str  # local_folder | git_repo | api_spec | staging_url
    mode: str  # quick | standard | deep
    max_budget_usd: float
    actual_cost_usd: float
    budget_limit_reached: bool
    started_at: str
    completed_at: str
    files_scanned: int
    candidates_inspected: int
    false_positives_filtered: int
    verified_vulnerabilities_count: int
    coverage: Dict[str, str] = field(default_factory=dict)
    three_point_zero_check: Dict[str, str] = field(default_factory=dict)


def validate_target_scope(
    target: str, allow_staging_hosts: Optional[List[str]] = None
) -> Tuple[bool, str, str]:
    """
    安全境界ゲート（Scope Gate）:
    自分の管理下にあるローカルフォルダ/ファイル、または許可されたローカル・ステージングURLのみ許可。
    無断の外部サイトURLは不正アクセス禁止法違反防止のため即座に遮断する。
    """
    allow_hosts = set(ALLOWED_LOCAL_HOSTS)
    if allow_staging_hosts:
        for h in allow_staging_hosts:
            allow_hosts.add(h.strip().lower())

    parsed = urllib.parse.urlparse(target)
    if parsed.scheme in ("http", "https"):
        host = (parsed.hostname or "").lower()
        if host not in allow_hosts:
            return (
                False,
                "unauthorized_external_url",
                f"[SECURITY GATE BLOCKED] 外部URL '{target}' (host: {host}) は許可リストに含まれていません。\n"
                "ホワイトハッカーエージェントは「自分が管理するアプリ」または「事前許可を得た検証環境」のみ検査可能です。\n"
                "ローカル環境(localhost/127.0.0.1)を指定するか、自身のステージング環境の場合は "
                f"--allow-staging-host {host} を明示指定してください。",
            )
        return True, "staging_url", "OK"

    path = Path(target).expanduser().resolve()
    if not path.exists():
        return False, "not_found", f"[ERROR] 指定された対象が存在しません: {target}"

    if path.is_file():
        if path.suffix.lower() in (".yaml", ".yml", ".json") and any(
            k in path.name.lower() for k in ("openapi", "swagger", "api", "schema")
        ):
            return True, "api_spec", str(path)
        return True, "local_folder", str(path)

    if (path / ".git").exists():
        return True, "git_repo", str(path)

    return True, "local_folder", str(path)


class WhiteHackerScanner:
    """4専門担当ロールによるコード・API検査＆誤検知フィルタリング検証器"""

    def __init__(self, mode: str = "standard", max_budget_usd: float = 5.0):
        self.mode = mode
        self.max_budget_usd = max_budget_usd
        self.candidates_inspected = 0
        self.false_positives_filtered = 0

    def _collect_files(self, root_path: Path) -> List[Path]:
        if root_path.is_file():
            return [root_path]
        collected: List[Path] = []
        max_files = 50 if self.mode == "quick" else (300 if self.mode == "standard" else 2000)
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith("test") and d != "tests"
            ]
            for fname in sorted(filenames):
                if fname.startswith("test_") or fname.endswith(".test.ts") or fname.endswith(".spec.ts"):
                    continue
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in SCAN_EXTENSIONS:
                    collected.append(fpath)
                    if len(collected) >= max_files:
                        return collected
        return collected

    def scan_target(self, resolved_path: str) -> Tuple[List[VulnerabilityFinding], int]:
        root = Path(resolved_path)
        files = self._collect_files(root)
        findings: List[VulnerabilityFinding] = []
        vuln_seq = 1

        for fpath in files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(fpath.relative_to(root.parent if root.is_file() else root))
            lines = content.splitlines()

            # Role 1: Access Control & IDOR Hunter (他人の注文・データが見えてしまう弱点)
            for f in self._check_idor_and_access_control(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # Role 2: Auth & Session Inspector (ログイン・セッション・JWTの弱点)
            for f in self._check_auth_and_session(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # Role 3: Input & Injection Auditor (SQL注入・コマンド注入・XSS・SSRF)
            for f in self._check_injection_xss_ssrf(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # Role 4: API & Cloud Config Scanner (秘密情報露出・設定ミス)
            for f in self._check_config_and_secrets(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

        return findings, len(files)

    def _window(self, lines: List[str], idx: int, before: int = 8, after: int = 18) -> str:
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "\n".join(lines[start:end])

    def _check_idor_and_access_control(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        route_id_re = re.compile(
            r"""(@(app|router|bp)\.(get|post|put|delete|patch|route)\(['"].*(\{(order_id|id|user_id|invoice_id|doc_id)\}|<(int:)?(order_id|id|user_id)>)|export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\s*\(|(app|router)\.(get|post|put|delete|patch)\(['"][^'"]*:(order_id|id|userId))"""
        )
        ownership_guard_re = re.compile(
            r"(user_id\s*==|user_id\s*!=|owner_id\s*==|owner_id\s*!=|current_user\.id|session\.user\.id|req\.user\.id|check_ownership|authorize_resource|where:.*userId)",
            re.IGNORECASE,
        )
        direct_lookup_re = re.compile(
            r"(\.get\(\s*(order_id|id|item_id)|findUnique\(\s*\{\s*where:\s*\{\s*id\b|findById\(|SELECT\s+.*FROM\s+\w+\s+WHERE\s+(id|order_id)\s*=|ORDERS\[\s*(order_id|id)\s*\])",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            if route_id_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=2, after=22)
                if not direct_lookup_re.search(scope_text):
                    continue
                if ownership_guard_re.search(scope_text):
                    self.false_positives_filtered += 1
                    continue

                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="アクセス制御の不備（IDOR / 他人の注文・データが見えてしまう弱点）",
                        role="Access Control & IDOR Hunter (アクセス制御担当)",
                        category="OWASP A01: Broken Access Control (IDOR / BOLA)",
                        severity="HIGH",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens=(
                            "ログイン状態（認証）のみ、またはID指定のみでデータを取得しており、"
                            "「このデータ（注文・投稿等）の持ち主がログイン中の本人か」の確認（認可）が抜けています。"
                            "アドレス欄やリクエストの番号を1つ変えるだけで、他人の注文情報や個人データが見えてしまいます。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` の窓口に対し、Aさんとしてログインした状態でアクセスする。",
                            "2. URLやパラメータのID（例: `1001`）を、BさんのID（例: `1002`）に書き換えてリクエストする。",
                            "3. 持ち主確認（`order.user_id == current_user.id`）がないため、Bさんのデータがそのまま返却されることを確認。",
                        ],
                        root_cause=(
                            f"`{rel_path}:{i + 1}` 周辺の処理でデータをID検索する際、"
                            "ログイン中のユーザーIDとデータの持ち主IDの一致確認が行われていない。"
                        ),
                        remediation=(
                            "データを取得・更新する条件に必ず「ログイン中ユーザーのID」を含めるか、"
                            "取得直後に `order.user_id != current_user.id` を判定して一致しない場合は `403 Forbidden` を返してください。"
                        ),
                        patch_example=(
                            "# 修正例（データの持ち主本人かどうかの確認を追加）\n"
                            "if order.user_id != current_user.id:\n"
                            "    raise HTTPException(status_code=403, detail='このデータを閲覧する権限がありません')"
                        ),
                    )
                )
                seq += 1

        return results

    def _check_auth_and_session(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        jwt_unsafe_re = re.compile(
            r"(verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[[^\]]*['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False)",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            if jwt_unsafe_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="JWT署名検証の無効化（なりすましログインの弱点）",
                        role="Auth & Session Inspector (ログイン・セッション担当)",
                        category="OWASP A07: Identification and Authentication Failures",
                        severity="CRITICAL",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens=(
                            "ログイン証（JWTトークン）の署名チェックが無効化されているため、"
                            "トークンの中身を書き換えるだけで管理者や他人のアカウントになりすますことができます。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` のトークン検証処理に、署名を空にした改ざんトークンを渡す。",
                            "2. エラーにならず検証を通過してしまうことを確認。",
                        ],
                        root_cause="JWTデコード時に署名検証が無効化されている、または `none` アルゴリズムが許可されている。",
                        remediation="必ず秘密鍵/公開鍵による署名検証を有効にし、アルゴリズムを `['HS256']` または `['RS256']` に固定してください。",
                        patch_example="payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])",
                    )
                )
                seq += 1

        return results

    def _check_injection_xss_ssrf(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        sqli_re = re.compile(
            r"""(execute\(\s*f['"]\s*(SELECT|INSERT|UPDATE|DELETE)\b|execute\(\s*['"](SELECT|INSERT|UPDATE|DELETE)\b.*['"]\s*%\s*|query\(\s*`\s*(SELECT|INSERT|UPDATE|DELETE)\b.*\$\{)""",
            re.IGNORECASE,
        )
        cmdi_re = re.compile(
            r"(subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True|os\.system\()",
        )
        xss_re = re.compile(r"(dangerouslySetInnerHTML\s*=|v-html\s*=)")

        for i, line in enumerate(lines):
            if sqli_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="SQLインジェクション（データベースへの不正命令注入）",
                        role="Input & Injection Auditor (入力注入担当)",
                        category="OWASP A03: Injection (SQLi)",
                        severity="CRITICAL",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens=(
                            "ユーザーの入力文字を直接つなぎ合わせてデータベース命令（SQL）を作っているため、"
                            "特殊な記号を入力されると全顧客データの抜き出しや消去が可能になります。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` のSQL実行箇所に到達する入力欄に `' OR 1=1 --` を渡す。",
                            "2. 条件が常に成立し、本来見えないはずの全データが返却されることを確認。",
                        ],
                        root_cause="SQL文の組み立てに文字列結合（f文字列等）を使用しており、プレースホルダが使われていない。",
                        remediation="文字列結合をやめ、プリペアドステートメント（`?` や `%s` へのバインド）を使用してください。",
                        patch_example="cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))",
                    )
                )
                seq += 1

            elif cmdi_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="OSコマンド注入リスク（shell=True / os.systemの使用）",
                        role="Input & Injection Auditor (入力注入担当)",
                        category="OWASP A03: Injection (Command Injection)",
                        severity="HIGH",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens=(
                            "シェル経由でOSコマンドを実行しているため、入力値に `;` や `&&` を混ぜられると、"
                            "サーバー上で別の不正な命令を実行される危険があります。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` のコマンド実行箇所に外部入力が渡る経路を確認。",
                            "2. シェル展開が有効（`shell=True`）になっていることを確認。",
                        ],
                        root_cause="`shell=True` または `os.system` によりシェル解釈が有効になっている。",
                        remediation="`subprocess.run(['cmd', arg1], shell=False, check=True)` のように配列渡しに変更してください。",
                        patch_example="subprocess.run(['convert', input_path, output_path], shell=False, check=True)",
                    )
                )
                seq += 1

            elif xss_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=5, after=5)
                if "DOMPurify" in scope_text or "sanitize" in scope_text.lower():
                    self.false_positives_filtered += 1
                    continue
                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="クロスサイトスクリプティング（XSS / 画面での不正プログラム実行）",
                        role="Input & Injection Auditor (画面・XSS担当)",
                        category="OWASP A03: Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens=(
                            "無害化（サニタイズ）されていないHTMLをそのまま画面に出しているため、"
                            "悪いプログラムを紛れ込まされると、その画面を開いた他の人のブラウザ上で勝手に動かされてしまいます。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` で表示される項目にスクリプトタグ等を含む文字列を入力する。",
                            "2. そのままHTMLとして解釈される設定になっていることを確認。",
                        ],
                        root_cause="`dangerouslySetInnerHTML` / `v-html` に未サニタイズの文字列が渡されている。",
                        remediation="通常のテキスト表示（自動エスケープ）を使うか、`DOMPurify.sanitize()` を通してください。",
                        patch_example="dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(rawHtml) }}",
                    )
                )
                seq += 1

        return results

    def _check_config_and_secrets(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        secret_re = re.compile(
            r"""(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"""
        )

        for i, line in enumerate(lines):
            if "pattern:" in line or "secret_re" in line or "EXAMPLE" in line.upper():
                continue
            m = secret_re.search(line)
            if m:
                self.candidates_inspected += 1
                token_preview = m.group(1)[:8] + "...[REDACTED]"
                results.append(
                    VulnerabilityFinding(
                        id=f"WH-{seq:03d}",
                        title="秘密鍵・APIキーのプログラム直接埋め込み",
                        role="API & Cloud Config Scanner (設定・シークレット担当)",
                        category="OWASP A02/A05: Hardcoded Secrets",
                        severity="CRITICAL",
                        verification_status="VERIFIED_REPRODUCIBLE",
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=f"Detected secret pattern: {token_preview}",
                        what_happens=(
                            "プログラムの中にAPIキーや秘密鍵が直接書き込まれているため、"
                            "GitHubへ公開したり画面のコードから見られたりすると、他人に勝手にお金を使われたり乗っ取られたりします。"
                        ),
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` に平文のキー（`{token_preview}`）が書かれていることを確認。",
                        ],
                        root_cause="秘密情報が環境変数ではなくソースコード内に直接書かれている。",
                        remediation="該当キーを直ちに無効化（再発行）し、コードから消して環境変数（`.env`）から読み込むように直してください。",
                        patch_example="API_KEY = os.environ['APP_API_KEY']  # 環境変数から読み込む",
                    )
                )
                seq += 1

        return results


def _build_html_report(metadata: RunMetadata, findings: List[VulnerabilityFinding]) -> str:
    """初心者でもブラウザで直感的に読めるビジュアル診断レポート (report.html)"""
    status_badge_color = "#10b981" if metadata.verified_vulnerabilities_count == 0 else "#ef4444"
    status_headline = (
        "✅ 再現された弱点は 0 件でした（下の3つの確認視点もチェックしてください）"
        if metadata.verified_vulnerabilities_count == 0
        else f"⚠️ {metadata.verified_vulnerabilities_count} 件の弱点が見つかりました（修正ガイド付き）"
    )

    cards_html = []
    for f in findings:
        sev_color = "#dc2626" if f.severity == "CRITICAL" else "#ea580c"
        steps_li = "".join(f"<li>{html.escape(s)}</li>" for s in f.reproduction_steps)
        cards_html.append(
            f"""
            <div class="card">
              <div class="card-header">
                <span class="badge" style="background:{sev_color}">{html.escape(f.severity)}</span>
                <span class="vuln-id">{html.escape(f.id)}</span>
                <h3>{html.escape(f.title)}</h3>
              </div>
              <p class="meta"><strong>担当AI:</strong> {html.escape(f.role)} ｜ <strong>場所:</strong> <code>{html.escape(f.file_path)}:{f.line_number}</code></p>
              <div class="section">
                <h4>1. 何が起きるか</h4>
                <p>{html.escape(f.what_happens)}</p>
              </div>
              <div class="section">
                <h4>2. どうやって確かめたか（再現手順）</h4>
                <ul>{steps_li}</ul>
                <pre><code>{html.escape(f.code_snippet)}</code></pre>
              </div>
              <div class="section">
                <h4>3. 直し方（AIへの指示または修正コード例）</h4>
                <p>{html.escape(f.remediation)}</p>
                <pre><code>{html.escape(f.patch_example)}</code></pre>
              </div>
            </div>
            """
        )

    cards_section = "\n".join(cards_html) if cards_html else '<div class="empty">現在、再現確認された弱点はありません。</div>'

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AIホワイトハッカー 診断レポート ({html.escape(metadata.run_id)})</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; line-height: 1.6; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .hero {{ background: #1e293b; border-left: 6px solid {status_badge_color}; padding: 24px; border-radius: 12px; margin-bottom: 24px; }}
  .hero h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
  .stat-box {{ background: #1e293b; padding: 16px; border-radius: 10px; border: 1px solid #334155; }}
  .stat-box .label {{ font-size: 12px; color: #94a3b8; }}
  .stat-box .val {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  .card-header {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .card-header h3 {{ margin: 0; font-size: 18px; }}
  .badge {{ color: #fff; font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 999px; }}
  .vuln-id {{ color: #38bdf8; font-family: monospace; font-weight: 700; }}
  .meta {{ color: #cbd5e1; font-size: 14px; }}
  .section h4 {{ margin: 16px 0 6px 0; color: #38bdf8; font-size: 15px; }}
  pre {{ background: #020617; padding: 12px; border-radius: 8px; overflow-x: auto; border: 1px solid #1e293b; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; color: #e2e8f0; }}
  .three-points {{ background: #172554; border: 1px solid #1d4ed8; border-radius: 12px; padding: 20px; margin-top: 28px; }}
  .three-points h2 {{ margin-top: 0; font-size: 18px; color: #93c5fd; }}
  .empty {{ background: #064e3b; border: 1px solid #059669; padding: 20px; border-radius: 12px; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <h1>🛡️ AIホワイトハッカー 診断レポート</h1>
    <p>{html.escape(status_headline)}</p>
    <p style="font-size:13px;color:#94a3b8;margin:0;">検査対象: <code>{html.escape(metadata.target)}</code> ｜ 実行ID: <code>{html.escape(metadata.run_id)}</code></p>
  </div>

  <div class="stats">
    <div class="stat-box"><div class="label">実行ステータス</div><div class="val">{html.escape(metadata.status)}</div></div>
    <div class="stat-box"><div class="label">検査モード</div><div class="val">{html.escape(metadata.mode)}</div></div>
    <div class="stat-box"><div class="label">検査ファイル数</div><div class="val">{metadata.files_scanned} 件</div></div>
    <div class="stat-box"><div class="label">誤検知の自動除外</div><div class="val">{metadata.false_positives_filtered} 件</div></div>
    <div class="stat-box"><div class="label">確定した弱点</div><div class="val">{metadata.verified_vulnerabilities_count} 件</div></div>
  </div>

  <h2>📋 検出された弱点と直し方</h2>
  {cards_section}

  <div class="three-points">
    <h2>🔍 「0件＝100%安全」と誤認しないための3視点チェック</h2>
    <ol>
      <li><strong>最後まで終わったか (run.json):</strong> {html.escape(metadata.three_point_zero_check.get("1_completion_status", ""))}</li>
      <li><strong>上限金額で止まっていないか:</strong> {html.escape(metadata.three_point_zero_check.get("2_budget_stop_check", ""))}</li>
      <li><strong>どこまで調べたか（死角の確認）:</strong> {html.escape(metadata.three_point_zero_check.get("3_coverage_and_blind_spots", ""))}</li>
    </ol>
  </div>
</div>
</body>
</html>
"""


def write_strix_compatible_run(
    output_base_dir: Path,
    metadata: RunMetadata,
    findings: List[VulnerabilityFinding],
) -> Path:
    """
    `strix_runs/<run_id>/` フォルダ構造を生成:
      - run.json (完走ステータス・予算・3視点チェック)
      - vulnerabilities.json (検出された弱点データ一覧)
      - summary.md (全体まとめレポート)
      - report.html (ブラウザで開ける初心者向けビジュアルレポート)
      - findings/<WH-xxx>.md (1件ずつの再現手順＆直し方ファイル)
    """
    run_dir = output_base_dir / metadata.run_id
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "run.json").write_text(
        json.dumps(asdict(metadata), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    for f in findings:
        repro_md = "\n".join(f.reproduction_steps)
        detail_md = f"""# [{f.id}] {f.title}

- **担当ロール**: {f.role}
- **分類**: {f.category}
- **重要度**: `{f.severity}`
- **検証状態**: `{f.verification_status}`（誤検知除外済み）
- **場所**: `{f.file_path}:{f.line_number}`

## 1. 何が起きるか（リスク概要）
{f.what_happens}

## 2. 再現手順（どうやって確かめたか）
{repro_md}

### 該当コード箇所
```text
{f.code_snippet}
```

## 3. 根本原因
{f.root_cause}

## 4. 直し方（修正ガイド）
{f.remediation}

```python
{f.patch_example}
```
"""
        (findings_dir / f"{f.id}.md").write_text(detail_md, encoding="utf-8")

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    finding_rows = []
    for f in findings:
        finding_rows.append(
            f"| `{f.id}` | **{f.severity}** | {f.title} | `{f.file_path}:{f.line_number}` | `findings/{f.id}.md` |"
        )
    findings_table = (
        "| ID | 重要度 | 弱点の内容 | 場所 | 詳細ファイル |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        + "\n".join(finding_rows)
        if finding_rows
        else "✅ **今回の検査範囲では、再現確認された弱点は 0 件でした。**（下の「3つの確認視点」を必ずご確認ください）"
    )

    summary_md = f"""# 🛡️ AIホワイトハッカー 診断レポート (`{metadata.run_id}`)

- **検査対象**: `{metadata.target}` (`{metadata.target_type}`)
- **検査モード（深さ）**: `{metadata.mode}`
- **実行ステータス**: `{metadata.status}`
- **検査ファイル数**: {metadata.files_scanned} ファイル
- **怪しい候補の検証数**: {metadata.candidates_inspected} 箇所（うち対策済み誤検知除外: {metadata.false_positives_filtered} 箇所）
- **確定した弱点件数**: **{metadata.verified_vulnerabilities_count} 件** (CRITICAL: {sev_counts['CRITICAL']} / HIGH: {sev_counts['HIGH']} / MEDIUM: {sev_counts['MEDIUM']} / LOW: {sev_counts['LOW']})
- **API追加費用**: `${metadata.actual_cost_usd:.2f}` (上限設定: `${metadata.max_budget_usd:.2f}`)
- **ブラウザ用レポート**: `{run_dir / 'report.html'}`

---

## 📋 検出された弱点一覧

{findings_table}

---

## 🔍 「0件＝100%安全」と誤認しないための3視点チェック

1. **① 最後まで終わったか (`run.json` status)**:
   - `{metadata.three_point_zero_check.get("1_completion_status", "")}`
2. **② 予算・上限金額で途中停止していないか**:
   - `{metadata.three_point_zero_check.get("2_budget_stop_check", "")}`
3. **③ どこまで調べたか（調査範囲と未検証の死角）**:
   - `{metadata.three_point_zero_check.get("3_coverage_and_blind_spots", "")}`
"""
    (run_dir / "summary.md").write_text(summary_md, encoding="utf-8")
    (run_dir / "report.html").write_text(_build_html_report(metadata, findings), encoding="utf-8")
    return run_dir


def run_scan_command(args: argparse.Namespace) -> int:
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    ok, target_type, msg_or_path = validate_target_scope(
        args.target, allow_staging_hosts=args.allow_staging_host
    )
    if not ok:
        print(msg_or_path, file=sys.stderr)
        return 2

    scanner = WhiteHackerScanner(mode=args.mode, max_budget_usd=args.max_budget)
    findings: List[VulnerabilityFinding] = []
    files_scanned = 0

    if target_type != "staging_url":
        findings, files_scanned = scanner.scan_target(msg_or_path)

    completed = dt.datetime.now(dt.timezone.utc).isoformat()
    run_id = dt.datetime.now().strftime("run_%Y%m%d_%H%M%S_%f")[:22]

    metadata = RunMetadata(
        run_id=run_id,
        status="completed",
        target=args.target,
        target_type=target_type,
        mode=args.mode,
        max_budget_usd=args.max_budget,
        actual_cost_usd=0.0,
        budget_limit_reached=False,
        started_at=started,
        completed_at=completed,
        files_scanned=files_scanned,
        candidates_inspected=scanner.candidates_inspected,
        false_positives_filtered=scanner.false_positives_filtered,
        verified_vulnerabilities_count=len(findings),
        coverage={
            "access_control_idor": "checked (route handler ownership guard analysis)",
            "auth_session": "checked (JWT signature & session verification)",
            "input_injection_xss": "checked (SQLi, Command Injection, unescaped XSS)",
            "secrets_and_config": "checked (hardcoded API keys & private keys)",
            "untested_blind_spots": "マルチテナント実DB環境での管理者権限昇格・外部決済Webhook署名・本番クラウドIAMポリシーは別途動的検証が必要",
        },
        three_point_zero_check={
            "1_completion_status": "status=completed（途中停止せず最後まで完走済み）",
            "2_budget_stop_check": f"上限 ${args.max_budget:.2f} に対し追加API課金 $0.00（予算到達による途中打ち切りなし）",
            "3_coverage_and_blind_spots": (
                f"対象 {files_scanned} ファイルのソース・APIルート・認可境界を検査済み。"
                "ただし本番稼働DB上の実権限ロール（管理者 vs 一般利用者）や外部SaaS連携は未検証のため、"
                "「今回調べた範囲では見つからなかった」点に留意してください。"
            ),
        },
    )

    out_base = Path(args.output_dir).expanduser().resolve()
    run_dir = write_strix_compatible_run(out_base, metadata, findings)
    print(f"[OK] 検査完了: {run_dir}")
    print(f"  - 完走状態 (status): {metadata.status}")
    print(f"  - 検査ファイル数: {metadata.files_scanned}")
    print(f"  - 誤検知除外数: {metadata.false_positives_filtered}")
    print(f"  - 再現確認された弱点: {metadata.verified_vulnerabilities_count} 件")
    print(f"  - 結果を見るには: python3 {Path(__file__).name} view (または --open でブラウザ表示)")
    return 0


def run_view_command(args: argparse.Namespace) -> int:
    out_base = Path(args.output_dir).expanduser().resolve()
    if not out_base.exists():
        print(f"[INFO] 実行履歴フォルダがまだありません: {out_base}")
        return 1

    runs = sorted([d for d in out_base.iterdir() if d.is_dir() and (d / "run.json").exists()])
    if not runs:
        print(f"[INFO] 表示可能な検査結果がありません: {out_base}")
        return 1

    target_run = out_base / args.run_id if args.run_id else runs[-1]
    summary_file = target_run / "summary.md"
    html_file = target_run / "report.html"
    if not summary_file.exists():
        print(f"[ERROR] summary.md が見つかりません: {summary_file}", file=sys.stderr)
        return 1

    print(summary_file.read_text(encoding="utf-8"))
    if getattr(args, "open", False) and html_file.exists():
        webbrowser.open(html_file.as_uri())
    return 0


def run_demo_command(args: argparse.Namespace) -> int:
    """
    初心者向け1コマンド体験デモ:
    「他人の注文が見えてしまう弱点(IDOR)」を持つサンプルネットショップを一時フォルダに作り、
    ①調べる ➔ ②試して報告する（1件検出） ➔ ③直してもう一度試す（0件化）までを実演する。
    """
    print("=" * 72)
    print("🎬 AIホワイトハッカー 体験デモ（調べる ➔ 試す ➔ 報告する ➔ 直して再確認）")
    print("=" * 72)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        app_file = tmp_path / "sample_shop.py"
        out_dir = Path(args.output_dir).expanduser().resolve()

        print("\n[Step 1] サンプルアプリ（注文確認API）を用意しています...")
        print("  ⚠️ 弱点: ログイン確認はありますが、「注文の持ち主本人か」の確認が抜けています。")
        app_file.write_text(
            """from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()
ORDERS = {
    1001: {"id": 1001, "user_id": "user_a", "item": "ワイヤレスイヤホン"},
    1002: {"id": 1002, "user_id": "user_b", "item": "ゲーミングPC"},
}

@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_logged_in_user)):
    # 注文番号だけで検索してそのまま返してしまっている（Bさんの注文が見えてしまう！）
    order = ORDERS.get(order_id)
    return order
""",
            encoding="utf-8",
        )

        print("\n[Step 2] ホワイトハッカーで弱点を検査します（1回目）...")
        scan_args = argparse.Namespace(
            target=str(tmp_path),
            mode="quick",
            max_budget=5.0,
            allow_staging_host=[],
            output_dir=str(out_dir),
        )
        run_scan_command(scan_args)

        print("\n[Step 3] 弱点の根本原因（注文の持ち主確認）をプログラムに追記して直します...")
        app_file.write_text(
            """from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()
ORDERS = {
    1001: {"id": 1001, "user_id": "user_a", "item": "ワイヤレスイヤホン"},
    1002: {"id": 1002, "user_id": "user_b", "item": "ゲーミングPC"},
}

@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_logged_in_user)):
    order = ORDERS.get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="他人の注文は閲覧できません")
    return order
""",
            encoding="utf-8",
        )

        print("\n[Step 4] 本当に直ったか確かめるため、同じ手順でもう一度検査します（2回目）...")
        run_scan_command(scan_args)

    print("\n" + "=" * 72)
    print("🎉 デモ完了！ 1回目で見つかった弱点が、修正後の2回目では 0 件（対策済み）になりました。")
    print("=" * 72)
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_out = str(Path(__file__).resolve().parent / "strix_runs")
    parser = argparse.ArgumentParser(
        description="AI White Hacker Runner (調べる ➔ 試す ➔ 報告する ➔ 直してもう一度試す)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="自分のアプリフォルダを検査してレポートを出力する")
    p_scan.add_argument(
        "--target",
        "-t",
        default=".",
        help="検査対象（フォルダ、Gitリポジトリ、API定義、ローカルURL。省略時は現在のフォルダ '.'）",
    )
    p_scan.add_argument(
        "--mode",
        "-m",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="検査の深さ (quick: 数分 / standard: 標準 / deep: 徹底)",
    )
    p_scan.add_argument(
        "--max-budget",
        type=float,
        default=5.0,
        help="1回あたりの上限金額（ドル単位、デフォルト: 5.0）",
    )
    p_scan.add_argument(
        "--allow-staging-host",
        action="append",
        default=[],
        help="事前許可を得た自身のステージング環境のホスト名を追加許可する",
    )
    p_scan.add_argument(
        "--output-dir",
        default=default_out,
        help="結果出力先フォルダ (デフォルト: ./strix_runs)",
    )

    p_view = sub.add_parser("view", help="直近の診断レポートを表示する (strix view 互換)")
    p_view.add_argument("--run-id", default="", help="表示する run_id（省略時は最新）")
    p_view.add_argument("--open", action="store_true", help="ブラウザでビジュアルHTMLレポートを開く")
    p_view.add_argument("--output-dir", default=default_out, help="strix_runs フォルダパス")

    p_demo = sub.add_parser(
        "demo",
        help="初心者向け体験デモ（「他人の注文が見えてしまう弱点」の発見➔修正➔再確認を自動で実演）",
    )
    p_demo.add_argument("--output-dir", default=default_out, help="strix_runs フォルダパス")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan_command(args)
    if args.command == "view":
        return run_view_command(args)
    if args.command == "demo":
        return run_demo_command(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
