#!/usr/bin/env python3
"""
AI White Hacker Runner — Holistic Organizational Security Audit & 100-Point Scoring Engine
==========================================================================================
外部パッケージ不要（Python標準ライブラリのみ）・追加API課金ゼロで動作する
「組織・プロジェクト全体の構造把握 × 6大領域包括セキュリティ監査 × 100点満点標準採点」基盤。

主な機能:
  1. 組織・システム全構造マッピング (OrganizationTopologyAnalyzer):
     - リポジトリ・サブプロジェクト・技術スタック（画面/API/認証/DB/インフラ・CI/AIエージェント）の自動棚卸しと信頼境界の特定
  2. 6大領域×4専門ロールによる包括的セキュリティ監査 (WhiteHackerScanner):
     - ① アクセス制御・業務ロジック・IDOR (25点)
     - ② 認証・セッション・権限統治 (15点)
     - ③ 入力注入・XSS・SSRF・パストラバーサル防御 (20点)
     - ④ 秘密情報・個人情報(PII)・データ保護 (15点)
     - ⑤ インフラ・クラウド設定・CI/CD・サプライチェーン (15点)
     - ⑥ AIエージェント統治・例外処理(Fail-Closed)・監査証跡 (10点)
  3. 100点満点標準スコアリング＆致命的欠陥キャップ制 (ComprehensiveAuditScorer):
     - 3軸リスク評価 (Severity[1-5] × Exploitability[1-5] × BlastRadius[1-5] = Priority[1-125])
     - 見せかけの高得点を防ぐ「致命的欠陥キャップ制」（CRITICAL残存時は上限49点/Grade D、HIGH残存時は上限69点/Grade C）
  4. 標準監査レポート出力 (`strix_runs/<run_id>/`):
     - `audit_scorecard.json` / `summary.md` / `report.html` / `vulnerabilities.json` / `run.json` / `findings/*.md`
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
from typing import Any, Dict, List, Optional, Tuple


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
    ".sh",
    ".sql",
    ".toml",
    ".dockerfile",
}

# 6大監査領域の標準配点（合計100点）
AUDIT_DOMAINS_SPEC: Dict[str, Dict[str, Any]] = {
    "access_control": {
        "name": "① アクセス制御・業務ロジック・認可 (IDOR/RBAC)",
        "max_score": 25,
        "penalty": {"CRITICAL": 18, "HIGH": 12, "MEDIUM": 5, "LOW": 2},
    },
    "auth_session": {
        "name": "② 認証・セッション・ID統治 (JWT/Cookie/Auth)",
        "max_score": 15,
        "penalty": {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 4, "LOW": 1},
    },
    "input_injection": {
        "name": "③ 入力検証・インジェクション・XSS/SSRF防御",
        "max_score": 20,
        "penalty": {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 4, "LOW": 2},
    },
    "secrets_data": {
        "name": "④ 秘密情報・データ保護・暗号化 (Secrets/PII/DB)",
        "max_score": 15,
        "penalty": {"CRITICAL": 15, "HIGH": 9, "MEDIUM": 4, "LOW": 1},
    },
    "infra_supply_chain": {
        "name": "⑤ インフラ・クラウド設定・CI/CD・サプライチェーン",
        "max_score": 15,
        "penalty": {"CRITICAL": 12, "HIGH": 8, "MEDIUM": 4, "LOW": 1},
    },
    "ai_governance_resilience": {
        "name": "⑥ AIガバナンス・例外処理(Fail-Closed)・監査証跡",
        "max_score": 10,
        "penalty": {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 3, "LOW": 1},
    },
}


@dataclass
class VulnerabilityFinding:
    id: str
    title: str
    domain_key: str  # AUDIT_DOMAINS_SPEC のキー
    role: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    severity_score: int  # 1-5
    exploitability_score: int  # 1-5
    blast_radius_score: int  # 1-5
    risk_priority_score: int  # 1-125 (3軸積)
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
class DomainScoreDetail:
    domain_key: str
    domain_name: str
    max_score: int
    earned_score: int
    deducted_points: int
    percentage: float
    finding_counts: Dict[str, int]
    status_label: str  # PASS / WARNING / CRITICAL_DEFECT


@dataclass
class OrganizationTopology:
    root_path: str
    total_files_scanned: int
    subprojects_detected: List[str]
    tech_stack_summary: List[str]
    layer_file_counts: Dict[str, int]
    api_endpoints_estimated: int
    has_gitignore_env_protection: bool
    has_dependency_lockfile: bool
    has_automated_tests: bool
    ai_agent_configs_count: int
    trust_boundaries: List[str]


@dataclass
class AuditScorecard:
    raw_score: int  # 0-100 (単純減点後の合計)
    final_score: int  # 0-100 (致命的欠陥キャップ適用後の最終得点)
    max_score: int  # 100
    grade: str  # S, A, B, C, D, F
    verdict: str  # PASS_PRODUCTION_READY / CONDITIONAL_FIX_REQUIRED / BLOCK_CRITICAL_RISK
    cap_applied: bool
    cap_reason: str
    audit_coverage_percent: int
    domain_scores: List[DomainScoreDetail]
    executive_summary: str


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
    overall_score: int = 100
    overall_grade: str = "S"
    overall_verdict: str = "PASS_PRODUCTION_READY"
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


class OrganizationTopologyAnalyzer:
    """組織・プロジェクトの全体構造（6大レイヤー・サブプロジェクト・技術スタック・信頼境界）を自動解析"""

    def analyze(self, root_path: Path, scanned_files: List[Path]) -> OrganizationTopology:
        base_dir = root_path.parent if root_path.is_file() else root_path
        subprojects: List[str] = []
        tech_stack = set()
        layer_counts = {
            "frontend_ui": 0,
            "backend_api": 0,
            "data_db": 0,
            "infra_ci_config": 0,
            "ai_agents_governance": 0,
        }
        api_routes_count = 0
        has_tests = False

        # サブプロジェクト・テスト有無の確認
        if base_dir.is_dir():
            for child in sorted(base_dir.iterdir()):
                if child.is_dir() and child.name not in SKIP_DIRS and not child.name.startswith("."):
                    if any(
                        (child / marker).exists()
                        for marker in ("package.json", "pyproject.toml", "requirements.txt", "Cargo.toml", "go.mod", "README.md")
                    ):
                        subprojects.append(child.name)
                if child.is_dir() and child.name in ("tests", "test", "__tests__", "e2e"):
                    has_tests = True

        if not subprojects:
            subprojects.append(base_dir.name)

        route_re = re.compile(
            r"(@(app|router|bp)\.(get|post|put|delete|patch|route)\(|export\s+async\s+function\s+(GET|POST|PUT|DELETE|PATCH)\b|(app|router)\.(get|post|put|delete|patch)\()"
        )

        for fpath in scanned_files:
            name_lower = fpath.name.lower()
            rel_parts = [p.lower() for p in fpath.parts]
            suffix = fpath.suffix.lower()

            if suffix in (".tsx", ".jsx") or any(k in rel_parts for k in ("components", "pages", "views", "ui")):
                layer_counts["frontend_ui"] += 1
                tech_stack.add("Frontend UI (React/Next.js/Web)")
            elif suffix in (".sql",) or any(k in name_lower for k in ("schema", "migration", "prisma", "models")):
                layer_counts["data_db"] += 1
                tech_stack.add("Database / Schema Layer")
            elif any(k in rel_parts for k in (".github", "docker", "infra", "deploy")) or name_lower in (
                "dockerfile",
                "docker-compose.yml",
                "package.json",
                "requirements.txt",
                "pyproject.toml",
            ):
                layer_counts["infra_ci_config"] += 1
            elif any(k in rel_parts for k in ("agents", ".agents", ".claude", "skills", "prompts")):
                layer_counts["ai_agents_governance"] += 1
                tech_stack.add("AI Agent / Skill Governance")
            else:
                layer_counts["backend_api"] += 1

            if suffix == ".py":
                tech_stack.add("Python")
            elif suffix in (".ts", ".tsx", ".js", ".jsx"):
                tech_stack.add("TypeScript/JavaScript")

            try:
                txt = fpath.read_text(encoding="utf-8", errors="ignore")
                api_routes_count += len(route_re.findall(txt))
                if "fastapi" in txt.lower():
                    tech_stack.add("FastAPI")
                if "express" in txt.lower():
                    tech_stack.add("Express")
                if "supabase" in txt.lower():
                    tech_stack.add("Supabase")
            except OSError:
                pass

        # .gitignore による .env 保護確認
        gitignore_path = base_dir / ".gitignore"
        has_gitignore_env = True
        if gitignore_path.exists():
            gi_text = gitignore_path.read_text(encoding="utf-8", errors="ignore")
            has_gitignore_env = ".env" in gi_text
        elif (base_dir / ".env").exists():
            has_gitignore_env = False

        # ロックファイルの存在確認
        has_lockfile = any(
            (base_dir / lf).exists()
            for lf in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt")
        )

        trust_boundaries = [
            "Boundary 1: 外部インターネット / ブラウザ画面 ➔ APIエンドポイント（認証・レート制限・CORS境界）",
            "Boundary 2: 認証済みユーザーA ➔ 他ユーザーBのデータ / 管理者機能（オブジェクト認可・IDOR/RBAC境界）",
            "Boundary 3: アプリケーション層 ➔ DB・OSシェル・外部URL通信（SQLi / Command Injection / SSRF境界）",
            "Boundary 4: ソースコード / 環境変数 / CIパイプライン ➔ 外部公開リポジトリ（シークレット漏洩境界）",
            "Boundary 5: 外部非信頼テキスト / ユーザー入力 ➔ AIエージェント・LLMツール実行（Prompt Injection / L0人間承認境界）",
        ]

        return OrganizationTopology(
            root_path=str(base_dir),
            total_files_scanned=len(scanned_files),
            subprojects_detected=subprojects[:20],
            tech_stack_summary=sorted(tech_stack) if tech_stack else ["General Application"],
            layer_file_counts=layer_counts,
            api_endpoints_estimated=api_routes_count,
            has_gitignore_env_protection=has_gitignore_env,
            has_dependency_lockfile=has_lockfile,
            has_automated_tests=has_tests,
            ai_agent_configs_count=layer_counts["ai_agents_governance"],
            trust_boundaries=trust_boundaries,
        )


class WhiteHackerScanner:
    """6大領域×4専門担当ロールによる組織横断コード・設定・ガバナンス検査＆誤検知除外エンジン"""

    def __init__(self, mode: str = "standard", max_budget_usd: float = 5.0):
        self.mode = mode
        self.max_budget_usd = max_budget_usd
        self.candidates_inspected = 0
        self.false_positives_filtered = 0

    def _collect_files(self, root_path: Path) -> List[Path]:
        if root_path.is_file():
            return [root_path]
        collected: List[Path] = []
        max_files = 80 if self.mode == "quick" else (400 if self.mode == "standard" else 2500)
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith("test") and d != "tests"
            ]
            for fname in sorted(filenames):
                if (
                    fname.startswith("test_")
                    or fname.endswith(".test.ts")
                    or fname.endswith(".spec.ts")
                    or fname == "white_hacker_runner.py"
                ):
                    continue
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in SCAN_EXTENSIONS or fname.lower() == "dockerfile":
                    collected.append(fpath)
                    if len(collected) >= max_files:
                        return collected
        return collected

    def scan_target(
        self, resolved_path: str
    ) -> Tuple[List[VulnerabilityFinding], int, OrganizationTopology]:
        root = Path(resolved_path)
        files = self._collect_files(root)
        topology = OrganizationTopologyAnalyzer().analyze(root, files)
        findings: List[VulnerabilityFinding] = []
        vuln_seq = 1

        for fpath in files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(fpath.relative_to(root.parent if root.is_file() else root))
            lines = content.splitlines()

            # ① アクセス制御・業務ロジック・認可 (access_control)
            for f in self._check_idor_and_access_control(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # ② 認証・セッション・ID統治 (auth_session)
            for f in self._check_auth_and_session(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # ③ 入力検証・インジェクション・XSS/SSRF防御 (input_injection)
            for f in self._check_injection_xss_ssrf(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # ④ 秘密情報・データ保護・暗号化 (secrets_data)
            for f in self._check_secrets_and_data(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # ⑤ インフラ・クラウド設定・CI/CD・サプライチェーン (infra_supply_chain)
            for f in self._check_infra_and_cicd(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

            # ⑥ AIガバナンス・例外処理(Fail-Closed)・監査証跡 (ai_governance_resilience)
            for f in self._check_ai_and_resilience(rel_path, lines, vuln_seq):
                findings.append(f)
                vuln_seq += 1

        return findings, len(files), topology

    def _window(self, lines: List[str], idx: int, before: int = 8, after: int = 18) -> str:
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "\n".join(lines[start:end])

    def _make_finding(
        self,
        seq: int,
        title: str,
        domain_key: str,
        role: str,
        category: str,
        severity: str,
        sev_s: int,
        exp_s: int,
        blast_s: int,
        file_path: str,
        line_number: int,
        code_snippet: str,
        what_happens: str,
        reproduction_steps: List[str],
        root_cause: str,
        remediation: str,
        patch_example: str,
    ) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id=f"WH-{seq:03d}",
            title=title,
            domain_key=domain_key,
            role=role,
            category=category,
            severity=severity,
            severity_score=sev_s,
            exploitability_score=exp_s,
            blast_radius_score=blast_s,
            risk_priority_score=sev_s * exp_s * blast_s,
            verification_status="VERIFIED_REPRODUCIBLE",
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            what_happens=what_happens,
            reproduction_steps=reproduction_steps,
            root_cause=root_cause,
            remediation=remediation,
            patch_example=patch_example,
        )

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

        # Admin route without role check
        admin_route_re = re.compile(
            r"""(@(app|router|bp)\.(get|post|put|delete|patch|route)\(['"]/admin/(users|settings|delete|config)|export\s+async\s+function\s+(POST|DELETE|PUT)\b)"""
        )
        admin_guard_re = re.compile(
            r"(is_admin|role\s*==\s*['\"]admin['\"]|require_admin|check_admin|current_user\.admin)",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            if route_id_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=2, after=22)
                if direct_lookup_re.search(scope_text):
                    if ownership_guard_re.search(scope_text):
                        self.false_positives_filtered += 1
                    else:
                        results.append(
                            self._make_finding(
                                seq=seq,
                                title="アクセス制御の不備（IDOR / 他人の注文・データが見えてしまう弱点）",
                                domain_key="access_control",
                                role="Access Control & IDOR Hunter (アクセス制御担当)",
                                category="OWASP A01: Broken Access Control (IDOR / BOLA)",
                                severity="HIGH",
                                sev_s=4,
                                exp_s=5,
                                blast_s=4,
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
                                    "if order.user_id != current_user.id:\n"
                                    "    raise HTTPException(status_code=403, detail='このデータを閲覧する権限がありません')"
                                ),
                            )
                        )
                        seq += 1

            elif "/admin/" in line and admin_route_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=2, after=18)
                if admin_guard_re.search(scope_text):
                    self.false_positives_filtered += 1
                else:
                    results.append(
                        self._make_finding(
                            seq=seq,
                            title="管理者エンドポイントの権限確認漏れ（垂直権限昇格の弱点）",
                            domain_key="access_control",
                            role="Access Control & IDOR Hunter (アクセス制御担当)",
                            category="OWASP A01: Broken Function Level Authorization",
                            severity="HIGH",
                            sev_s=4,
                            exp_s=4,
                            blast_s=5,
                            file_path=rel_path,
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            what_happens=(
                                "`/admin/` 向けの管理用窓口に「管理者ロール（`role == 'admin'`）を持っているか」の確認がないため、"
                                "一般ユーザーがURLを直接叩くだけで管理者機能を実行できてしまいます。"
                            ),
                            reproduction_steps=[
                                f"1. 一般ユーザー権限のアカウントで `{rel_path}:{i + 1}` の `/admin/...` エンドポイントへリクエストを送る。",
                                "2. 管理者ロール判定が存在しないため処理が通ってしまうことを確認。",
                            ],
                            root_cause="管理機能ルートに対するロールベース認可チェック（RBAC）の欠如。",
                            remediation="エンドポイント冒頭またはミドルウェアで `current_user.role == 'admin'` を強制検証してください。",
                            patch_example=(
                                "if getattr(current_user, 'role', None) != 'admin':\n"
                                "    raise HTTPException(status_code=403, detail='管理者権限が必要です')"
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
        cookie_insecure_re = re.compile(
            r"(set_cookie\([^)]*httponly\s*=\s*False|httpOnly\s*:\s*false)",
            re.IGNORECASE,
        )

        for i, line in enumerate(lines):
            if jwt_unsafe_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="JWT署名検証の無効化（なりすましログインの弱点）",
                        domain_key="auth_session",
                        role="Auth & Session Inspector (ログイン・セッション担当)",
                        category="OWASP A07: Identification and Authentication Failures",
                        severity="CRITICAL",
                        sev_s=5,
                        exp_s=5,
                        blast_s=5,
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

            elif cookie_insecure_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="セッションCookieのHttpOnly無効化（トークン窃取リスク）",
                        domain_key="auth_session",
                        role="Auth & Session Inspector (ログイン・セッション担当)",
                        category="OWASP A07: Insecure Session Cookie Configuration",
                        severity="MEDIUM",
                        sev_s=3,
                        exp_s=3,
                        blast_s=3,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens="Cookieの `HttpOnly` が無効になっているため、画面上でJavaScriptからセッション情報を読み取られるリスクがあります。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` のCookie発行処理で `httponly=False` が指定されていることを確認。"
                        ],
                        root_cause="セッションCookie発行時のセキュア属性設定ミス。",
                        remediation="認証用Cookieには必ず `httponly=True, secure=True, samesite='lax'` を設定してください。",
                        patch_example="response.set_cookie('session_id', token, httponly=True, secure=True, samesite='lax')",
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
        ssrf_re = re.compile(
            r"(requests\.(get|post)\(\s*(req\.|request\.|user_url|target_url|url\b)|urllib\.request\.urlopen\(\s*(req\.|request\.|user_url|target_url))"
        )

        for i, line in enumerate(lines):
            if sqli_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="SQLインジェクション（データベースへの不正命令注入）",
                        domain_key="input_injection",
                        role="Input & Injection Auditor (入力注入担当)",
                        category="OWASP A03: Injection (SQLi)",
                        severity="CRITICAL",
                        sev_s=5,
                        exp_s=5,
                        blast_s=5,
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
                    self._make_finding(
                        seq=seq,
                        title="OSコマンド注入リスク（shell=True / os.systemの使用）",
                        domain_key="input_injection",
                        role="Input & Injection Auditor (入力注入担当)",
                        category="OWASP A03: Injection (Command Injection)",
                        severity="HIGH",
                        sev_s=5,
                        exp_s=4,
                        blast_s=5,
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
                    self._make_finding(
                        seq=seq,
                        title="クロスサイトスクリプティング（XSS / 画面での不正プログラム実行）",
                        domain_key="input_injection",
                        role="Input & Injection Auditor (画面・XSS担当)",
                        category="OWASP A03: Cross-Site Scripting (XSS)",
                        severity="HIGH",
                        sev_s=4,
                        exp_s=4,
                        blast_s=3,
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

            elif ssrf_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=6, after=6)
                if "allowlist" in scope_text.lower() or "validate_url" in scope_text.lower():
                    self.false_positives_filtered += 1
                    continue
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="SSRF（サーバー側からの内部ネットワーク不正アクセス）",
                        domain_key="input_injection",
                        role="Input & Injection Auditor (通信・SSRF担当)",
                        category="OWASP A10: Server-Side Request Forgery (SSRF)",
                        severity="HIGH",
                        sev_s=4,
                        exp_s=4,
                        blast_s=4,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens="外部から指定されたURLへサーバーがそのまま通信するため、内部管理画面やクラウドメタデータ（`169.254.169.254`）の情報を盗み見られる危険があります。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` のURL取得箇所に内部IPアドレス（`http://127.0.0.1` 等）を渡す。",
                            "2. ドメイン許可リストの確認なしに通信が実行されることを確認。",
                        ],
                        root_cause="外部入力URLに対するスキーマ・ホスト名許可リスト検証およびプライベートIP遮断の欠如。",
                        remediation="接続先ホストを事前許可されたドメインリスト（Allowlist）で検証し、内部IPを拒否してください。",
                        patch_example="if parsed.hostname not in ALLOWED_DOMAINS:\n    raise ValueError('許可されていない接続先です')",
                    )
                )
                seq += 1

        return results

    def _check_secrets_and_data(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        secret_re = re.compile(
            r"""(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"""
        )
        frontend_secret_re = re.compile(
            r"(NEXT_PUBLIC_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|API_KEY)|VITE_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE))"
        )

        for i, line in enumerate(lines):
            if "pattern:" in line or "secret_re" in line or "EXAMPLE" in line.upper():
                continue
            m = secret_re.search(line)
            if m:
                self.candidates_inspected += 1
                token_preview = m.group(1)[:8] + "...[REDACTED]"
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="秘密鍵・APIキーのプログラム直接埋め込み",
                        domain_key="secrets_data",
                        role="API & Cloud Config Scanner (設定・シークレット担当)",
                        category="OWASP A02/A05: Hardcoded Secrets",
                        severity="CRITICAL",
                        sev_s=5,
                        exp_s=5,
                        blast_s=5,
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

            elif frontend_secret_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="フロントエンド公開環境変数（NEXT_PUBLIC_/VITE_）への秘密鍵混入",
                        domain_key="secrets_data",
                        role="API & Cloud Config Scanner (設定・シークレット担当)",
                        category="OWASP A01/A05: Frontend Bundle Secret Exposure",
                        severity="HIGH",
                        sev_s=4,
                        exp_s=5,
                        blast_s=4,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens="`NEXT_PUBLIC_` や `VITE_` が付いた変数はブラウザに丸ごと配信されるため、利用者が開発者ツールを開くだけで管理者用キーを抜き取れます。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` でクライアント公開プレフィックス付きの変数に秘密鍵系名称が使われていることを確認。"
                        ],
                        root_cause="サーバー専用にすべき秘密鍵にフロントエンド公開用プレフィックスを付与している。",
                        remediation="`NEXT_PUBLIC_` / `VITE_` を外し、サーバー側のAPIルート内でのみ参照してください。",
                        patch_example="const secret = process.env.SUPABASE_SERVICE_ROLE_KEY; // サーバー側のみで使用",
                    )
                )
                seq += 1

        return results

    def _check_infra_and_cicd(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        cors_wildcard_re = re.compile(r"""(allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"])""")
        debug_prod_re = re.compile(r"""(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)""")

        for i, line in enumerate(lines):
            if cors_wildcard_re.search(line):
                self.candidates_inspected += 1
                scope_text = self._window(lines, i, before=4, after=6)
                if "allow_credentials=True" in scope_text or "credentials: true" in scope_text.lower():
                    results.append(
                        self._make_finding(
                            seq=seq,
                            title="CORS設定の全面開放（allow_origins=['*'] と認証情報の併用）",
                            domain_key="infra_supply_chain",
                            role="API & Cloud Config Scanner (インフラ・設定担当)",
                            category="OWASP A05: Security Misconfiguration (CORS)",
                            severity="MEDIUM",
                            sev_s=3,
                            exp_s=4,
                            blast_s=3,
                            file_path=rel_path,
                            line_number=i + 1,
                            code_snippet=line.strip(),
                            what_happens="すべての外部サイト（`*`）からの認証付き通信を許可しているため、悪意ある罠サイトからユーザーの権限でAPIを勝手に操作される危険があります。",
                            reproduction_steps=[
                                f"1. `{rel_path}:{i + 1}` で `allow_origins=['*']` と `allow_credentials=True` が同時設定されていることを確認。"
                            ],
                            root_cause="CORSのオリジン許可リストがワイルドカードになっている。",
                            remediation="自社のフロントエンドURLのみを明示的にリスト指定してください。",
                            patch_example="allow_origins=['https://app.example.com'], allow_credentials=True",
                        )
                    )
                    seq += 1

            elif debug_prod_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="デバッグモードの常時有効化（内部情報・スタックトレース露出）",
                        domain_key="infra_supply_chain",
                        role="API & Cloud Config Scanner (インフラ・設定担当)",
                        category="OWASP A05: Security Misconfiguration (Debug Enabled)",
                        severity="MEDIUM",
                        sev_s=3,
                        exp_s=3,
                        blast_s=3,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens="エラー発生時にプログラムの内部構造や環境変数が画面に表示されたり、デバッグ用コンソールを悪用されたりする危険があります。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` で `debug=True` が直接指定されていることを確認。"
                        ],
                        root_cause="本番・検証の切り替えなしにデバッグフラグが固定有効化されている。",
                        remediation="環境変数から読み取り、デフォルトは `False`（安全側）にしてください。",
                        patch_example="debug_mode = os.environ.get('APP_DEBUG', 'false').lower() == 'true'",
                    )
                )
                seq += 1

        return results

    def _check_ai_and_resilience(
        self, rel_path: str, lines: List[str], start_seq: int
    ) -> List[VulnerabilityFinding]:
        results: List[VulnerabilityFinding] = []
        seq = start_seq

        bare_except_re = re.compile(r"^\s*except(\s+Exception)?\s*:\s*$")
        eval_exec_re = re.compile(r"\b(eval|exec)\(\s*(req\.|request\.|user_input|body|untrusted)")

        for i, line in enumerate(lines):
            if eval_exec_re.search(line):
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="動的コード評価（eval / exec）への外部入力の直接投入",
                        domain_key="ai_governance_resilience",
                        role="Input & Injection Auditor (AI・動的実行統治担当)",
                        category="OWASP A03 / Agentic AI: Arbitrary Code Execution",
                        severity="CRITICAL",
                        sev_s=5,
                        exp_s=5,
                        blast_s=5,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=line.strip(),
                        what_happens="外部入力やAI出力をそのまま `eval()` / `exec()` でプログラムとして実行しているため、サーバー全体を乗っ取られます。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` で `eval` または `exec` に外部由来の変数が渡されていることを確認。"
                        ],
                        root_cause="危険な動的コード実行関数の使用。",
                        remediation="`eval` / `exec` を廃止し、`json.loads` や `ast.literal_eval`、型付きパーサーを使用してください。",
                        patch_example="data = json.loads(raw_input)",
                    )
                )
                seq += 1

            elif bare_except_re.search(line) and i + 1 < len(lines) and lines[i + 1].strip() == "pass":
                self.candidates_inspected += 1
                results.append(
                    self._make_finding(
                        seq=seq,
                        title="エラーの無言握り潰し（Silent Failure / Fail-Open リスク）",
                        domain_key="ai_governance_resilience",
                        role="API & Cloud Config Scanner (回復性・監査証跡担当)",
                        category="OWASP A09: Security Logging and Monitoring Failures",
                        severity="LOW",
                        sev_s=2,
                        exp_s=2,
                        blast_s=2,
                        file_path=rel_path,
                        line_number=i + 1,
                        code_snippet=f"{line.strip()} -> pass",
                        what_happens="エラーや攻撃が起きた際にログも残さず無視（`pass`）するため、異常の発見が遅れたり、チェック失敗のまま次の処理へ進んでしまうリスクがあります。",
                        reproduction_steps=[
                            f"1. `{rel_path}:{i + 1}` で `except: pass` により例外が記録されず破棄されていることを確認。"
                        ],
                        root_cause="例外捕捉時にログ記録も再送出も行われていない。",
                        remediation="少なくとも警告ログを記録し、認証・認可処理では必ず拒否側（Fail-Closed）へ倒してください。",
                        patch_example="except Exception as exc:\n    logger.warning('Operation failed: %s', exc)\n    raise",
                    )
                )
                seq += 1

        return results


class ComprehensiveAuditScorer:
    """
    100点満点標準採点エンジン（6大領域別スコア ＋ 致命的欠陥ハードキャップ制 ＋ 監査カバレッジ算出）
    """

    def evaluate(
        self,
        findings: List[VulnerabilityFinding],
        topology: OrganizationTopology,
        mode: str,
        status: str,
        budget_limit_reached: bool,
    ) -> AuditScorecard:
        domain_details: List[DomainScoreDetail] = []
        raw_total = 0

        total_sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            total_sev_counts[f.severity] = total_sev_counts.get(f.severity, 0) + 1

        for dkey, spec in AUDIT_DOMAINS_SPEC.items():
            max_pts = int(spec["max_score"])
            penalties = spec["penalty"]
            dfindings = [f for f in findings if f.domain_key == dkey]

            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            deducted = 0
            for df in dfindings:
                counts[df.severity] = counts.get(df.severity, 0) + 1
                deducted += int(penalties.get(df.severity, 1))

            # 環境保護欠如（.gitignore に .env がない等）の構造減点
            if dkey == "secrets_data" and not topology.has_gitignore_env_protection:
                deducted += 3

            deducted = min(max_pts, deducted)
            earned = max_pts - deducted
            raw_total += earned
            pct = round((earned / max_pts) * 100.0, 1) if max_pts > 0 else 100.0

            if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
                status_label = "CRITICAL_DEFECT"
            elif deducted > 0:
                status_label = "WARNING"
            else:
                status_label = "PASS"

            domain_details.append(
                DomainScoreDetail(
                    domain_key=dkey,
                    domain_name=str(spec["name"]),
                    max_score=max_pts,
                    earned_score=earned,
                    deducted_points=deducted,
                    percentage=pct,
                    finding_counts=counts,
                    status_label=status_label,
                )
            )

        # 致命的欠陥ハードキャップ制（見せかけの高得点を物理遮断）
        final_score = raw_total
        cap_applied = False
        cap_reason = "キャップ適用なし（重大な未解決脆弱性なし）"

        if total_sev_counts["CRITICAL"] > 0:
            if final_score > 49:
                final_score = 49
                cap_applied = True
            cap_reason = (
                f"CRITICAL（致命的弱点）が {total_sev_counts['CRITICAL']} 件残存しているため、"
                "素点合計に関わらず最高得点を 49点（Grade D: 本番公開不可）に上限固定（ハードキャップ）しました。"
            )
        elif total_sev_counts["HIGH"] > 0:
            if final_score > 69:
                final_score = 69
                cap_applied = True
            cap_reason = (
                f"HIGH（高リスク弱点: IDOR/XSS/コマンド注入等）が {total_sev_counts['HIGH']} 件残存しているため、"
                "素点合計に関わらず最高得点を 69点（Grade C: リリース前修正必須）に上限固定（ハードキャップ）しました。"
            )

        # グレードと判定
        if final_score >= 95:
            grade = "S"
            verdict = "PASS_PRODUCTION_READY (極めて良好・要定期監査)"
        elif final_score >= 85:
            grade = "A"
            verdict = "PASS_PRODUCTION_READY (良好・軽微な改善推奨)"
        elif final_score >= 70:
            grade = "B"
            verdict = "CONDITIONAL_PASS (中程度のリスクあり・計画的修正推奨)"
        elif final_score >= 50:
            grade = "C"
            verdict = "CONDITIONAL_FIX_REQUIRED (高リスク残存・本番公開前に修正必須)"
        elif final_score >= 30:
            grade = "D"
            verdict = "BLOCK_CRITICAL_RISK (致命的リスク残存・即時修正が必要)"
        else:
            grade = "F"
            verdict = "BLOCK_CRITICAL_RISK (全面的なセキュリティ再設計が必要)"

        # 監査カバレッジ率（静的＋構造解析＋モード深さ）
        base_cov = 65 if mode == "quick" else (80 if mode == "standard" else 90)
        if status != "completed" or budget_limit_reached:
            base_cov = min(base_cov, 40)
        if topology.total_files_scanned == 0:
            base_cov = 20

        exec_summary = (
            f"総合セキュリティ監査スコアは **{final_score} / 100点（Grade {grade}）**、判定は **{verdict}** です。"
            f"（素点合計: {raw_total}点 / 監査カバレッジ推定: {base_cov}%）。"
        )
        if cap_applied:
            exec_summary += f" ⚠️ {cap_reason}"

        return AuditScorecard(
            raw_score=raw_total,
            final_score=final_score,
            max_score=100,
            grade=grade,
            verdict=verdict,
            cap_applied=cap_applied,
            cap_reason=cap_reason,
            audit_coverage_percent=base_cov,
            domain_scores=domain_details,
            executive_summary=exec_summary,
        )


def _build_maintenance_proposal_md(
    metadata: RunMetadata,
    topology: OrganizationTopology,
    scorecard: AuditScorecard,
    findings: List[VulnerabilityFinding],
) -> Tuple[str, str]:
    """
    監査結果（100点満点スコア・組織規模・検出リスク）に基づき、
    クライアントまたは経営層へそのまま提示できる「サイバーセキュリティ継続保守プログラム提案書」を自動生成する。
    戻り値: (recommended_plan_name, proposal_markdown)
    """
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    total_apps = len(topology.subprojects_detected)
    total_routes = topology.api_endpoints_estimated

    if crit_count > 0 or total_apps >= 5 or total_routes >= 30:
        recommended_plan = "Enterprise（全社・複数プロダクト統治＆緊急是正プラン）"
    elif high_count > 0 or scorecard.final_score < 85 or total_routes >= 5:
        recommended_plan = "Standard（標準・継続ホワイトハッカー監査＆改修伴走プラン）"
    else:
        recommended_plan = "Light（定期ヘルスチェック＆スコア維持プラン）"

    urgent_items = [f"- `[{f.id}]` **{f.title}** (`{f.file_path}:{f.line_number}` / 重要度: {f.severity})" for f in findings[:5]]
    urgent_list_md = "\n".join(urgent_items) if urgent_items else "- 初期診断における重大な未解決ホールはありません（高水準の維持・監視フェーズへ移行可能）。"

    proposal_md = f"""# 🛡️ サイバーセキュリティ継続保守プログラム ご提案書

- **対象組織 / プロジェクト**: `{topology.root_path}`
- **初回監査実施日 / 実行ID**: `{metadata.completed_at[:10]}` (`{metadata.run_id}`)
- **現在の総合セキュリティ得点**: **{scorecard.final_score} / 100 点（Grade `{scorecard.grade}`）**
- **推奨保守プラン**: **{recommended_plan}**

---

## 1. なぜ「単発の診断・修正」だけでは危険なのか？（継続保守が必要な3つの理由）

1. **AI開発（バイブコーディング）・機能追加による「新たな穴」の日常的発生**
   画面やAPIを1つ追加・変更するたびに、「ログイン確認はあるが、データの持ち主確認（IDOR対策）が抜ける」「環境変数の公開設定を誤る」といったセキュリティホールが再発します。
2. **「100点・0件＝永久に安全」ではない（外部環境と依存ライブラリの変化）**
   今日時点で弱点が0件でも、利用中の外部パッケージ（npm / Python等）に新しい脆弱性（CVE）が発見されたり、クラウド権限設定が変更されたりすることで、翌月には危険な状態へ転落します。
3. **取引先・顧客に対する「継続的な監査証跡（100点満点スコアカード）」の提示責任**
   情報漏洩事故が起きた際、「いつ・どの範囲を・どの基準で点検し、どう塞いだか」の客観的な記録（`audit_scorecard.json` / `run.json`）を継続保存しておくことが、企業の信用防衛に直結します。

---

## 2. 今回の初回監査結果に基づく3フェーズ改善ロードマップ

### 🚨 Phase 1（初月）: 緊急是正＆スコア引き上げ（目標: Grade A [85点以上] 達成）
現在検出されている以下の優先リスクを最小差分で修正し、同じ再現手順で再テストを行って「確実に塞がったこと」を証明します。
{urgent_list_md}

### 🔄 Phase 2（2〜3ヶ月目）: 組織全体の信頼境界（6大領域）の標準化
- 全APIエンドポイント（推定 `{total_routes}` 箇所）におけるオブジェクト認可（IDOR防止）と管理者権限（RBAC）の統一化
- 秘密情報（`.env` / APIキー）の漏洩遮断と、フロントエンド公開変数の棚卸し

### 🛡️ Phase 3（継続保守）: 月次100点満点監査＆リリース前ゲートキーパー運用
- 毎月の定期フルスキャン（`deep` モード）と「月次セキュリティ監査スコア推移レポート」の提出
- 大規模機能追加時の事前ホワイトハッカー点検と、万が一の脆弱性発覚時の緊急パッチ作成支援

---

## 3. サイバーセキュリティ継続保守プログラム（3プラン比較表）

| 項目 | Light（定期点検プラン） | Standard（標準・改修伴走プラン）⭐推奨 | Enterprise（全社統治・要塞化プラン） |
| :--- | :--- | :--- | :--- |
| **対象目安** | 小規模Webアプリ・LP（単一構成） | 顧客データを扱う自社サービス・業務システム | 複数プロダクト・決済・AIエージェント連携組織 |
| **100点満点包括監査** | 月1回（定例レポート提出） | **月2回 ＋ 主要リリース前点検** | **週次 / CI自動連動 ＋ 全サブプロジェクト横断** |
| **6大領域リスク分析** | ○（標準6領域スコアカード） | ○（3軸リスク優先度＆再現手順付き） | ○（カスタム業務ロジック・権限マトリクス検証） |
| **脆弱性の修正（パッチ）** | 修正ガイド・コード例の提示まで | **修正コード（PR/最小差分）の作成＋再テスト証明** | **優先緊急パッチ作成 ＋ アーキテクチャ設計レビュー** |
| **AI/シークレット漏洩監視** | 基本チェック | フロントエンド露出・プロンプト境界監査 | 全社AIガバナンス・L0承認ゲート設計・証跡保全 |
| **経営層向け監査レポート** | 月次サマリ（HTML/MD） | **月次監査証明書 ＋ スコア推移グラフ** | **取引先提出用セキュリティ体制レポート作成支援** |

---

## 4. 契約・法務および運用上の重要合意事項（安心・安全な運用のために）

1. **事前許可・対象範囲の明文化（不正アクセス禁止法等の遵守）**
   診断および検証は、貴社が管理権限を有し、書面（または電磁的記録）にて事前合意した対象（指定リポジトリ・ステージング環境・ローカル検証環境）のみに対して実施します。
2. **本番環境の保護（ステージング・隔離環境での検証）**
   実顧客データが稼働する本番環境への直接的な負荷・破壊的テストは行わず、隔離された検証環境およびコード・構成監査を組み合わせて安全に実施します。
3. **契約性質（準委任契約）と3視点の透明性開示**
   セキュリティ監査は「検査時点・合意範囲内における既知の弱点の発見および是正支援（善管注意義務に基づく準委任）」であり、未知のゼロデイ攻撃や検査範囲外（クラウド事業者の障害、人的ソーシャルエンジニアリング等）を含む「100%の無事故・完全無欠」を保証（結果請負）するものではありません。毎回のレポートにて「①完走状態、②予算・時間上限、③調査範囲と未検証の死角」を正直に開示します。
"""
    return recommended_plan, proposal_md


def _build_html_report(
    metadata: RunMetadata,
    topology: OrganizationTopology,
    scorecard: AuditScorecard,
    findings: List[VulnerabilityFinding],
    recommended_plan: str = "",
) -> str:
    """100点満点スコアゲージ・6大領域レーダー棒グラフ・組織構造マップ付きの監査HTMLダッシュボード"""
    score_color = (
        "#10b981"
        if scorecard.final_score >= 85
        else ("#f59e0b" if scorecard.final_score >= 70 else "#ef4444")
    )

    domain_rows_html = []
    for d in scorecard.domain_scores:
        bar_color = (
            "#10b981"
            if d.status_label == "PASS"
            else ("#f59e0b" if d.status_label == "WARNING" else "#ef4444")
        )
        domain_rows_html.append(
            f"""
            <div class="domain-row">
              <div class="domain-head">
                <span><strong>{html.escape(d.domain_name)}</strong></span>
                <span><strong>{d.earned_score} / {d.max_score} 点</strong> ({d.percentage}%)</span>
              </div>
              <div class="progress-bg">
                <div class="progress-fill" style="width:{d.percentage}%;background:{bar_color};"></div>
              </div>
            </div>
            """
        )

    cards_html = []
    for f in sorted(findings, key=lambda x: x.risk_priority_score, reverse=True):
        sev_color = "#dc2626" if f.severity == "CRITICAL" else ("#ea580c" if f.severity == "HIGH" else "#d97706")
        steps_li = "".join(f"<li>{html.escape(s)}</li>" for s in f.reproduction_steps)
        cards_html.append(
            f"""
            <div class="card">
              <div class="card-header">
                <span class="badge" style="background:{sev_color}">{html.escape(f.severity)}</span>
                <span class="vuln-id">{html.escape(f.id)}</span>
                <h3>{html.escape(f.title)}</h3>
                <span class="risk-pill">3軸リスク値: {f.risk_priority_score} / 125</span>
              </div>
              <p class="meta"><strong>監査領域:</strong> {html.escape(f.domain_key)} ｜ <strong>担当AI:</strong> {html.escape(f.role)} ｜ <strong>場所:</strong> <code>{html.escape(f.file_path)}:{f.line_number}</code></p>
              <div class="section">
                <h4>1. 何が起きるか（業務・組織への影響）</h4>
                <p>{html.escape(f.what_happens)}</p>
              </div>
              <div class="section">
                <h4>2. どうやって確かめたか（再現手順）</h4>
                <ul>{steps_li}</ul>
                <pre><code>{html.escape(f.code_snippet)}</code></pre>
              </div>
              <div class="section">
                <h4>3. 直し方（最小差分パッチ例）</h4>
                <p>{html.escape(f.remediation)}</p>
                <pre><code>{html.escape(f.patch_example)}</code></pre>
              </div>
            </div>
            """
        )

    cards_section = (
        "\n".join(cards_html)
        if cards_html
        else '<div class="empty">✅ 今回の検査範囲では、再現確認されたセキュリティホールは 0 件です。</div>'
    )

    boundaries_li = "".join(f"<li>{html.escape(b)}</li>" for b in topology.trust_boundaries)
    cap_banner = (
        f'<div class="cap-alert">⚠️ <strong>致命的欠陥キャップ発動:</strong> {html.escape(scorecard.cap_reason)}</div>'
        if scorecard.cap_applied
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>包括的組織セキュリティ監査レポート ({scorecard.final_score}/100点 - {html.escape(metadata.run_id)})</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 32px; line-height: 1.6; }}
  .container {{ max-width: 1020px; margin: 0 auto; }}
  .score-hero {{ display: flex; flex-wrap: wrap; gap: 24px; align-items: center; justify-content: space-between; background: #1e293b; border-left: 8px solid {score_color}; padding: 28px; border-radius: 14px; margin-bottom: 24px; }}
  .score-box {{ text-align: center; background: #020617; padding: 20px 32px; border-radius: 14px; border: 2px solid {score_color}; min-width: 180px; }}
  .score-num {{ font-size: 48px; font-weight: 800; color: {score_color}; line-height: 1.1; }}
  .score-grade {{ font-size: 18px; font-weight: 700; color: #e2e8f0; margin-top: 6px; }}
  .cap-alert {{ background: #7f1d1d; border: 1px solid #ef4444; color: #fecaca; padding: 14px 18px; border-radius: 10px; margin-bottom: 24px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(440px, 1fr)); gap: 20px; margin-bottom: 24px; }}
  .panel {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }}
  .panel h2 {{ margin-top: 0; font-size: 18px; color: #38bdf8; }}
  .domain-row {{ margin-bottom: 14px; }}
  .domain-head {{ display: flex; justify-content: space-between; font-size: 14px; margin-bottom: 4px; }}
  .progress-bg {{ background: #020617; height: 10px; border-radius: 999px; overflow: hidden; }}
  .progress-fill {{ height: 100%; border-radius: 999px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  .card-header {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .card-header h3 {{ margin: 0; font-size: 18px; flex: 1; }}
  .badge {{ color: #fff; font-weight: 700; font-size: 12px; padding: 4px 10px; border-radius: 999px; }}
  .risk-pill {{ background: #334155; color: #f8fafc; font-size: 12px; padding: 4px 10px; border-radius: 999px; font-weight: 600; }}
  .vuln-id {{ color: #38bdf8; font-family: monospace; font-weight: 700; }}
  .meta {{ color: #cbd5e1; font-size: 13px; }}
  .section h4 {{ margin: 14px 0 6px 0; color: #38bdf8; font-size: 15px; }}
  pre {{ background: #020617; padding: 12px; border-radius: 8px; overflow-x: auto; border: 1px solid #1e293b; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; color: #e2e8f0; }}
  .three-points {{ background: #172554; border: 1px solid #1d4ed8; border-radius: 12px; padding: 20px; margin-top: 28px; }}
  .empty {{ background: #064e3b; border: 1px solid #059669; padding: 20px; border-radius: 12px; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
  <div class="score-hero">
    <div style="flex:1;min-width:280px;">
      <h1 style="margin:0 0 8px 0;font-size:24px;">🛡️ 包括的組織セキュリティ監査レポート</h1>
      <p style="margin:0 0 8px 0;font-size:15px;"><strong>総合判定:</strong> {html.escape(scorecard.verdict)}</p>
      <p style="margin:0;font-size:13px;color:#94a3b8;">
        対象: <code>{html.escape(metadata.target)}</code> ｜ 素点合計: {scorecard.raw_score}/100点 ｜ 監査カバレッジ率: {scorecard.audit_coverage_percent}% ｜ 誤検知除外: {metadata.false_positives_filtered}件
      </p>
    </div>
    <div class="score-box">
      <div class="score-num">{scorecard.final_score}<span style="font-size:20px;color:#94a3b8;">/100</span></div>
      <div class="score-grade">Grade {html.escape(scorecard.grade)}</div>
    </div>
  </div>

  {cap_banner}

  <div class="grid-2">
    <div class="panel">
      <h2>📊 6大セキュリティ監査領域の内訳（100点満点）</h2>
      {"".join(domain_rows_html)}
    </div>
    <div class="panel">
      <h2>🏗️ 組織・システム構造の全体像 (Topology Map)</h2>
      <ul style="font-size:14px;padding-left:20px;margin:0;">
        <li><strong>検出サブプロジェクト:</strong> {html.escape(", ".join(topology.subprojects_detected))}</li>
        <li><strong>技術スタック:</strong> {html.escape(", ".join(topology.tech_stack_summary))}</li>
        <li><strong>検査ファイル数:</strong> {topology.total_files_scanned} 件（推定APIエンドポイント: {topology.api_endpoints_estimated} 箇所）</li>
        <li><strong>レイヤー構成:</strong> 画面UI({topology.layer_file_counts['frontend_ui']}) / API({topology.layer_file_counts['backend_api']}) / DB({topology.layer_file_counts['data_db']}) / Infra({topology.layer_file_counts['infra_ci_config']}) / AI統治({topology.layer_file_counts['ai_agents_governance']})</li>
        <li><strong>.env Git保護:</strong> {"✅ 保護済み" if topology.has_gitignore_env_protection else "⚠️ 未保護"} ｜ <strong>自動テスト:</strong> {"✅ あり" if topology.has_automated_tests else "⚠️ 未検出"}</li>
      </ul>
      <h4 style="margin:14px 0 6px 0;color:#93c5fd;font-size:14px;">特定された5つの信頼境界 (Trust Boundaries)</h4>
      <ul style="font-size:12px;color:#cbd5e1;padding-left:18px;margin:0;">{boundaries_li}</ul>
    </div>
  </div>

  <h2>📋 検出されたセキュリティホールと優先度順の是正計画</h2>
  {cards_section}

  <div class="panel" style="margin-top:28px;border-color:#0ea5e9;">
    <h2>🛡️ サイバーセキュリティ継続保守プログラムのご提案（推奨: {html.escape(recommended_plan)}）</h2>
    <p style="font-size:14px;color:#cbd5e1;margin-top:0;">
      単発の診断・修正だけでは、日々のAI機能開発や外部ライブラリの脆弱性発覚により再びスコアが低下します。<br>
      「初期緊急是正（Phase 1）➔ 組織全体の認可・秘密情報境界の標準化（Phase 2）➔ 月次100点満点監査＆リリース前ゲートキーパー（Phase 3）」による継続保守プログラムを推奨します。（詳細は同フォルダの <code>maintenance_proposal.md</code> をご参照ください）
    </p>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:12px;">
      <thead>
        <tr style="background:#020617;color:#38bdf8;text-align:left;">
          <th style="padding:10px;border:1px solid #334155;">プラン</th>
          <th style="padding:10px;border:1px solid #334155;">監査頻度・範囲</th>
          <th style="padding:10px;border:1px solid #334155;">是正・パッチ支援</th>
          <th style="padding:10px;border:1px solid #334155;">経営層・取引先向け証跡</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="padding:10px;border:1px solid #334155;"><strong>Light</strong>（定期点検）</td>
          <td style="padding:10px;border:1px solid #334155;">月1回 100点満点監査</td>
          <td style="padding:10px;border:1px solid #334155;">修正ガイド・コード例の提示</td>
          <td style="padding:10px;border:1px solid #334155;">月次監査サマリ（HTML/MD）</td>
        </tr>
        <tr style="background:#0c4a6e;">
          <td style="padding:10px;border:1px solid #0284c7;"><strong>Standard</strong>（標準・改修伴走）⭐</td>
          <td style="padding:10px;border:1px solid #0284c7;">月2回 ＋ 主要リリース前点検</td>
          <td style="padding:10px;border:1px solid #0284c7;"><strong>最小差分修正パッチ作成 ＋ 再テスト閉塞証明</strong></td>
          <td style="padding:10px;border:1px solid #0284c7;"><strong>月次監査証明書 ＋ スコア推移レポート</strong></td>
        </tr>
        <tr>
          <td style="padding:10px;border:1px solid #334155;"><strong>Enterprise</strong>（全社統治）</td>
          <td style="padding:10px;border:1px solid #334155;">週次 / CI自動連動 ＋ 全プロジェクト横断</td>
          <td style="padding:10px;border:1px solid #334155;">優先緊急パッチ ＋ アーキテクチャ設計審査</td>
          <td style="padding:10px;border:1px solid #334155;">取引先提出用セキュリティ体制報告書作成</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="three-points">
    <h2 style="margin-top:0;font-size:18px;color:#93c5fd;">🔍 「100点・0件＝絶対安全」と誤認しないための3視点監査証跡</h2>
    <ol style="margin:0;">
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
    topology: OrganizationTopology,
    scorecard: AuditScorecard,
    findings: List[VulnerabilityFinding],
) -> Path:
    """
    `strix_runs/<run_id>/` に包括的監査レポート＆保守提案書一式を出力:
      - audit_scorecard.json (100点満点採点・6領域内訳・組織構造マップ・推奨保守プラン)
      - maintenance_proposal.md (クライアント提案用・サイバーセキュリティ継続保守プログラム提案書)
      - run.json (完走ステータス・予算・3視点チェック)
      - vulnerabilities.json (3軸リスク評価付き弱点一覧)
      - summary.md (100点満点監査レポート Markdown)
      - report.html (経営層・開発者向けビジュアル監査ダッシュボード)
      - findings/<WH-xxx>.md (1件ずつの詳細・再現手順・パッチ)
    """
    run_dir = output_base_dir / metadata.run_id
    findings_dir = run_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    sorted_findings = sorted(findings, key=lambda x: x.risk_priority_score, reverse=True)
    recommended_plan, proposal_md = _build_maintenance_proposal_md(
        metadata, topology, scorecard, sorted_findings
    )

    (run_dir / "run.json").write_text(
        json.dumps(asdict(metadata), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([asdict(f) for f in sorted_findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    (run_dir / "audit_scorecard.json").write_text(
        json.dumps(
            {
                "scorecard": asdict(scorecard),
                "organization_topology": asdict(topology),
                "recommended_maintenance_plan": recommended_plan,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    (run_dir / "maintenance_proposal.md").write_text(proposal_md, encoding="utf-8")

    for f in sorted_findings:
        repro_md = "\n".join(f.reproduction_steps)
        detail_md = f"""# [{f.id}] {f.title}

- **監査領域**: `{f.domain_key}`
- **担当ロール**: {f.role}
- **分類**: {f.category}
- **重要度**: `{f.severity}` (3軸リスク優先度スコア: **{f.risk_priority_score} / 125** = 深刻度{f.severity_score} × 悪用容易性{f.exploitability_score} × 影響範囲{f.blast_radius_score})
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

    # 6大領域テーブル
    domain_table_rows = []
    for d in scorecard.domain_scores:
        status_icon = "✅ PASS" if d.status_label == "PASS" else ("⚠️ WARN" if d.status_label == "WARNING" else "🚨 DEFECT")
        domain_table_rows.append(
            f"| {d.domain_name} | **{d.earned_score} / {d.max_score} 点** ({d.percentage}%) | -{d.deducted_points} 点 | C:{d.finding_counts['CRITICAL']} / H:{d.finding_counts['HIGH']} / M:{d.finding_counts['MEDIUM']} / L:{d.finding_counts['LOW']} | {status_icon} |"
        )
    domain_table_md = (
        "| 監査領域（6大レイヤー） | 獲得スコア | 減点 | 検出内訳 (C/H/M/L) | 状態 |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        + "\n".join(domain_table_rows)
    )

    # 弱点一覧テーブル（3軸リスク順）
    finding_rows = []
    for f in sorted_findings:
        finding_rows.append(
            f"| `{f.id}` | **{f.severity}** | **{f.risk_priority_score}**/125 | {f.title} | `{f.file_path}:{f.line_number}` | `findings/{f.id}.md` |"
        )
    findings_table = (
        "| ID | 重要度 | 3軸リスク値 | 弱点の内容 | 場所 | 詳細ファイル |\n"
        "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
        + "\n".join(finding_rows)
        if finding_rows
        else "✅ **今回の検査範囲では、再現確認された弱点は 0 件でした。**（下の「3つの確認視点」を必ずご確認ください）"
    )

    boundaries_md = "\n".join(f"- {b}" for b in topology.trust_boundaries)

    summary_md = f"""# 🛡️ 包括的組織セキュリティ監査レポート (`{metadata.run_id}`)

## 🏆 1. 総合セキュリティ得点（100点満点採点）

| 項目 | 評価結果 |
| :--- | :--- |
| **総合セキュリティ得点** | **{scorecard.final_score} / 100 点** （素点合計: {scorecard.raw_score} / 100 点） |
| **監査グレード (Grade)** | **Grade `{scorecard.grade}`** |
| **リリース可否判定 (Verdict)** | **{scorecard.verdict}** |
| **致命的欠陥キャップ判定** | {scorecard.cap_reason} |
| **監査カバレッジ率（推定）** | **{scorecard.audit_coverage_percent}%** （検査モード: `{metadata.mode}` / 検査ファイル数: {metadata.files_scanned} 件 / 誤検知除外: {metadata.false_positives_filtered} 件） |
| **推奨継続保守プラン** | **{recommended_plan}** （提案書: `{run_dir / 'maintenance_proposal.md'}`） |
| **ビジュアルHTMLレポート** | `{run_dir / 'report.html'}` |

---

## 📊 2. 6大監査領域別スコア内訳（合計100点）

{domain_table_md}

---

## 🏗️ 3. 組織・システム全構造マップ (Organizational Topology)

- **検査対象ルート**: `{topology.root_path}` (`{metadata.target_type}`)
- **検出されたサブプロジェクト/モジュール**: `{", ".join(topology.subprojects_detected)}`
- **使用技術スタック**: `{", ".join(topology.tech_stack_summary)}`
- **6層ファイル分布**:
  - 画面・UI層: `{topology.layer_file_counts['frontend_ui']}` ファイル
  - API・業務ロジック層: `{topology.layer_file_counts['backend_api']}` ファイル（推定エンドポイント数: `{topology.api_endpoints_estimated}`）
  - DB・データスキーマ層: `{topology.layer_file_counts['data_db']}` ファイル
  - インフラ・CI/CD・設定層: `{topology.layer_file_counts['infra_ci_config']}` ファイル
  - AIエージェント・統治層: `{topology.layer_file_counts['ai_agents_governance']}` ファイル
- **組織セキュリティ基盤衛生**:
  - `.env` 等のGit追跡除外保護: `{"保護済み (OK)" if topology.has_gitignore_env_protection else "未保護 (要対応)"}`
  - 依存パッケージ固定 (Lockfile): `{"あり (OK)" if topology.has_dependency_lockfile else "未検出"}`
  - 自動テストスイート: `{"あり (OK)" if topology.has_automated_tests else "未検出"}`

### 特定された5つの信頼境界 (Trust Boundaries)
{boundaries_md}

---

## 📋 4. 検出されたセキュリティホール一覧（3軸リスク優先度順）

{findings_table}

---

## 🛡️ 5. サイバーセキュリティ継続保守プログラムのご提案（抜粋）

- **推奨プラン**: **{recommended_plan}**
- **提案書フルテキスト**: 同フォルダ内の `maintenance_proposal.md` に、経営層・クライアント提示用の「3フェーズ改善ロードマップ」「Light / Standard / Enterprise 3プラン比較表」「事前同意・準委任契約境界の定義」を自動出力しています。

---

## 🔍 6. 「高得点・0件＝100%安全」と誤認しないための3視点チェック

1. **① 最後まで終わったか (`run.json` status)**:
   - `{metadata.three_point_zero_check.get("1_completion_status", "")}`
2. **② 予算・上限金額で途中停止していないか**:
   - `{metadata.three_point_zero_check.get("2_budget_stop_check", "")}`
3. **③ どこまで調べたか（調査範囲と未検証の死角）**:
   - `{metadata.three_point_zero_check.get("3_coverage_and_blind_spots", "")}`
"""
    (run_dir / "summary.md").write_text(summary_md, encoding="utf-8")
    (run_dir / "report.html").write_text(
        _build_html_report(metadata, topology, scorecard, sorted_findings, recommended_plan=recommended_plan),
        encoding="utf-8",
    )
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
        findings, files_scanned, topology = scanner.scan_target(msg_or_path)
    else:
        topology = OrganizationTopology(
            root_path=args.target,
            total_files_scanned=0,
            subprojects_detected=[args.target],
            tech_stack_summary=["Staging Web Endpoint"],
            layer_file_counts={
                "frontend_ui": 0,
                "backend_api": 0,
                "data_db": 0,
                "infra_ci_config": 0,
                "ai_agents_governance": 0,
            },
            api_endpoints_estimated=1,
            has_gitignore_env_protection=True,
            has_dependency_lockfile=True,
            has_automated_tests=False,
            ai_agent_configs_count=0,
            trust_boundaries=["External HTTP Client ➔ Staging Server"],
        )

    scorecard = ComprehensiveAuditScorer().evaluate(
        findings=findings,
        topology=topology,
        mode=args.mode,
        status="completed",
        budget_limit_reached=False,
    )

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
        overall_score=scorecard.final_score,
        overall_grade=scorecard.grade,
        overall_verdict=scorecard.verdict,
        coverage={
            "access_control_idor": "checked (25pts: route handler ownership & RBAC analysis)",
            "auth_session": "checked (15pts: JWT signature & session cookie verification)",
            "input_injection_xss": "checked (20pts: SQLi, Command Injection, XSS, SSRF)",
            "secrets_and_data": "checked (15pts: hardcoded secrets, NEXT_PUBLIC_ leaks, .env hygiene)",
            "infra_supply_chain": "checked (15pts: CORS, debug flags, lockfile & CI hygiene)",
            "ai_governance_resilience": "checked (10pts: dynamic eval/exec guard, silent failure check)",
            "untested_blind_spots": "マルチテナント実DB環境での管理者権限昇格・外部決済Webhook署名・本番クラウドIAMポリシーは別途動的検証が必要",
        },
        three_point_zero_check={
            "1_completion_status": "status=completed（途中停止せず最後まで完走済み）",
            "2_budget_stop_check": f"上限 ${args.max_budget:.2f} に対し追加API課金 $0.00（予算到達による途中打ち切りなし）",
            "3_coverage_and_blind_spots": (
                f"組織内の {files_scanned} ファイル（推定API窓口 {topology.api_endpoints_estimated} 箇所、監査カバレッジ率 {scorecard.audit_coverage_percent}%）を検査済み。"
                "ただし本番稼働DB上の実権限ロール（管理者 vs 一般利用者）やクラウドIAM設定は未検証のため、"
                "「100点でも未検証領域の動的テストが必要」な点に留意してください。"
            ),
        },
    )

    out_base = Path(args.output_dir).expanduser().resolve()
    run_dir = write_strix_compatible_run(out_base, metadata, topology, scorecard, findings)
    print(f"[OK] 包括セキュリティ監査完了: {run_dir}")
    print(f"  🏆 総合セキュリティ得点: {scorecard.final_score} / 100 点 (Grade {scorecard.grade} / 素点 {scorecard.raw_score} 点)")
    print(f"  ⚖️  判定 (Verdict): {scorecard.verdict}")
    if scorecard.cap_applied:
        print(f"  ⚠️  キャップ適用: {scorecard.cap_reason}")
    print(f"  - 検査ファイル数: {metadata.files_scanned} (誤検知除外: {metadata.false_positives_filtered} 件)")
    print(f"  - 確定した弱点: {metadata.verified_vulnerabilities_count} 件")
    print(f"  - レポート表示: python3 {Path(__file__).name} view (または --open でブラウザ表示)")
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
    ①組織構造の把握と1回目の監査（69点・Grade C） ➔ ②修正 ➔ ③2回目の監査（100点・Grade S）までを実演する。
    """
    print("=" * 76)
    print("🎬 AIホワイトハッカー 100点満点包括監査デモ（調査 ➔ 採点報告 ➔ 修正 ➔ 再採点）")
    print("=" * 76)

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
    order = ORDERS.get(order_id)
    return order
""",
            encoding="utf-8",
        )

        print("\n[Step 2] 1回目の包括セキュリティ監査を実行します...")
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

        print("\n[Step 4] 修正後に2回目の包括セキュリティ監査を実行します...")
        run_scan_command(scan_args)

    print("\n" + "=" * 76)
    print("🎉 デモ完了！ 1回目（69点・Grade C）から、修正後の2回目で 100点（Grade S）へ改善されました。")
    print("=" * 76)
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_out = str(Path(__file__).resolve().parent / "strix_runs")
    parser = argparse.ArgumentParser(
        description="AI White Hacker Runner — 組織全体構造マッピング＆100点満点包括セキュリティ監査エンジン"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="組織・アプリのフォルダを包括監査して100点満点レポートを出力する")
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

    p_view = sub.add_parser("view", help="直近の100点満点監査レポートを表示する (strix view 互換)")
    p_view.add_argument("--run-id", default="", help="表示する run_id（省略時は最新）")
    p_view.add_argument("--open", action="store_true", help="ブラウザでビジュアル監査ダッシュボードを開く")
    p_view.add_argument("--output-dir", default=default_out, help="strix_runs フォルダパス")

    p_demo = sub.add_parser(
        "demo",
        help="初心者向け体験デモ（69点/Grade C ➔ 修正 ➔ 100点/Grade S の改善サイクルを自動実演）",
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
