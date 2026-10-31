import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from white_hacker_runner import (
    WhiteHackerScanner,
    main,
    validate_target_scope,
)


class TestWhiteHackerRunner(unittest.TestCase):
    def test_blocks_unauthorized_external_url(self):
        """無断の外部サイト（友達のサイトや第三者URL）は物理遮断されること"""
        ok, ttype, msg = validate_target_scope("https://friends-app.example.com/orders/1")
        self.assertFalse(ok)
        self.assertEqual(ttype, "unauthorized_external_url")
        self.assertIn("SECURITY GATE BLOCKED", msg)

    def test_allows_localhost_and_authorized_staging(self):
        """localhost や明示許可したステージング環境のみ通過すること"""
        ok1, ttype1, _ = validate_target_scope("http://localhost:3000/api/orders")
        self.assertTrue(ok1)
        self.assertEqual(ttype1, "staging_url")

        ok2, ttype2, _ = validate_target_scope(
            "https://staging.my-own-app.internal/api",
            allow_staging_hosts=["staging.my-own-app.internal"],
        )
        self.assertTrue(ok2)
        self.assertEqual(ttype2, "staging_url")

    def test_100_point_scoring_cap_and_maintenance_proposal(self):
        """
        100点満点採点・ハードキャップ制（HIGH残存時は69点/Grade C上限 ➔ 修正後100点/Grade S）
        および組織構造マップ・保守プログラム提案書(maintenance_proposal.md)の生成検証
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            app_file = tmp_path / "shop_api.py"
            runs_dir = tmp_path / "strix_runs"

            vulnerable_code = """from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()
ORDERS = {1001: {"id": 1001, "user_id": "user_a", "item": "PC"}}

@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_logged_in_user)):
    order = ORDERS.get(order_id)
    return order
"""
            app_file.write_text(vulnerable_code, encoding="utf-8")

            rc = main(
                [
                    "scan",
                    "--target",
                    str(tmp_path),
                    "--mode",
                    "quick",
                    "--max-budget",
                    "5.0",
                    "--output-dir",
                    str(runs_dir),
                ]
            )
            self.assertEqual(rc, 0)

            run_folders = sorted(runs_dir.iterdir())
            self.assertEqual(len(run_folders), 1)
            latest_run = run_folders[0]

            run_json = json.loads((latest_run / "run.json").read_text(encoding="utf-8"))
            scorecard_data = json.loads((latest_run / "audit_scorecard.json").read_text(encoding="utf-8"))
            vulns_json = json.loads((latest_run / "vulnerabilities.json").read_text(encoding="utf-8"))

            self.assertEqual(run_json["status"], "completed")
            self.assertEqual(run_json["verified_vulnerabilities_count"], 1)
            # HIGH 1件（素点 100 - 12 = 88点 だが、HIGH残存キャップにより 69点 / Grade C になること）
            self.assertEqual(scorecard_data["scorecard"]["raw_score"], 88)
            self.assertEqual(scorecard_data["scorecard"]["final_score"], 69)
            self.assertEqual(scorecard_data["scorecard"]["grade"], "C")
            self.assertTrue(scorecard_data["scorecard"]["cap_applied"])
            self.assertEqual(len(scorecard_data["scorecard"]["domain_scores"]), 6)

            self.assertEqual(vulns_json[0]["id"], "WH-001")
            self.assertIn("IDOR", vulns_json[0]["title"])
            self.assertTrue((latest_run / "findings" / "WH-001.md").exists())
            self.assertTrue((latest_run / "report.html").exists())
            self.assertTrue((latest_run / "maintenance_proposal.md").exists())

            proposal_text = (latest_run / "maintenance_proposal.md").read_text(encoding="utf-8")
            self.assertIn("サイバーセキュリティ継続保守プログラム", proposal_text)
            self.assertIn("69 / 100 点", proposal_text)

            # 修正後: 100点 / Grade S になること
            fixed_code = """from fastapi import FastAPI, Depends, HTTPException

app = FastAPI()
ORDERS = {1001: {"id": 1001, "user_id": "user_a", "item": "PC"}}

@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_logged_in_user)):
    order = ORDERS.get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return order
"""
            app_file.write_text(fixed_code, encoding="utf-8")

            scanner_after = WhiteHackerScanner(mode="quick")
            findings_after, _, _ = scanner_after.scan_target(str(tmp_path))

            self.assertEqual(len(findings_after), 0)
            self.assertEqual(scanner_after.false_positives_filtered, 1)

    def test_critical_vulnerability_caps_score_at_49_grade_d(self):
        """CRITICAL脆弱性（SQLi等）がある場合は素点が高くても49点（Grade D）以下にキャップされること"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            app_file = tmp_path / "db_api.py"
            runs_dir = tmp_path / "strix_runs"

            app_file.write_text(
                "def find_user(cursor, name):\n"
                "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
                encoding="utf-8",
            )
            rc = main(["scan", "--target", str(tmp_path), "--mode", "quick", "--output-dir", str(runs_dir)])
            self.assertEqual(rc, 0)
            latest_run = sorted(runs_dir.iterdir())[-1]
            scorecard = json.loads((latest_run / "audit_scorecard.json").read_text(encoding="utf-8"))["scorecard"]
            self.assertEqual(scorecard["final_score"], 49)
            self.assertEqual(scorecard["grade"], "D")
            self.assertTrue(scorecard["cap_applied"])

    def test_builtin_demo_command(self):
        """初心者向けの demo コマンドがエラーなく完走し、1回目69点➔2回目100点になること"""
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir) / "strix_runs"
            rc = main(["demo", "--output-dir", str(runs_dir)])
            self.assertEqual(rc, 0)
            run_folders = sorted(runs_dir.iterdir())
            self.assertEqual(len(run_folders), 2)
            first_run = json.loads((run_folders[0] / "run.json").read_text(encoding="utf-8"))
            second_run = json.loads((run_folders[1] / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(first_run["overall_score"], 69)
            self.assertEqual(first_run["overall_grade"], "C")
            self.assertEqual(second_run["overall_score"], 100)
            self.assertEqual(second_run["overall_grade"], "S")

    def test_opensource_sanitization_no_personal_paths(self):
        """公開用リポジトリ内に個人環境パス(/Users/等)が含まれていないこと"""
        repo_root = Path(__file__).resolve().parent.parent
        for fpath in repo_root.rglob("*"):
            if fpath.is_dir() or ".git" in fpath.parts or "__pycache__" in fpath.parts or "strix_runs" in fpath.parts:
                continue
            if fpath.name == "test_white_hacker_runner.py":
                continue
            text = fpath.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("/Users/", text, f"Personal macOS path leaked in {fpath}")


if __name__ == "__main__":
    unittest.main()
