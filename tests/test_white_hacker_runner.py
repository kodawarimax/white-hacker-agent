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

    def test_discover_verify_fix_reverify_idor_cycle(self):
        """
        「他人の注文が見えてしまう(IDOR)」の検出 ➔ 報告(MD+HTML) ➔ 修正 ➔ 再検証(0件化)サイクルの検証
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
            vulns_json = json.loads((latest_run / "vulnerabilities.json").read_text(encoding="utf-8"))

            self.assertEqual(run_json["status"], "completed")
            self.assertEqual(run_json["verified_vulnerabilities_count"], 1)
            self.assertEqual(vulns_json[0]["id"], "WH-001")
            self.assertIn("IDOR", vulns_json[0]["title"])
            self.assertTrue((latest_run / "findings" / "WH-001.md").exists())
            self.assertTrue((latest_run / "report.html").exists())

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
            findings_after, _ = scanner_after.scan_target(str(tmp_path))

            self.assertEqual(len(findings_after), 0)
            self.assertEqual(scanner_after.false_positives_filtered, 1)

    def test_builtin_demo_command(self):
        """初心者向けの demo コマンドがエラーなく完走し、1回目検出➔2回目0件化すること"""
        with tempfile.TemporaryDirectory() as tmpdir:
            runs_dir = Path(tmpdir) / "strix_runs"
            rc = main(["demo", "--output-dir", str(runs_dir)])
            self.assertEqual(rc, 0)
            run_folders = sorted(runs_dir.iterdir())
            self.assertEqual(len(run_folders), 2)
            first_run = json.loads((run_folders[0] / "run.json").read_text(encoding="utf-8"))
            second_run = json.loads((run_folders[1] / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(first_run["verified_vulnerabilities_count"], 1)
            self.assertEqual(second_run["verified_vulnerabilities_count"], 0)

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
