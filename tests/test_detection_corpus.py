"""
検出精度の回帰テスト（見逃し＝False Negative / 誤検知＝False Positive）。

- 脆弱なコード例(VULNERABLE)は必ず検出されること（recall）
- 安全・紛らわしいコード例(SAFE)は一切検出されないこと（false positive 0）
- シークレット風の文字列はファイルに固定せず、実行時に組み立てる
  （リポジトリに実在形式のキーを置いてGitHubのシークレットスキャンに誤反応させないため）
"""
import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from white_hacker_runner import ExternalToolBridge, WhiteHackerScanner, build_code_mask

STRIPE = "sk_" + "live_" + "51H8aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
GH_REAL_SENTINEL = "ghp_" + "Real" + "GitHubTokenForTestOnly0123456789abcdef"

# (ファイル名, ソース, 期待する検出キーワード(タイトルの一部))
VULNERABLE = {
    "flask_idor": ("app.py", '''from flask import Flask
app = Flask(__name__)
@app.route("/invoice/<int:invoice_id>")
def inv(invoice_id):
    row = db.execute("SELECT * FROM invoices WHERE id = " + str(invoice_id)).fetchone()
    return row
''', "IDOR"),
    "sqli_concat": ("db.py", 'def f(db, n):\n    return db.execute("SELECT * FROM t WHERE n=" + n)\n', "SQLインジェクション"),
    "sqli_format": ("db2.py", 'def f(db, q):\n    return db.execute("SELECT * FROM t WHERE n=\'{}\'".format(q))\n', "SQLインジェクション"),
    "stripe_key": ("conf.py", f'KEY = "{STRIPE}"\n', "秘密鍵"),
    "express_idor": ("server.js", '''const app = require('express')();
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id });
  res.json(order);
});
''', "IDOR"),
    "fetch_ssrf": ("proxy.js", "app.get('/fetch', async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });\n", "SSRF"),
    "comment_bypass_idor": ("api.py", '''from fastapi import FastAPI
app = FastAPI()
@app.get("/orders/{order_id}")
def get_order(order_id: int, user=None):
    # if order.user_id != current_user.id: raise  <- コメントだけで未実装
    return ORDERS.get(order_id)
''', "IDOR"),
    "hardcoded_password": ("cfg.py", 'DB_PASSWORD = "Xk9#mQ2$vL8nRt5Z"\n', "認証情報"),
    "cmd_injection": ("run.py", "import subprocess\ndef f(c):\n    subprocess.run(c, shell=True)\n", "コマンド注入"),
}

SAFE = {
    "comment_shell": ("a.py", "# subprocess.run(cmd, shell=True)  <- コメント\nx = 1\n"),
    "string_literal_sql": ("b.py", 'DOC = "execute(f\'SELECT ...\') は危険"\n'),
    "docstring_sql": ("b2.py", 'def f():\n    """cursor.execute(f"SELECT * FROM t") のような書き方は避ける"""\n    return 1\n'),
    "parameterized_sql": ("c.py", 'def f(cur, i):\n    cur.execute("SELECT * FROM a WHERE id=?", (i,))\n'),
    "fastapi_owner_checked": ("d.py", '''from fastapi import FastAPI, Depends, HTTPException
app = FastAPI()
@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_logged_in_user)):
    order = ORDERS.get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(status_code=403)
    return order
'''),
    "express_owner_checked": ("e.js", '''app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, owner: req.user.id });
  res.json(order);
});
'''),
    "placeholder_token": ("f.py", f'EXAMPLE = "{GH_REAL_SENTINEL}"\nTOKEN_DOC = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'),
    "hash_fingerprint_not_secret": ("h.py", 'rec = dict(password_hash_fingerprint="9f86d081884c7d659a2feaa0c55ad015", token_id="a1b2c3d4e5f60718293a")\n'),
    "british_sanitiser": ("v.tsx", "import { sanitisePanelHtml } from './sanitise'\nconst x = <div dangerouslySetInnerHTML={{ __html: sanitisePanelHtml(h) }} />\n"),
    "env_read": ("g.py", 'import os\nAPI_KEY = os.environ["APP_API_KEY"]\n'),
}


def scan_single(name: str, src: str):
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / name).write_text(src, encoding="utf-8")
        scanner = WhiteHackerScanner(mode="quick")
        findings, _, _ = scanner.scan_target(td)
        return findings


class TestDetectionCorpus(unittest.TestCase):
    def test_recall_on_vulnerable_corpus(self):
        missed = []
        for case, (fname, src, expect) in VULNERABLE.items():
            titles = [f.title for f in scan_single(fname, src)]
            if not any(expect in t for t in titles):
                missed.append((case, titles))
        total = len(VULNERABLE)
        print(f"\n[corpus] recall = {total - len(missed)}/{total}")
        self.assertEqual(missed, [], f"見逃し: {missed}")

    def test_no_false_positives_on_safe_corpus(self):
        flagged = []
        for case, (fname, src) in SAFE.items():
            titles = [f.title for f in scan_single(fname, src)]
            if titles:
                flagged.append((case, titles))
        total = len(SAFE)
        print(f"\n[corpus] false positives = {len(flagged)}/{total}")
        self.assertEqual(flagged, [], f"誤検知: {flagged}")

    def test_findings_are_not_labeled_verified(self):
        for fname, src, _ in VULNERABLE.values():
            for f in scan_single(fname, src):
                self.assertEqual(f.verification_status, "PATTERN_MATCH_UNVERIFIED")

    def test_code_mask_basics(self):
        text = 'x = "a#b"  # c\ny = 1\n'
        mask = build_code_mask(text, ".py")
        self.assertEqual(mask[text.index("a#b")], "s")
        self.assertEqual(mask[text.index("# c")], "m")
        self.assertEqual(mask[text.index("y")], "c")

    def test_external_tool_parsers_with_canned_output(self):
        """semgrep/gitleaks が未導入でも、出力JSONのパース（取り込み）ロジックを検証する"""
        bridge = ExternalToolBridge()
        gl = bridge.parse_gitleaks([{"RuleID": "aws-access-token", "Description": "AWS key", "File": "a\\b.py", "StartLine": 7}], 1)
        self.assertEqual(gl[0].severity, "CRITICAL")
        self.assertEqual(gl[0].file_path, "a/b.py")
        self.assertEqual(gl[0].verification_status, "EXTERNAL_TOOL_REPORTED")
        sg = bridge.parse_semgrep({"results": [{"check_id": "python.django.sql-injection", "path": "x.py",
                                                "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "m", "lines": "l"}}]}, 2)
        self.assertEqual(sg[0].severity, "HIGH")
        self.assertEqual(sg[0].domain_key, "input_injection")


if __name__ == "__main__":
    unittest.main()
