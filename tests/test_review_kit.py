# SPDX-License-Identifier: Apache-2.0
"""scripts/review_kit.py: the blind review file and the comparison with the published verdicts."""

import contextlib
import csv
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import review_kit  # noqa: E402


class ReviewKit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "review.csv")
        with contextlib.redirect_stdout(io.StringIO()):
            review_kit.make("5", self.out, 1)
        with open(self.out, newline="", encoding="utf-8") as fh:
            self.rows = list(csv.DictReader(fh))
        with open(os.path.join(ROOT, "docs", "benchmark-judgments-5.json"), encoding="utf-8") as fh:
            self.judged = json.load(fh)["judged"]

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_blind_and_complete(self):
        self.assertEqual(sorted(int(r["id"]) for r in self.rows), list(range(len(self.judged))))
        text = open(self.out, encoding="utf-8").read().lower()
        for hidden in ("mobsfscan", "rnsec", "semgrep", "overrated", "check by hand"):
            self.assertNotIn(hidden, text)
        for r in self.rows:
            self.assertRegex(r["link"], r"^https://github\.com/[\w.-]+/[\w.-]+/blob/[0-9a-f]{40}/.+#L\d+$")
            self.assertTrue(r["message"] and not r["verdict"] and not r["reason"])

    def test_the_published_verdicts_agree_with_themselves(self):
        for r in self.rows:
            r["verdict"] = self.judged[int(r["id"])]["verdict"]
        with open(self.out, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(self.rows[0]))
            w.writeheader()
            w.writerows(self.rows)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(review_kit.compare("5", self.out), 0)
        self.assertIn("same verdict on 244 (100%)", out.getvalue())
        self.assertIn("Cohen's kappa: 1.00", out.getvalue())


if __name__ == "__main__":
    unittest.main()
