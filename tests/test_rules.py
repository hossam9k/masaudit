# SPDX-License-Identifier: Apache-2.0
"""Every rule must fire on its vulnerable fixture and stay silent on its clean (near-miss) fixture.

Layout: tests/fixtures/<RULE-ID>/{vulnerable,clean}/... and expected.json with hit counts:
{"vulnerable": <n>, "clean": 0}. Every non-retired rule must have a fixture.
"""

import json
import os
import shutil
import tempfile
import unittest

from helpers import FIXTURES, scan_dir
from masaudit import engine


class RuleFixtures(unittest.TestCase):
    def test_every_rule_has_a_fixture(self):
        missing = [r.id for r in engine.load_rules()
                   if not r.retired and not os.path.isdir(os.path.join(FIXTURES, r.id))]
        self.assertEqual(missing, [], "rules without fixtures")

    def test_fixtures(self):
        for rule_id in sorted(os.listdir(FIXTURES)):
            base = os.path.join(FIXTURES, rule_id)
            exp_path = os.path.join(base, "expected.json")
            if not os.path.isfile(exp_path):
                continue
            with open(exp_path, encoding="utf-8") as fh:
                expected = json.load(fh)
            for variant, want in expected.items():
                with self.subTest(rule=rule_id, variant=variant):
                    hits = [f for f in scan_dir(os.path.join(base, variant), {rule_id})]
                    self.assertEqual(
                        len(hits), want,
                        f"{rule_id}/{variant}: expected {want} hit(s), got "
                        + ", ".join(f"{h.location.path}:{h.location.line}" for h in hits),
                    )

    def test_fixtures_give_the_same_results_with_windows_line_endings(self):
        # A repository checked out on Windows (or committed with CRLF) must scan the same way.
        tmp = tempfile.mkdtemp()
        try:
            for rule_id in sorted(os.listdir(FIXTURES)):
                base = os.path.join(FIXTURES, rule_id)
                exp_path = os.path.join(base, "expected.json")
                if not os.path.isfile(exp_path):
                    continue
                with open(exp_path, encoding="utf-8") as fh:
                    expected = json.load(fh)
                for variant, want in expected.items():
                    src, dst = os.path.join(base, variant), os.path.join(tmp, rule_id, variant)
                    _copy_with_crlf(src, dst)
                    with self.subTest(rule=rule_id, variant=variant):
                        self.assertEqual(len(scan_dir(dst, {rule_id})), want, f"{rule_id}/{variant} with CRLF")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def _copy_with_crlf(src, dst):
    for dirpath, _dirs, files in os.walk(src):
        out = os.path.join(dst, os.path.relpath(dirpath, src))
        os.makedirs(out, exist_ok=True)
        for name in files:
            with open(os.path.join(dirpath, name), "rb") as fh:
                data = fh.read()
            if b"\0" not in data[:8192]:
                data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            with open(os.path.join(out, name), "wb") as fh:
                fh.write(data)


if __name__ == "__main__":
    unittest.main()
