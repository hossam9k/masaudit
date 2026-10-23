# SPDX-License-Identifier: Apache-2.0
"""Rule metadata must be complete, consistent with the book, and safe to show newcomers."""

import json
import os
import re
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import engine, profile

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "src", "masaudit", "rules")


def _load(name):
    with open(os.path.join(RULES_DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


SECTIONS = _load("_book_sections.json")
MASWE = _load("_maswe.json")
ID_FORMAT = re.compile(r"^(AND|IOS|KMP|XPL|CI)-\d{3}$")
PREFIX = {"android": "AND", "ios": "IOS", "kmp": "KMP", "cross": "XPL", "ci": "CI"}


class RuleMetadata(unittest.TestCase):
    rules = engine.load_rules()

    def test_ids(self):
        for r in self.rules:
            with self.subTest(rule=r.id):
                self.assertRegex(r.id, ID_FORMAT)
                self.assertTrue(r.id.startswith(PREFIX[r.platform] + "-"), "prefix must match platform")

    def test_book_links_resolve(self):
        for r in self.rules:
            with self.subTest(rule=r.id):
                self.assertIn(r.book, SECTIONS, "book reference must be a real § or Chapter")
                self.assertEqual(r.book_url, SECTIONS[r.book], "book_url must match the § it names")

    def test_maswe_ids_exist_and_match_masvs(self):
        for r in self.rules:
            if r.maswe is None:
                continue
            with self.subTest(rule=r.id):
                self.assertIn(r.maswe, MASWE, "MASWE ID must exist in v1.0.0")
                if r.masvs:
                    self.assertEqual(r.masvs, MASWE[r.maswe]["masvs"], "MASVS must match the MASWE mapping")

    def test_mastg_ids_are_v2(self):
        for r in self.rules:
            for t in r.mastg:
                with self.subTest(rule=r.id, test=t):
                    m = re.match(r"^MASTG-(TEST|BEST|TECH|KNOW|DEMO)-(\d{4})$", t)
                    self.assertIsNotNone(m)
                    if m.group(1) == "TEST":
                        self.assertGreaterEqual(int(m.group(2)), 200, "v1 tests are deprecated")

    def test_fields(self):
        for r in self.rules:
            with self.subTest(rule=r.id):
                self.assertIn(r.effort, ("minutes", "hours", "days"))
                self.assertIn(r.confidence, ("high", "medium", "manual"))
                self.assertTrue(set(r.profiles) <= {"L1", "L2", "R", "P"} and r.profiles)
                if r.app_types is not None:
                    self.assertTrue(set(r.app_types) <= set(profile.APP_TYPES))
                    self.assertTrue(r.not_needed_reason, "app_types rules must explain why others don't need it")
                self.assertTrue(r.detector or r.pattern, "a rule needs a detector or a pattern")
                for text in (r.title, r.why, r.fix, r.verify):
                    self.assertTrue(text.strip())
                    self.assertNotRegex(text, r"\b(simply|just|obviously|easy|easily)\b", "no filler words")
                    self.assertNotRegex(text, r"(isation|ised\b|behaviour|colour|defence|licence)", "US spelling")
                self.assertLessEqual(len(r.why), 400, "keep 'why' short")
                if r.safe_fix:
                    self.assertEqual(r.id, "AND-002", "only the vetted debuggable rule may be safe_fix in v1")


if __name__ == "__main__":
    unittest.main()
