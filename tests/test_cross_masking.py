# SPDX-License-Identifier: Apache-2.0
"""Secret-rule hits must never show the secret value in a snippet."""

import os
import re
import unittest

from helpers import FIXTURES, scan_dir

SECRET_RULES = ("XPL-001", "XPL-002", "XPL-003", "CI-006")
KNOWN_FORMAT = re.compile(r"(?:AKIA|ASIA|sk-|[sr]k_live_|gh[pousr]_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_\-]{8,}")


class SecretMasking(unittest.TestCase):
    def test_snippets_are_masked(self):
        for rule_id in SECRET_RULES:
            hits = scan_dir(os.path.join(FIXTURES, rule_id, "vulnerable"), {rule_id})
            self.assertTrue(hits, rule_id)
            for hit in hits:
                snippet = hit.location.snippet
                with self.subTest(rule=rule_id, path=hit.location.path, line=hit.location.line):
                    self.assertIsNone(KNOWN_FORMAT.search(snippet), snippet)
                    if hit.location.line and "PRIVATE KEY-----" not in snippet:
                        self.assertIn("[masked]", snippet)

    def test_short_values_are_masked_too(self):
        hits = scan_dir(os.path.join(FIXTURES, "CI-006", "vulnerable"), {"CI-006"})
        props = [h for h in hits if h.location.path.endswith("key.properties")]
        self.assertEqual(len(props), 1)
        self.assertNotIn("hunter22", props[0].location.snippet)


if __name__ == "__main__":
    unittest.main()
