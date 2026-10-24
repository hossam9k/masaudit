# SPDX-License-Identifier: Apache-2.0
"""Flutter and KMP rules: debug-only hits are lowered (debug scope), never dropped."""

import os
import unittest

from helpers import FIXTURES, scan_dir


def _scopes(rule_id, variant):
    hits = scan_dir(os.path.join(FIXTURES, rule_id, variant), {rule_id})
    return sorted((h.location.line, h.scope) for h in hits)


class DebugScope(unittest.TestCase):
    def test_dio_logger_in_assert_is_debug(self):
        self.assertEqual([s for _, s in _scopes("FLT-003", "debug_only")], ["debug"])

    def test_dio_logger_under_kdebugmode_is_debug(self):
        scopes = _scopes("FLT-003", "vulnerable")
        self.assertEqual([s for _, s in scopes], ["main", "main", "main", "debug"])

    def test_webview_debugging_under_kdebugmode_is_debug(self):
        scopes = _scopes("FLT-006", "vulnerable")
        self.assertEqual([s for _, s in scopes].count("debug"), 1)
        self.assertEqual(scopes[-1][1], "debug")

    def test_ktor_logging_under_debug_flag_is_debug(self):
        scopes = _scopes("KMP-004", "vulnerable")
        self.assertEqual([s for _, s in scopes], ["main", "main", "debug"])


class Messages(unittest.TestCase):
    def test_log_interceptor_names_the_locked_dio_version(self):
        hits = scan_dir(os.path.join(FIXTURES, "FLT-003", "vulnerable"), {"FLT-003"})
        self.assertTrue(any("dio 4.0.6" in h.message for h in hits))

    def test_obfuscation_counts_commands_per_file(self):
        hits = scan_dir(os.path.join(FIXTURES, "FLT-008", "vulnerable"), {"FLT-008"})
        workflow = [h for h in hits if h.location.path.endswith("release.yml")]
        self.assertEqual(len(workflow), 1)
        self.assertIn("2 build commands", workflow[0].message)


if __name__ == "__main__":
    unittest.main()
