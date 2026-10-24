# SPDX-License-Identifier: Apache-2.0
"""Cross-platform code rules: debug-only hits are lowered (debug scope), never dropped, and the
structural helpers find the right function."""

import os
import unittest

from helpers import FIXTURES, scan_dir
from masaudit.detectors import cross


def _scopes(rule_id, variant):
    hits = scan_dir(os.path.join(FIXTURES, rule_id, variant), {rule_id})
    return sorted(h.scope for h in hits)


class DebugScope(unittest.TestCase):
    def test_guarded_log_lines_are_debug(self):
        self.assertEqual(_scopes("XPL-010", "debug"), ["debug", "debug"])

    def test_secret_under_if_debug_is_debug(self):
        self.assertEqual(_scopes("XPL-003", "debug"), ["debug"])

    def test_staging_url_chosen_by_debug_flag_is_debug(self):
        self.assertEqual(_scopes("XPL-036", "debug"), ["debug"])

    def test_unguarded_hits_stay_main(self):
        hits = scan_dir(os.path.join(FIXTURES, "XPL-010", "vulnerable"), {"XPL-010"})
        self.assertEqual({h.scope for h in hits if h.location.path.startswith("app/src/main/")}, {"main"})


class Structure(unittest.TestCase):
    def test_enclosing_function_skips_control_blocks(self):
        code = "fun derive(p: String) {\n    if (p.isEmpty()) {\n        val x = 1\n    }\n}\n"
        start, end, head = cross._enclosing_function(code, code.index("val x"), "A.kt")
        self.assertEqual(cross._function_name(head), "derive")
        self.assertEqual(code[start], "{")

    def test_java_method_head(self):
        code = "class A {\n  byte[] decrypt(byte[] in) throws Exception {\n    for (int i = 0; i < 2; i++) {\n" \
               "      x();\n    }\n  }\n}\n"
        _s, _e, head = cross._enclosing_function(code, code.index("x();"), "A.java")
        self.assertEqual(cross._function_name(head), "decrypt")

    def test_fixed_buffer_filled_by_arraycopy_is_not_literal(self):
        code = ("byte[] a() { byte[] nonce = getSecretBytes(12); use(nonce); }\n"
                "byte[] b(byte[] in) { byte[] nonce = new byte[12]; System.arraycopy(in, 0, nonce, 0, 12); "
                "use(nonce); }\n")
        self.assertFalse(cross._var_is_literal(code, "nonce", code.index("use(nonce)", 60), "A.java"))
        self.assertFalse(cross._var_is_literal(code, "nonce", code.index("use(nonce)"), "A.java"))

    def test_zero_buffer_never_written_is_literal(self):
        code = "fun a(key: SecretKey) {\n    val iv = ByteArray(16)\n    init(key, IvParameterSpec(iv))\n}\n"
        self.assertTrue(cross._var_is_literal(code, "iv", code.index("IvParameterSpec"), "A.kt"))


if __name__ == "__main__":
    unittest.main()
