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


def _severities(rule_id, variant):
    hits = scan_dir(os.path.join(FIXTURES, rule_id, variant), {rule_id})
    return {f"{h.location.path}:{h.location.line}": h.severity for h in hits}


class AuditedSeverity(unittest.TestCase):
    """Per-hit severities the final precision audit asked for (ios-code audit)."""

    def test_pbkdf2_legacy_fallback_is_low(self):
        self.assertEqual(set(_severities("XPL-015", "vulnerable_legacy").values()), {"low"})
        # The enum's weakest entry is reported once, at the entry, not at each call site.
        self.assertIn("app/src/main/java/com/demo/crypto/CryptoHelper.kt:12", _severities("XPL-015", "vulnerable_legacy"))

    def test_pbkdf2_100k_is_medium(self):
        self.assertEqual(list(_severities("XPL-015", "vulnerable_medium").values()), ["medium"])

    def test_cbc_auth_bound_keystore_key_is_low(self):
        self.assertEqual(list(_severities("XPL-005", "vulnerable_auth_bound").values()), ["low"])

    def test_ecb_nsae_fallback_and_legacy_rsa_are_low(self):
        self.assertEqual(list(_severities("XPL-004", "vulnerable_fallback").values()), ["low"])
        self.assertEqual(list(_severities("XPL-023", "vulnerable_legacy").values()), ["low"])
        self.assertIn("", _severities("XPL-004", "vulnerable").values())

    def test_mac_compare_is_low_without_remote_io(self):
        self.assertEqual(set(_severities("XPL-025", "vulnerable").values()), {"low"})
        self.assertEqual(list(_severities("XPL-025", "vulnerable_network").values()), [""])

    def test_http_link_opened_in_browser_is_low(self):
        sev = _severities("XPL-009", "vulnerable")
        self.assertEqual(sev["app/src/main/java/com/demo/Help.kt:2"], "low")
        self.assertEqual(sev["app/src/main/java/com/demo/Api.kt:2"], "")

    def test_absence_anchor_skips_watch_app(self):
        hits = scan_dir(os.path.join(FIXTURES, "XPL-021", "watch_anchor"), {"XPL-021"})
        self.assertEqual([h.location.path for h in hits], ["ios/Bank/Application/Support/Info.plist"])


class DebuggerEvidence(unittest.TestCase):
    def test_watchdog_and_debug_only_checks_are_not_evidence(self):
        text = "if (!uiRan && !Debug.isDebuggerConnected()) report()"
        m = cross.DEBUGGER_ANDROID.search(text)
        self.assertFalse(cross._real_debugger_check("app/src/main/java/A.kt", text, m))
        text = "val attached = Debug.isDebuggerConnected()"
        self.assertTrue(cross._real_debugger_check("app/src/main/java/A.kt", text, cross.DEBUGGER_ANDROID.search(text)))
        self.assertFalse(cross._real_debugger_check("anrs/anrs-impl/src/main/java/AnrSupervisor.kt", text,
                                                    cross.DEBUGGER_ANDROID.search(text)))
        objc = "#ifdef DEBUG\nBOOL f(void) { return p_flag & P_TRACED; }\n#endif\nint g;\n"
        self.assertFalse(cross._real_debugger_check("Utils.m", objc, cross.DEBUGGER_IOS.search(objc)))
        release = "#ifndef DEBUG\nBOOL f(void) { return p_flag & P_TRACED; }\n#endif\n"
        self.assertTrue(cross._real_debugger_check("Utils.m", release, cross.DEBUGGER_IOS.search(release)))


if __name__ == "__main__":
    unittest.main()
