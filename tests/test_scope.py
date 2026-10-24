# SPDX-License-Identifier: Apache-2.0
"""Which code ships: file scope from the path, and debug-only blocks inside a file."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import guards, lexer
from masaudit.detect import scope_of

# Paths taken from real apps scanned during the precision review (2026-10-24).
CASES = {
    "app/src/main/java/org/wikipedia/analytics/ABTest.kt": "main",
    "core/src/main/java/com/x/attest/KeyAttest.kt": "main",
    "app/src/main/kotlin/com/acme/Latest.kt": "main",
    "analytics/testkitchen/src/main/java/a/SessionController.kt": "main",
    "app/src/main/java/com/acme/testing/Production.kt": "main",
    "app/src/testShared/org/x/DonationResponses.kt": "test",
    "app/src/benchmarkShared/java/org/x/Harness.kt": "test",
    "mail/testing/src/main/java/a/VeryTrustingTrustManager.kt": "test",
    "SignalUI/Calls/CallLinkTest.swift": "test",
    "WikipediaUnitTests/Code/NSURL+WMFExtrasTests.m": "test",
    "WMFData/Sources/WMFDataMocks/WMFMockURLSession.swift": "test",
    "feature/x/src/commonTest/kotlin/FooTest.kt": "test",
    "test/widget_test.dart": "test",
    "build-logic/plugins/src/main/java/Licenses.kt": "build-script",
    "app/build.gradle.kts": "build-script",
    "components/ui/catalog/src/main/kotlin/a/TabRowItems.kt": "debug",
    "features/m/impl/src/main/kotlin/a/BannerStatePreviewParam.kt": "debug",
    "app/src/debug/AndroidManifest.xml": "debug",
    "app/src/main/AndroidManifest.xml": "main",
    "lib/main.dart": "main",
    ".github/workflows/ci.yml": "ci",
    "Sources/Networking/URLTests.swift": "test",
    "app/src/internal/java/com/acme/DevMenu.kt": "debug",
    "sync/sync-internal/src/main/java/com/ddg/SyncInternal.kt": "debug",
    "app/settings/internal/src/main/kotlin/Playground.kt": "debug",
    "app/src/main/java/com/acme/internal/Crypto.kt": "main",
}


class Scope(unittest.TestCase):
    def test_paths(self):
        for path, expected in CASES.items():
            with self.subTest(path=path):
                self.assertEqual(scope_of(path), expected)


def _guarded(check, code, marker, lang):
    blank = lexer.strip(code, lang, keep_strings=False)
    return check(blank, code.index(marker))


class DebugGuards(unittest.TestCase):
    def test_kotlin(self):
        code = "if (BuildConfig.DEBUG) {\n  Log.d(TAG, token)\n}\nLog.d(TAG, other)\n"
        self.assertTrue(_guarded(guards.jvm_debug_guarded, code, "token", "kotlin"))
        self.assertFalse(_guarded(guards.jvm_debug_guarded, code, "other", "kotlin"))
        self.assertFalse(_guarded(guards.jvm_debug_guarded, "if (!BuildConfig.DEBUG) { x(token) }", "token", "kotlin"))

    def test_swift(self):
        code = "#if DEBUG\nprint(token)\n#else\nprint(release)\n#endif\nprint(after)\n"
        self.assertTrue(_guarded(guards.swift_debug_guarded, code, "token", "swift"))
        self.assertFalse(_guarded(guards.swift_debug_guarded, code, "release", "swift"))
        self.assertFalse(_guarded(guards.swift_debug_guarded, code, "after", "swift"))
        self.assertFalse(_guarded(guards.swift_debug_guarded, "#if !DEBUG\nprint(token)\n#endif\n", "token", "swift"))

    def test_dart(self):
        code = "if (kDebugMode) {\n  print(token);\n}\nprint(other);\n"
        self.assertTrue(_guarded(guards.dart_debug_guarded, code, "token", "dart"))
        self.assertFalse(_guarded(guards.dart_debug_guarded, code, "other", "dart"))



class FastGuardsMatchReference(unittest.TestCase):
    """guards and textscan answer exactly as the original walks did, on the first question about a
    text and on later ones (which use a per-text index)."""

    def test_same_answers_on_fixtures_and_mutations(self):
        import os
        import random
        import sys

        import reference_guards
        from masaudit import textscan
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fuzz"))
        import fuzz_parsers

        pool = list(fuzz_parsers._seeds(os.path.join(os.path.dirname(__file__), "fixtures")))
        rng = random.Random(5)
        texts = [p.decode("utf-8", "replace") for p in pool[:400]]
        texts += [fuzz_parsers._mutate(rng, rng.choice(pool), pool).decode("utf-8", "replace") for _ in range(150)]
        texts += ["if (BuildConfig.DEBUG) { a(); if (x) { b(); } }\nc();", "#if DEBUG\na\n#else\nb\n#endif\nc",
                  "#ifdef DEBUG\nx\n#elif FOO\ny\n#endif", "if (kDebugMode) {\n f();\n}\n g();", "{{{{(((("]
        for text in texts:
            for path in ("A.kt", "A.swift", "a.dart", "a.m"):
                lang = lexer.LANG_BY_SUFFIX[path[path.index("."):]]
                blank = lexer.strip(text, lang, keep_strings=False)
                spots = sorted({0, len(blank)} | {rng.randrange(len(blank) + 1) for _ in range(8)})
                for _ in range(2):                    # first question, then the indexed path
                    for i in spots:
                        self.assertEqual(guards.debug_guarded(path, blank, i),
                                         reference_guards.debug_guarded(path, blank, i), (path, i, text[:40]))
                        self.assertEqual(guards.preprocessor_debug_guarded(blank, i),
                                         reference_guards.preprocessor_debug_guarded(blank, i))
                for _ in range(2):
                    for i in [k for k, ch in enumerate(blank) if ch in "({"][:40]:
                        closer = ")" if blank[i] == "(" else "}"
                        self.assertEqual(textscan.bracket_match(blank, i, blank[i], closer),
                                         reference_guards.match(blank, i, blank[i], closer))

if __name__ == "__main__":
    unittest.main()
