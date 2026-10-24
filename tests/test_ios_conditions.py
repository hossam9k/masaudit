# SPDX-License-Identifier: Apache-2.0
"""Shared schemes, shipping configurations and #if evaluation for the iOS detectors."""

import os
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit.detectors import ios
from masaudit.parsers import pbxproj, xcscheme

SCHEME = """<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion = "1600" version = "1.7">
   <BuildAction parallelizeBuildables = "YES" buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting = "YES" buildForArchiving = "YES">
            <BuildableReference BuildableIdentifier = "primary" BlueprintIdentifier = "D8EC3DCE1E9BDA35006712EB"
               BuildableName = "Alpha.app" BlueprintName = "Alpha" ReferencedContainer = "container:Wikipedia.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
         <BuildActionEntry buildForTesting = "YES" buildForArchiving = "NO">
            <BuildableReference BlueprintIdentifier = "AAAA" BlueprintName = "AlphaTests"></BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <LaunchAction buildConfiguration = "AlphaDebug"></LaunchAction>
   <ArchiveAction buildConfiguration = "Alpha" revealArchiveInOrganizer = "YES"></ArchiveAction>
</Scheme>
"""


class SchemeTests(unittest.TestCase):
    def test_parse(self):
        s = xcscheme.parse(SCHEME, "Alpha")
        self.assertEqual((s.name, s.archive_config, s.launch_config), ("Alpha", "Alpha", "AlphaDebug"))
        self.assertEqual(s.archive_targets, ["D8EC3DCE1E9BDA35006712EB"])
        self.assertEqual(s.archive_target_names, ["Alpha"])

    def test_rejects_non_schemes_and_entities(self):
        for text in ("", "<Workspace/>", "not xml", '<!DOCTYPE x [<!ENTITY a "b">]><Scheme/>'):
            self.assertIsNone(xcscheme.parse(text), text)

    def test_shared_schemes_listing(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "App.xcodeproj", "xcshareddata", "xcschemes")
            os.makedirs(folder)
            with open(os.path.join(folder, "App.xcscheme"), "w", encoding="utf-8") as fh:
                fh.write(SCHEME)
            with open(os.path.join(folder, "notes.txt"), "w", encoding="utf-8") as fh:
                fh.write("x")
            self.assertEqual([s.name for s in xcscheme.shared_schemes(tmp, "App.xcodeproj")], ["App"])
            self.assertEqual(xcscheme.shared_schemes(tmp, "Missing.xcodeproj"), [])
            self.assertEqual(xcscheme.shared_schemes(tmp, "../outside"), [])

    def test_debug_config_names(self):
        for name in ("UITests", "Test-Staging", "Profile", "Local", "app-dev"):
            self.assertTrue(pbxproj.is_debug_config(name), name)
        for name in ("Release", "Alpha", "Experimental", "App Store Release", "Staging"):
            self.assertFalse(pbxproj.is_debug_config(name), name)


# MAIN and LEVEL: set by the app target. EXTENSION: set only by extensions (both branches ship).
# WMF_ALPHA: set only by another app flavor. DEBUG: Debug configurations only.
ENV = ios.CondEnv(defined={"MAIN": "1", "LEVEL": "2"}, partial={"EXTENSION"},
                  known={"MAIN", "EXTENSION", "LEVEL", "WMF_ALPHA", "DEBUG"}, targets={"EXTENSION": ["Share", "Widget"]})


class ConditionTests(unittest.TestCase):
    def test_eval(self):
        cases = {
            "DEBUG": False, "!DEBUG": True, "MAIN": True, "EXTENSION": None, "!EXTENSION": None,
            "WMF_ALPHA || WMF_EXPERIMENTAL": None, "WMF_ALPHA || DEBUG": False, "UNKNOWN": None,
            "MAIN && !DEBUG": True, "EXTENSION || MAIN": True, "EXTENSION && DEBUG": False,
            "os(iOS)": None, "targetEnvironment(simulator)": False, "canImport(UIKit) && DEBUG": False,
            "swift(>=5.9)": None, "defined(DEBUG)": False, "defined MAIN": True, "DEBUG == 0": True,
            "LEVEL >= 2": True, "(MAIN)": True, "false": False, "1": True, "0": False,
            "canImport(X, _version: 1.2)": None, "((": None, "A B": None,
        }
        for expr, want in cases.items():
            with self.subTest(expr=expr):
                self.assertIs(ios._eval_cond(expr, ENV), want)

    def test_blank_inactive(self):
        code = ("a()\n#if WMF_ALPHA\nb()\n#elseif EXTENSION\nc()\n#else\nd()\n#endif\n"
                "#if UNKNOWN\ne()\n#else\nf()\n#endif\n#ifdef DEBUG\ng()\n#elif EXTENSION\nh()\n#endif\n"
                "#if MAIN\ni()\n#else\nj()\n#endif\n")
        out = ios._blank_inactive(code, ENV)
        self.assertEqual(len(out), len(code))
        self.assertEqual({c for c in "abcdefghij" if f"{c}()" in out}, {"a", "c", "d", "e", "f", "h", "i"})

    def test_branch_variants(self):
        body = "{\n#if EXTENSION\ntrustAll()\n#else\nevaluate()\n#endif\nend()\n}"
        texts = [(("trustAll" in t), ("evaluate" in t), conds) for t, conds in ios._branch_variants(body, ENV)]
        # Extension-only flag: both branches compile into some binary.
        self.assertEqual(texts, [(True, False, ["EXTENSION"]), (False, True, [])])
        # Set by the app itself: its #else is dead.
        self.assertEqual(len(ios._branch_variants(body.replace("EXTENSION", "MAIN"), ENV)), 1)
        self.assertIn("compiled into Share, Widget", ios._variant_note(ENV, ["EXTENSION"]))
        self.assertEqual(ios._branch_variants("{ no directives }", ENV), [("{ no directives }", [])])


class ConfigSymbolTests(unittest.TestCase):
    def test_tokens(self):
        self.assertEqual(ios._cond_tokens("OTHER_SWIFT_FLAGS", "$(inherited) -D DEBUG -DWMF_ALPHA -Onone"),
                         {"DEBUG": "1", "WMF_ALPHA": "1"})
        self.assertEqual(ios._cond_tokens("GCC_PREPROCESSOR_DEFINITIONS", '"DEBUG=1" $(inherited) COCOAPODS=1'),
                         {"DEBUG": "1", "COCOAPODS": "1"})
        self.assertEqual(ios._cond_tokens("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "$(inherited) EXTENSION"),
                         {"EXTENSION": "1"})


if __name__ == "__main__":
    unittest.main()
