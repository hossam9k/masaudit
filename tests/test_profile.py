# SPDX-License-Identifier: Apache-2.0
"""App types, aliases, code clues, and calibration to the app's profile."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import engine, profile
from masaudit.model import Finding, Location, Rule

PINNING_TYPES = ["banking", "fintech", "health", "ecommerce-cards"]


def make_rule(**kw):
    base = dict(id="AND-900", title="Certificate pinning is missing", platform="android",
                severity="high", profiles=["L2"], why="w", fix="f", verify="v", effort="hours",
                book="§8.8", book_url="https://example.invalid/8.8",
                app_types=list(PINNING_TYPES), not_needed_reason="Pinning is for high-risk apps (§8.8).",
                detector="none")
    base.update(kw)
    return Rule(**base)


def finding(rule, path="app/src/main/java/A.kt", line=3):
    return Finding(rule=rule, location=Location(path=path, line=line, snippet="x"),
                   scope=engine.scope_of(path))


class Profiles(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(profile.normalize("news"), "content")
        self.assertEqual(profile.normalize("News"), "content")
        self.assertEqual(profile.normalize("bank"), "banking")
        self.assertEqual(profile.normalize("ecommerce_cards"), "ecommerce-cards")
        self.assertEqual(profile.make("news", "flag").mas_profiles, ["L1", "P"])
        with self.assertRaises(ValueError):
            profile.normalize("spaceship")

    def test_describe_states_the_source(self):
        p = profile.make("banking", "flag")
        self.assertIn("from --app-type", profile.describe(p))
        self.assertIn("MAS-L1+L2+R+P", profile.describe(p))
        self.assertIn("assumed", profile.describe(profile.make("general", "default")))

    def test_clues_are_suggestions(self):
        clues = profile.infer_clues({"app/build.gradle": "implementation 'com.stripe:stripe-android:20.0.0'"})
        self.assertEqual(len(clues), 1)
        self.assertIn("payment SDK", clues[0])
        self.assertIn("app/build.gradle", clues[0])
        self.assertIn("may fit", clues[0])


class Calibration(unittest.TestCase):
    def test_pinning_rule_not_needed_for_content(self):
        f = finding(make_rule())
        engine.calibrate([f], profile.make("content", "flag"))
        self.assertEqual(f.bucket, "not-needed")
        self.assertEqual(f.effective_severity, "info")
        self.assertIn("high-risk", f.bucket_reason)

    def test_pinning_rule_fix_before_release_for_banking(self):
        f = finding(make_rule())
        engine.calibrate([f], profile.make("banking", "flag"))
        self.assertEqual(f.bucket, "fix-before-release")
        self.assertEqual(f.effective_severity, "high")

    def test_profile_mismatch_is_not_needed(self):
        f = finding(make_rule(app_types=None, profiles=["R"]))
        engine.calibrate([f], profile.make("health", "flag"))
        self.assertEqual(f.bucket, "not-needed")

    def test_debug_scope_is_downgraded(self):
        f = finding(make_rule(app_types=None, profiles=["L1"]), path="app/src/debug/AndroidManifest.xml")
        engine.calibrate([f], profile.make("general", "default"))
        self.assertEqual(f.effective_severity, "low")
        self.assertEqual(f.bucket, "fix-soon")
        self.assertIn("debug", f.bucket_reason)


if __name__ == "__main__":
    unittest.main()
