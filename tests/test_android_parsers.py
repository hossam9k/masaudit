# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Android Gradle/manifest parsers and Android-specific calibration."""

import os
import shutil
import tempfile
import unittest

from helpers import ALL_PLATFORMS  # noqa: F401  (sets sys.path)
from masaudit import engine, lexer, profile, safety
from masaudit.model import Project
from masaudit.parsers import gradle, manifest


def _strip(code, lang):
    return lexer.strip(code, lang, True), lexer.strip(code, lang, False)


class GradleParser(unittest.TestCase):
    def test_release_block_kotlin_and_groovy(self):
        kts = 'android {\n  buildTypes {\n    debug { isDebuggable = true }\n    getByName("release") {\n' \
              '      isDebuggable = true // "}" in a comment\n      buildConfigField("String", "X", "\\"}\\"")\n    }\n  }\n}\n'
        code, blank = _strip(kts, "kotlin")
        blocks = gradle.build_type_blocks(code, blank, "release")
        self.assertEqual(len(blocks), 1)
        values = [v for _, v in gradle.find_settings(code, gradle.setting("isDebuggable|debuggable"),
                                                     blocks[0].body_start, blocks[0].body_end)]
        self.assertEqual(values, ["true"])

        groovy = "android {\n  buildTypes {\n    release {\n      debuggable true\n    }\n  }\n}\n"
        code, blank = _strip(groovy, "groovy")
        block = gradle.build_type_blocks(code, blank, "release")[0]
        values = [v for _, v in gradle.find_settings(code, gradle.setting("isDebuggable|debuggable"),
                                                     block.body_start, block.body_end)]
        self.assertEqual(values, ["true"])

    def test_setting_values(self):
        pat = gradle.setting("targetSdkVersion|targetSdk")
        found = [v for _, v in gradle.find_settings("targetSdk(34)\ntargetSdk = libs.versions.t.get().toInt()\n", pat)]
        self.assertEqual(found, ["34", "libs.versions.t.get().toInt()"])
        self.assertEqual(gradle.int_literal('"35"'), 35)
        self.assertIsNone(gradle.int_literal("libs.versions.t"))

    def test_version_catalog(self):
        toml = '[versions]\ntarget-sdk = "35" # comment\nagp = "8.6.0"\n\n[libraries]\nx = "a:b:1"\n'
        versions = gradle.toml_versions(toml)
        self.assertEqual(versions["target-sdk"], ("35", 2))
        self.assertNotIn("x", versions)
        self.assertEqual(gradle.catalog_key("libs.versions.target.sdk.get().toInt()"), "target.sdk")
        self.assertEqual(gradle.catalog_lookup(versions, "target.sdk"), ("35", 2))


class ManifestParser(unittest.TestCase):
    def test_helpers(self):
        root = manifest.parse(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'xmlns:tools="http://schemas.android.com/tools"><application>'
            '<activity android:name=".Main" android:exported="true"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>'
            '<service android:name=".Gone" tools:node="remove"/>'
            '</application></manifest>')
        comps = list(manifest.components(root))
        self.assertEqual([c.get("android:name") for c in comps], [".Main"])
        self.assertTrue(manifest.is_launcher(comps[0]))
        self.assertTrue(manifest.is_placeholder("${flag}"))
        self.assertFalse(manifest.is_placeholder("true"))
        self.assertIsNone(manifest.parse("<resources/>"))


class AndroidCalibration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _run(self, rule_id, app_type):
        project = Project(root=self.tmp, platforms=["android"], files=safety.walk(self.tmp))
        rules = [r for r in engine.load_rules() if r.id == rule_id]
        return engine.calibrate(engine.run(project, rules), profile.make(app_type, "flag"))

    def test_pinning_only_needed_for_high_risk_apps(self):
        self._write("app/src/main/AndroidManifest.xml",
                    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                    '<uses-permission android:name="android.permission.INTERNET"/><application/></manifest>')
        bank = self._run("AND-007", "banking")
        news = self._run("AND-007", "content")
        self.assertEqual(bank[0].bucket, "fix-soon")
        self.assertEqual(news[0].bucket, "not-needed")
        self.assertIn("§8.8", news[0].bucket_reason)

    def test_user_ca_in_debug_source_set_is_downgraded(self):
        self._write("app/src/debug/res/xml/network_security_config.xml",
                    '<network-security-config><base-config><trust-anchors><certificates src="user"/>'
                    '</trust-anchors></base-config></network-security-config>')
        found = self._run("AND-003", "general")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].scope, "debug")
        self.assertEqual(found[0].effective_severity, "low")

    def test_only_and002_is_safe_fix(self):
        safe = [r.id for r in engine.load_rules() if r.safe_fix]
        self.assertEqual(safe, ["AND-002"])
        self.assertEqual(next(r for r in engine.load_rules() if r.id == "AND-002").title,
                         "Release build is debuggable")


if __name__ == "__main__":
    unittest.main()
