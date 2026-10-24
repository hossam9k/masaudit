# SPDX-License-Identifier: Apache-2.0
"""Android project model: Gradle variants and scope, Lint acknowledgements, keep-rule parsing, anchors."""

import os
import shutil
import tempfile
import unittest

from helpers import ALL_PLATFORMS  # noqa: F401  (sets sys.path)
from masaudit import engine, lexer, profile, safety
from masaudit.detectors import android
from masaudit.model import Project
from masaudit.parsers import gradle, proguard, xmlsafe

SIGNAL_LIKE = '''
plugins { id("com.android.application") }
android {
  buildTypes {
    getByName("debug") { isMinifyEnabled = false }
    getByName("release") { isMinifyEnabled = true }
    create("canary") { initWith(getByName("debug")); matchingFallbacks += "debug" }
    create("perf") { initWith(getByName("debug")); isDebuggable = false; matchingFallbacks += "debug" }
    create("beta") { initWith(getByName("release")); matchingFallbacks += listOf("release") }
  }
  flavorDimensions += listOf("distribution", "environment")
  productFlavors {
    create("play") { dimension = "distribution" }
    create("nightly") { dimension = "distribution" }
    create("prod") { dimension = "environment" }
    create("staging") { dimension = "environment" }
    create("internal") { dimension = "distribution" }
  }
}
dependencies {
  implementation(project(":core"))
  internalImplementation(project(":sync-internal"))
  playImplementation(project(":storage-impl"))
  internalImplementation(project(":storage-impl"))
  debugImplementation(libs.leakcanary)
}
'''


def _strip(code, lang="kotlin"):
    return lexer.strip(code, lang, True), lexer.strip(code, lang, False)


class GradleVariants(unittest.TestCase):
    def test_build_types_and_flavors(self):
        code, blank = _strip(SIGNAL_LIKE)
        types = gradle.build_types(code, blank)
        self.assertEqual(sorted(types), ["beta", "canary", "debug", "perf", "release"])
        self.assertEqual(types["canary"].init_from, "debug")
        self.assertIs(types["perf"].debuggable, False)
        self.assertEqual(types["beta"].fallbacks, ["release"])
        self.assertEqual(gradle.product_flavors(code, blank), ["play", "nightly", "prod", "staging", "internal"])

    def test_dependencies(self):
        code, _blank = _strip(SIGNAL_LIKE)
        deps = gradle.dependencies(code)
        by_variant = {(d.variant, tuple(d.projects), tuple(d.aliases)) for d in deps}
        self.assertIn(("", (":core",), ()), by_variant)
        self.assertIn(("internal", (":sync-internal",), ()), by_variant)
        self.assertIn(("debug", (), ("leakcanary",)), by_variant)

    def test_toml_libraries(self):
        toml = ('[libraries]\nchucker = { module = "com.github.chuckerteam.chucker:library", version.ref = "c" }\n'
                'leak-canary = "com.squareup.leakcanary:leakcanary-android:2.14"\n'
                'tink = { group = "com.google.crypto.tink", name = "tink-android", version = "1.13" }\n')
        libs = gradle.toml_libraries(toml)
        self.assertEqual(libs["chucker"][0], "com.github.chuckerteam.chucker:library")
        self.assertEqual(libs["leak-canary"], ("com.squareup.leakcanary:leakcanary-android", 3))
        self.assertEqual(libs["tink"][0], "com.google.crypto.tink:tink-android")
        self.assertEqual(gradle.alias_key("leak-canary"), "leak.canary")


class ScopeFromVariants(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._write("app/build.gradle.kts", SIGNAL_LIKE)
        for module in ("core", "sync/sync-internal", "storage/storage-impl"):
            self._write(f"{module}/build.gradle.kts", 'plugins { id("com.android.library") }\n')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_scope(self):
        project = Project(root=self.tmp, platforms=["android"], files=safety.walk(self.tmp))
        ctx = engine.Context(project)
        expected = {
            "app/src/main/AndroidManifest.xml": "main",
            "app/src/play/AndroidManifest.xml": "main",
            "app/src/beta/res/xml/network_security_config.xml": "main",
            "app/src/canary/AndroidManifest.xml": "debug",
            "app/src/perf/AndroidManifest.xml": "debug",
            "app/src/nightlyStaging/AndroidManifest.xml": "debug",
            "app/src/internal/AndroidManifest.xml": "debug",
            "app/src/playDebug/AndroidManifest.xml": "debug",
            "app/src/standardDebug/AndroidManifest.xml": "debug",
            "sync/sync-internal/src/main/AndroidManifest.xml": "debug",
            "storage/storage-impl/src/main/AndroidManifest.xml": "main",
            "core/src/main/AndroidManifest.xml": "main",
            "app/src/main/res/xml/network_security_config_debug.xml": "debug",
            "components/ui/playground/src/main/AndroidManifest.xml": "debug",
            "app/src/test/java/A.kt": "test",
        }
        for path, scope in expected.items():
            with self.subTest(path=path):
                self.assertEqual(android._scope(ctx, path), scope)


class LintAcknowledgements(unittest.TestCase):
    def test_inherited_ignore_and_reason(self):
        root = xmlsafe.parse(
            '<network-security-config xmlns:tools="http://schemas.android.com/tools"\n'
            '    tools:ignore="InsecureBaseConfiguration,AcceptsUserCertificates">\n'
            '  <base-config cleartextTrafficPermitted="true">\n'
            '    <trust-anchors>\n'
            '      <!-- We allow user certificates so managed devices work -->\n'
            '      <certificates src="user" />\n'
            '    </trust-anchors>\n'
            '  </base-config>\n'
            '</network-security-config>\n')
        cert = root.find("certificates")
        self.assertIs(xmlsafe.lint_ignored(cert, "AcceptsUserCertificates"), root)
        self.assertIsNone(xmlsafe.lint_ignored(cert, "ExportedService"))
        self.assertEqual(xmlsafe.ack_text(cert, "AcceptsUserCertificates"),
                         "tools:ignore=AcceptsUserCertificates — We allow user certificates so managed devices work")

    def test_trailing_comment(self):
        root = xmlsafe.parse(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            '    xmlns:tools="http://schemas.android.com/tools"><application>\n'
            '  <receiver android:name=".Feed"\n'
            '      android:exported="true"\n'
            '      tools:ignore="ExportedReceiver" /> <!-- allow feed updates from other apps -->\n'
            '  <service android:name=".Other" />\n'
            '</application></manifest>\n')
        receiver = root.find("receiver")
        self.assertEqual(xmlsafe.ack_text(receiver, "ExportedReceiver"),
                         "tools:ignore=ExportedReceiver — allow feed updates from other apps")
        self.assertEqual(xmlsafe.comment_near(root.find("service")), "")


class KeepRules(unittest.TestCase):
    def test_parse(self):
        opts = proguard.parse("# comment\n-dontobfuscate\n-keep class com.x.** {\n  *;\n}\n-keepnames,allowshrinking"
                              " class * # trailing\n")
        self.assertEqual([(o.line, o.name) for o in opts], [(2, "dontobfuscate"), (3, "keep"), (6, "keepnames")])
        self.assertEqual(proguard.class_pattern(opts[1].spec), "com.x.**")
        self.assertEqual(opts[1].spec, "class com.x.** { *; }")


class Findings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _run(self, rule_id, app_type="banking"):
        project = Project(root=self.tmp, platforms=["android"], files=safety.walk(self.tmp))
        rules = [r for r in engine.load_rules() if r.id == rule_id]
        return engine.calibrate(engine.run(project, rules), profile.make(app_type, "flag"))

    def test_pinning_anchors_on_main_manifest(self):
        base = os.path.join(os.path.dirname(__file__), "fixtures", "AND-007", "vulnerable_flavor_first")
        shutil.rmtree(self.tmp)
        shutil.copytree(base, self.tmp)
        found = self._run("AND-007")
        self.assertEqual([f.location.path for f in found], ["app/src/main/AndroidManifest.xml"])

    def test_acknowledged_finding_is_lowered_not_dropped(self):
        base = os.path.join(os.path.dirname(__file__), "fixtures", "AND-003", "vulnerable_acknowledged")
        shutil.rmtree(self.tmp)
        shutil.copytree(base, self.tmp)
        found = self._run("AND-003", "general")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].acknowledged.startswith("tools:ignore=AcceptsUserCertificates — Managed"))
        self.assertEqual(found[0].effective_severity, "medium")

    def test_debug_network_config_file_is_debug_scope(self):
        base = os.path.join(os.path.dirname(__file__), "fixtures", "AND-003", "vulnerable_debug_file")
        shutil.rmtree(self.tmp)
        shutil.copytree(base, self.tmp)
        found = self._run("AND-003", "general")
        self.assertEqual([(f.location.path.rsplit("/", 1)[-1], f.scope) for f in found],
                         [("network_security_config_debug.xml", "debug")])

    def test_permission_inventory_merges_modules(self):
        base = os.path.join(os.path.dirname(__file__), "fixtures", "AND-033", "vulnerable_modules")
        shutil.rmtree(self.tmp)
        shutil.copytree(base, self.tmp)
        found = self._run("AND-033")
        self.assertEqual(len(found), 1)
        self.assertIn("CAMERA (app, lib/qr)", found[0].message)
        self.assertEqual(found[0].bucket, "notes")

    def test_exported_component_reasons(self):
        base = os.path.join(os.path.dirname(__file__), "fixtures", "AND-015", "vulnerable_private_surfaces")
        shutil.rmtree(self.tmp)
        shutil.copytree(base, self.tmp)
        found = {f.location.line: f for f in self._run("AND-015")}
        messages = " | ".join(f.message for f in found.values())
        self.assertIn("no intent filter", messages)
        self.assertIn("com.example.intents.OPEN_FEED next to its public intent filters", messages)
        self.assertNotIn("QUICKBOOT_POWERON", messages)     # a vendor boot broadcast, not app-specific
        self.assertIn("private scheme k9mail:", messages)
        self.assertIn("BROADCAST_SMS", messages)
        # A custom action next to public filters is medium; no filter, a private scheme or a provider stays high.
        self.assertEqual({line: f.effective_severity for line, f in found.items()},
                         {6: "high", 7: "medium", 18: "medium", 27: "high", 34: "high", 35: "high", 36: "medium",
                          38: "high"})
        acked = [f for f in found.values() if f.acknowledged]
        self.assertEqual([f.acknowledged for f in acked], ["tools:ignore=ExportedContentProvider"])


if __name__ == "__main__":
    unittest.main()
