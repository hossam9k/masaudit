# SPDX-License-Identifier: Apache-2.0
"""Android project model: Gradle variants and scope, Lint acknowledgements, keep-rule parsing, anchors."""

import os
import shutil
import tempfile
import unittest

import helpers

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


class ShipGraph(unittest.TestCase):
    """Which Gradle modules ship: reached from the product app through release dependencies."""

    FILES = {
        "settings.gradle.kts": 'include(":app", ":core", ":core-test", ":feature:home", ":feature:home-demo")\n',
        "app/build.gradle.kts": (
            'plugins { id("com.android.application") }\n'
            'android { productFlavors { create("qa") {}; create("standard") {} } }\n'
            "dependencies {\n"
            "  implementation(projects.core)\n"
            '  implementation(project(":feature:home"))\n'
            "  qaImplementation(projects.shared.qa)\n"
            '  testImplementation(project(":common-test"))\n'
            '  debugImplementation(project(":debug-menu"))\n'
            '  implementation(project(":looped"))\n'
            "}\n"),
        "core/build.gradle.kts": (
            'plugins { kotlin("multiplatform"); id("com.android.library") }\n'
            "kotlin {\n  sourceSets {\n    commonTest.dependencies { implementation(projects.coreTest) }\n"
            '    val androidUnitTest by getting { dependencies { implementation(project(":fixtures-lib")) } }\n'
            "  }\n}\n"),
        "core-test/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "fixtures-lib/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "feature/home/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "feature/home-demo/build.gradle.kts": (
            'plugins { id("com.android.application") }\n'
            'dependencies { implementation(project(":feature:home")); implementation(project(":demo-only")) }\n'),
        "demo-only/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "autofill/e2e-app/build.gradle.kts": 'plugins { id("com.android.application") }\n',
        "shared/qa/build.gradle.kts": ('plugins { kotlin("multiplatform") }\n'
                                       "kotlin { iosArm64 { binaries.framework { } } }\n"),
        "common-test/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "debug-menu/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "unused/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "looped/build.gradle.kts": 'plugins { id("com.android.library") }\n',
        "build-logic/convention/build.gradle.kts": "plugins { `kotlin-dsl` }\n",
        "build.gradle.kts": "plugins { alias(libs.plugins.android.application) apply false }\n",
    }

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for rel, text in self.FILES.items():
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _ctx(self, platforms=("android", "ios", "kmp")):
        project = Project(root=self.tmp, platforms=list(platforms), files=safety.walk(self.tmp))
        return engine.Context(project)

    def test_scopes(self):
        ctx = self._ctx()
        expected = {
            "app": None, "core": None, "feature/home": None, "looped": None, "build-logic/convention": None,
            "core-test": "test", "fixtures-lib": "test", "common-test": "test",
            "debug-menu": "debug", "shared/qa": "debug",
            "feature/home-demo": "unshipped", "demo-only": "unshipped", "autofill/e2e-app": "unshipped",
            "unused": "unshipped",
        }
        scopes = android._module_scopes(ctx)
        for module, scope in expected.items():
            with self.subTest(module=module):
                self.assertEqual(scopes.get(module), scope)
        self.assertEqual(engine._shipped(ctx, "feature/home-demo/src/main/java/A.kt", "main"), "unshipped")
        self.assertEqual(engine._shipped(ctx, "unused/build.gradle.kts", "build-script"), "unshipped")
        self.assertEqual(engine._shipped(ctx, "core/src/commonMain/kotlin/A.kt", "main"), "main")
        self.assertEqual(engine._shipped(ctx, "unused/src/test/A.kt", "test"), "test")

    def test_dynamic_wiring_decides_only_demo_apps(self):
        self._write_text("app/build.gradle.kts", self.FILES["app/build.gradle.kts"]
                         + 'listOf("auth", "home").forEach { dependencies { implementation(project(":feature:$it")) } }\n')
        scopes = android._module_scopes(self._ctx())
        self.assertEqual(scopes.get("feature/home-demo"), "unshipped")
        self.assertEqual(scopes.get("autofill/e2e-app"), "unshipped")
        self.assertEqual(scopes.get("debug-menu"), "debug")         # what 0.6.5 already decided
        self.assertEqual(scopes.get("common-test"), "test")         # named as test code, wired in only by tests
        for module in ("unused", "demo-only"):
            with self.subTest(module=module):
                self.assertNotIn(module, scopes)

    def test_no_product_app_decides_nothing(self):
        for rel in ("app/build.gradle.kts",):
            os.remove(os.path.join(self.tmp, rel))
        self.assertEqual(android._module_scopes(self._ctx(platforms=("android",))), {})

    def test_calibration_reason(self):
        r = engine.load_rules()
        rule = next(x for x in r if x.id == "AND-021")
        from masaudit.model import Finding, Location
        f = Finding(rule=rule, location=Location("feature/home-demo/src/main/AndroidManifest.xml", 3), scope="unshipped")
        engine.calibrate([f], profile.make("banking", "flag"))
        self.assertEqual(f.bucket, "notes")
        self.assertIn("no mobile app module that ships", f.bucket_reason)

    def test_build_type_named_by_a_constant(self):
        self._write_text("app/build.gradle.kts",
                         'plugins { id("com.android.application") }\n'
                         "android { buildTypes { create(BuildTypes.LEAK_CANARY) { initWith(buildTypes.getByName(\"debug\")) } } }\n"
                         "dependencies { leakCanaryImplementation(libs.leakCanary) }\n")
        self._write_text("build-logic/src/main/kotlin/BuildTypes.kt",
                         'object BuildTypes { const val LEAK_CANARY = "leakCanary" }\n')
        ctx = self._ctx(platforms=("android",))
        self.assertEqual(android._variant_kind(ctx, "app", "leakCanary"), "debug")

    def test_what_else_ships(self):
        # An app applied through a convention plugin, wired to a module from an included build's convention code.
        self._write_text("app/build.gradle.kts", 'plugins { id("acme.android.application") }\n')
        self._write_text("build-logic/settings.gradle.kts", "")
        self._write_text("build-logic/convention/src/main/kotlin/acme.android.application.gradle.kts",
                         'plugins { id("com.android.application") }\n'
                         'dependencies { "implementation"(project(":wakeword")) }\n')
        self._write_text("wakeword/build.gradle.kts", 'plugins { id("com.android.library") }\n')
        # A React Native package's native module, linked by autolinking, not Gradle.
        self._write_text("packages/rn-alarm/package.json", "{}")
        self._write_text("packages/rn-alarm/android/build.gradle", "apply plugin: 'com.android.library'\n")
        # An Xcode project kept in a Kotlin Multiplatform module folder.
        self._write_text("unused/Demo.xcodeproj/project.pbxproj", "// !$*UTF8*$!\n")
        ctx = self._ctx()
        scopes = android._module_scopes(ctx)
        self.assertNotIn("app", scopes)
        self.assertNotIn("wakeword", scopes)
        self.assertNotIn("packages/rn-alarm/android", scopes)
        self.assertEqual(scopes.get("feature/home-demo"), "unshipped")
        self.assertEqual(engine._shipped(ctx, "unused/Demo.xcodeproj/project.pbxproj", "main"), "main")
        self.assertEqual(engine._shipped(ctx, "unused/src/main/AndroidManifest.xml", "main"), "unshipped")

    def test_application_id_makes_an_app(self):
        self._write_text("app/build.gradle.kts", 'plugins { id("acme.app") }\nandroid { defaultConfig { applicationId = "com.acme" } }\n'
                         "dependencies { implementation(projects.core) }\n")
        scopes = android._module_scopes(self._ctx())
        self.assertNotIn("core", scopes)
        self.assertEqual(scopes.get("feature/home"), "unshipped")

    def test_test_client_app_in_an_integration_folder(self):
        self._write_text("integration/wearCredentialProviderApp/build.gradle.kts", 'plugins { id("com.android.application") }\n')
        self.assertEqual(android._module_scopes(self._ctx()).get("integration/wearCredentialProviderApp"), "unshipped")

    def test_backup_turned_off_by_a_shipped_library(self):
        def scan():
            files = safety.walk(self.tmp)
            return [f for f in engine.run(Project(root=self.tmp, platforms=["android"], files=files),
                                          [r for r in engine.load_rules() if r.id == "AND-021"])
                    if f.location.path == "app/src/main/AndroidManifest.xml"]
        app = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>\n')
        lib = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
               '<application android:allowBackup="false"/></manifest>\n')
        self._write_text("app/src/main/AndroidManifest.xml", app)
        self.assertEqual(len(scan()), 1)
        self._write_text("unused/src/main/AndroidManifest.xml", lib)       # a library the app doesn't use
        self.assertEqual(len(scan()), 1)
        self._write_text("core/src/androidMain/AndroidManifest.xml", lib)  # one it ships with
        self.assertEqual(scan(), [])

    def _write_text(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


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


class ExportedActivityThatReadsNothing(unittest.TestCase):
    def test_keeps_its_severity(self):
        # DIVA's APICredsActivity and InsecureBankv2's DoTransfer read nothing from their intent, yet starting
        # them shows credentials or moves money: an exported screen is not safe just because it takes no input.
        hits = helpers.scan_dir(os.path.join(helpers.FIXTURES, "AND-015", "vulnerable_reads_no_intent"), {"AND-015"})
        self.assertEqual([h.severity for h in hits], [""])


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
