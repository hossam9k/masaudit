# SPDX-License-Identifier: Apache-2.0
"""Regression tests for attacks found by the independent security review (2026-10-23)."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import cli, detect, engine, profile, safety
from masaudit.model import Project
from masaudit.parsers import workflows


class AttackRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mask_is_fast_on_huge_crafted_lines(self):
        # A long digit-free run used to backtrack quadratically.
        for crafted in ("a" * 2_000_000, '"' + "Ab+/" * 500_000, "x1" * 1_000_000):
            start = time.monotonic()
            out = safety.mask(crafted)
            self.assertLess(time.monotonic() - start, 1.0)
            self.assertLessEqual(len(out), 160)

    def test_mask_still_hides_secrets_and_keeps_identifiers(self):
        self.assertIn("[masked]", safety.mask('key = "AKIAIOSFODNN7EXAMPLE"'))
        self.assertIn("[masked]", safety.mask("token=a8F3kd92LmQ0xZ7vP4tR1sW6yB5nC8eD"))
        self.assertEqual(safety.mask("NSAllowsArbitraryLoadsInWebContent"), "NSAllowsArbitraryLoadsInWebContent")

    def test_mask_strips_terminal_control_characters(self):
        self.assertNotIn("\x1b", safety.mask("evil \x1b[31mred\x1b[0m"))

    @unittest.skipIf(sys.platform == "win32", "hard links need extra privileges on some Windows setups")
    def test_hard_links_are_not_read(self):
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.kt")
            with open(secret, "w") as fh:
                fh.write('val k = "AKIAIOSFODNN7EXAMPLE"\n')
            os.link(secret, os.path.join(self.tmp, "Linked.kt"))
            self.assertNotIn("Linked.kt", safety.walk(self.tmp))
            self.assertIsNone(safety.read_text(self.tmp, "Linked.kt"))
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_doctype_anywhere_is_refused(self):
        text = "<?xml version='1.0'?>" + " " * 5000 + "<!DOCTYPE x [<!ELEMENT x ANY>]><x/>"
        self.assertTrue(safety.reject_xml_entities(text))

    @unittest.skipIf(sys.platform == "win32", "newlines aren't allowed in Windows file names")
    def test_file_names_with_control_characters_are_skipped(self):
        name = "Evil\n## Fix before release\n.kt"
        with open(os.path.join(self.tmp, name), "w") as fh:
            fh.write("class A\n")
        self.assertEqual([f for f in safety.walk(self.tmp) if "Evil" in f], [])

    @unittest.skipUnless(shutil.which("git") and sys.platform != "win32", "needs git and a POSIX shell")
    def test_git_status_does_not_run_repo_hooks(self):
        git = shutil.which("git")
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run([git, "init", "-q"], cwd=self.tmp, check=True, env=env)
        hooks = os.path.join(self.tmp, "myhooks")
        os.makedirs(hooks)
        marker = os.path.join(self.tmp, "PWNED")
        for hook in ("post-index-change", "pre-commit", "post-checkout"):
            path = os.path.join(hooks, hook)
            with open(path, "w") as fh:
                fh.write(f"#!/bin/sh\ntouch '{marker}'\n")
            os.chmod(path, 0o700)
        subprocess.run([git, "config", "core.hooksPath", hooks], cwd=self.tmp, check=True, env=env)
        with open(os.path.join(self.tmp, "a.txt"), "w") as fh:
            fh.write("x")
        subprocess.run([git, "add", "a.txt"], cwd=self.tmp, check=True, env={**env, "GIT_OPTIONAL_LOCKS": "0"},
                       capture_output=True)
        if os.path.exists(marker):
            os.remove(marker)   # `git add` above legitimately ran the hook; only masaudit's call matters
        cli._git_clean(self.tmp)
        self.assertFalse(os.path.exists(marker), "git status ran a hook from the scanned repo")

    @unittest.skipUnless(shutil.which("git") and sys.platform != "win32", "needs git and a POSIX shell")
    def test_git_status_does_not_run_repo_filters(self):
        # A folder that ships its own .git/config could run a clean filter on `git status`.
        git = shutil.which("git")
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}
        subprocess.run([git, "init", "-q"], cwd=self.tmp, check=True, env=env)
        marker = os.path.join(self.tmp, "PWNED")
        subprocess.run([git, "config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'"],
                       cwd=self.tmp, check=True, env=env)
        with open(os.path.join(self.tmp, ".gitattributes"), "w") as fh:
            fh.write("* filter=evil\n")
        reason = cli._git_clean(self.tmp)
        self.assertIn("filter.evil.clean", reason or "")
        self.assertFalse(os.path.exists(marker), "git status ran a filter from the scanned repo")

    def test_huge_and_unicode_numbers_do_not_crash_the_scan(self):
        # Python 3.11+ refuses to turn more than 4,300 digits into an int, and int() rejects digits like "²"
        # that str.isdigit() accepts. Either one in a crafted file used to end the scan with an internal error.
        for n in ("9" * 5000, "\u00b2"):
            files = {
                "app/build.gradle.kts": f"android {{ defaultConfig {{ minSdk = {n}\n targetSdk = {n} }} }}\n",
                "app/src/main/AndroidManifest.xml":
                    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                    f'<uses-sdk android:minSdkVersion="{n}" android:targetSdkVersion="{n}"/>'
                    f'<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" '
                    f'android:maxSdkVersion="{n}"/><application/></manifest>\n',
                "gradle/libs.versions.toml": f'[versions]\nminSdk = "{n}"\n',
                "app/src/main/K.kt": f"class K {{ fun f() {{ b.setUserAuthenticationValidityDurationSeconds({n}); "
                                     f"b.setUserAuthenticationParameters({n}, 2); g.initialize({n}) }} }}\n",
                "pubspec.lock": f'packages:\n  dio:\n    version: "{n}.{n}.{n}"\n',
                "ios/App/Model{n}.xcdatamodel/contents": "<model/>\n",
            }
            root = os.path.join(self.tmp, "n%d" % len(n))
            for rel, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
                with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                    fh.write(text)
            with self.subTest(digits=len(n)):
                cli.scan(root, cli_type="banking", cfg={}, allow_prompt=False)      # must not raise

    def test_stray_closer_in_flow_yaml_does_not_hang(self):
        # Found by fuzzing: a `}` inside `[...]` made the flow parser loop forever.
        for crafted in ("x: [}]", "x: [a, }, b]", "x: {a: ]}", "x: [[}}]]", "on: [" + "}" * 10_000 + "]"):
            start = time.monotonic()
            workflows.load(crafted)
            self.assertLess(time.monotonic() - start, 2.0, crafted[:20])


    def test_unclosed_flow_collection_in_a_large_workflow_is_fast(self):
        # Found by the fuzz test on a slow CI runner: an unclosed `{` made the parser rescan the
        # growing text for every following line, which was quadratic in the file size.
        crafted = "jobs: {\n" + "x: \n" * 200_000
        start = time.monotonic()
        workflows.load(crafted)
        self.assertLess(time.monotonic() - start, 2.0)

    def test_thousands_of_hits_in_one_file_scan_in_linear_time(self):
        # Found by the performance review (2026-10-24): per hit, rules re-split the file for the snippet,
        # recounted lines from the top, walked back to the enclosing function or #if, re-searched the whole
        # file or statement, or (AND-015's superclass regex) rescanned to the next brace from every `(`; the
        # Gradle helpers rescanned the rest of the script for every nested block. Each crafted 200 KB file
        # took 5 s to 4 minutes before the fix, and the build scripts far longer (8 KB took 4 s, growing
        # with the cube of the size).
        manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
                    '<application><activity android:name=".Main" android:exported="true"><intent-filter>'
                    '<action android:name="android.intent.action.MAIN"/></intent-filter></activity>'
                    '</application></manifest>')
        cases = [  # (rule, file, repeated text, reports something)
            ("XPL-010", "A.kt", 'if (BuildConfig.DEBUG) {\nLog.d(TAG, "$token")\n', True),   # debug guard, snippet
            ("XPL-010", "A.swift", '#if DEBUG\nprint("\\(token)")\n', True),                 # #if stack per hit
            ("XPL-008", "A.kt", "val token = Math.random()\n", True),                       # enclosing function
            ("XPL-042", "A.kt", 'Runtime.getRuntime().exec("sh -c " + cmd)\n', True),       # constant lookup
            ("AND-009", "A.kt", "if (BuildConfig.DEBUG) {\nval c = CertificatePinner\n", True),  # unclosed blocks
            ("IOS-004", "A.swift", "func urlSession(_ s: URLSession, didReceive challenge: "
                                   "URLAuthenticationChallenge) {\n", False),              # brace matching
            ("AND-015", "A.kt", "class A (\n", False),                                       # superclass regex
            ("AND-034", "A.kt", '\n.putString("token", t)', False),                          # one long chain
            ("AND-054", "A.kt", 'val i = Intent(); i.putExtra("token", token); startActivity(i)\n', False),
            ("XPL-032", "A.kt", 'NotificationCompat.Builder(c).setContentText("code $otp")\n', True),
            ("AND-027", "build.gradle", "buildTypes { release { minifyEnabled false\n", True),  # nested blocks
            ("AND-002", "build.gradle", "android { buildTypes { release { debuggable true\n", True),
            ("AND-064", "build.gradle", "signingConfigs { c { enableV2Signing false\n", True),
        ]
        all_rules = {r.id: r for r in engine.load_rules()}
        for rule_id, name, unit, reports in cases:
            with self.subTest(rule=rule_id, file=name):
                root = tempfile.mkdtemp(dir=self.tmp)
                os.makedirs(os.path.join(root, "app/src/main/java"))
                with open(os.path.join(root, "app/src/main/AndroidManifest.xml"), "w") as fh:
                    fh.write(manifest)
                where = "app" if name.endswith(".gradle") else "app/src/main/java"
                with open(os.path.join(root, where, name), "w") as fh:
                    fh.write(unit * (200_000 // len(unit)))
                files = safety.walk(root)
                project = Project(root=root, platforms=detect.platforms(files, root), files=files)
                start = time.monotonic()
                findings = engine.run(project, [all_rules[rule_id]], profile.make("banking", "flag"))
                self.assertLess(time.monotonic() - start, 3.0)
                self.assertEqual(bool(findings), reports)


class FuzzSmoke(unittest.TestCase):
    def test_parsers_survive_mutated_fixtures(self):
        # A short run of fuzz/fuzz_parsers.py on every CI job; the long run uses atheris.
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fuzz"))
        import fuzz_parsers

        cwd = os.getcwd()
        tmp = tempfile.mkdtemp()
        try:
            os.chdir(tmp)              # a crashing input is saved to the working directory
            self.assertEqual(fuzz_parsers.smoke(1500, seed=7, quiet=True), 0)
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
