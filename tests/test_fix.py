# SPDX-License-Identifier: Apache-2.0
"""--fix-safe: the AND-002 debuggable fix is minimal, idempotent, and keeps CRLF."""

import os
import shutil
import subprocess
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import cli, fix
from masaudit.model import Finding, Location, Rule
from masaudit.parsers import xmlsafe

MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
    "    <!-- android:debuggable=\"true\" kept in this comment -->\n"
    "    <application\n"
    '        android:label="Demo"\n'
    '        android:debuggable="true"\n'
    '        android:allowBackup="false">\n'
    '        <activity android:name=".Main" />\n'
    "    </application>\n"
    "</manifest>\n"
)

def _read(path, mode="r", **kw):
    with open(path, mode, **kw) as fh:
        return fh.read()


def _write(path, data, **kw):
    with open(path, "w", **kw) as fh:
        fh.write(data)



def rule(**kw):
    base = dict(id="AND-002", title="Release build is debuggable", platform="android", severity="high",
                profiles=["L1"], why="w", fix="f", verify="v", effort="minutes", book="§1.1",
                book_url="https://example.invalid", safe_fix=True, detector="android_debuggable")
    base.update(kw)
    return Rule(**base)


def finding(path, line=6, r=None, status="open"):
    return Finding(rule=r or rule(), location=Location(path=path, line=line), status=status)


class RemoveDebuggable(unittest.TestCase):
    def test_own_line_removed(self):
        out = fix.remove_debuggable(MANIFEST)
        self.assertNotIn('android:debuggable="true"\n', out)
        self.assertIn("kept in this comment", out)
        self.assertEqual(out, MANIFEST.replace('        android:debuggable="true"\n', ""))
        self.assertIsNotNone(xmlsafe.parse(out))

    def test_idempotent(self):
        once = fix.remove_debuggable(MANIFEST)
        self.assertEqual(fix.remove_debuggable(once), once)

    def test_crlf_preserved(self):
        crlf = MANIFEST.replace("\n", "\r\n")
        out = fix.remove_debuggable(crlf)
        self.assertEqual(out, crlf.replace('        android:debuggable="true"\r\n', ""))
        self.assertNotIn("\n", out.replace("\r\n", ""))

    def test_inline_with_other_attributes(self):
        text = "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n" \
               "\t<application android:debuggable='true' android:label=\"x\">\n</application>\n</manifest>"
        out = fix.remove_debuggable(text)
        self.assertIn("\t<application android:label=\"x\">\n", out)
        self.assertTrue(out.endswith("</manifest>"))

    def test_attribute_before_closing_bracket(self):
        text = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">\r\n'
                '    <application\r\n        android:label="x"\r\n        android:debuggable="true" />\r\n</manifest>\r\n')
        out = fix.remove_debuggable(text)
        self.assertIn('android:label="x" />\r\n</manifest>', out)
        self.assertIsNotNone(xmlsafe.parse(out))

    def test_attribute_first_on_line_followed_by_others(self):
        text = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <application\n        android:debuggable="true" android:label="x">\n    </application>\n</manifest>\n')
        out = fix.remove_debuggable(text)
        self.assertIn('\n        android:label="x">\n', out)

    def test_false_and_other_elements_untouched(self):
        text = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <application android:debuggable="false">\n'
                '        <meta-data android:debuggable="true" />\n    </application>\n</manifest>\n')
        self.assertEqual(fix.remove_debuggable(text), text)


class Plan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.main = "app/src/main/AndroidManifest.xml"
        self.debug = "app/src/debug/AndroidManifest.xml"
        for rel in (self.main, self.debug):
            os.makedirs(os.path.dirname(os.path.join(self.root, rel)), exist_ok=True)
            with open(os.path.join(self.root, rel), "w", encoding="utf-8", newline="") as fh:
                fh.write(MANIFEST.replace("\n", "\r\n"))
        with open(os.path.join(self.root, "app/build.gradle"), "w") as fh:
            fh.write("android { buildTypes { release { debuggable true } } }\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_fixes_main_only_and_suggests_gradle(self):
        findings = [finding(self.main), finding(self.debug), finding("app/build.gradle", 1)]
        plan = fix.plan(self.root, findings)
        self.assertEqual([f.path for f in plan.fixes], [self.main])
        self.assertEqual(len(plan.suggestions), 1)
        self.assertIn("build.gradle", plan.suggestions[0])
        self.assertTrue(any("debug" in s for s in plan.skipped))
        diff = fix.unified_diff(plan.fixes)
        self.assertIn(f"--- a/{self.main}", diff)
        self.assertIn('-        android:debuggable="true"\r\n', diff)

    def test_apply_preserves_bytes_and_is_idempotent(self):
        before = _read(os.path.join(self.root, self.main), "rb")
        plan = fix.plan(self.root, [finding(self.main)])
        self.assertEqual(fix.apply(self.root, plan.fixes), [self.main])
        after = _read(os.path.join(self.root, self.main), "rb")
        self.assertEqual(after, before.replace(b'        android:debuggable="true"\r\n', b""))
        self.assertEqual(fix.plan(self.root, [finding(self.main)]).fixes, [])
        # Gradle is never touched.
        self.assertIn("debuggable true", _read(os.path.join(self.root, "app/build.gradle")))

    def test_rules_without_safe_fix_or_suppressed_are_ignored(self):
        self.assertEqual(fix.plan(self.root, [finding(self.main, r=rule(safe_fix=False))]).fixes, [])
        self.assertEqual(fix.plan(self.root, [finding(self.main, r=rule(id="AND-001"))]).fixes, [])
        self.assertEqual(fix.plan(self.root, [finding(self.main, status="suppressed")]).fixes, [])

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_yes_needs_a_clean_git_tree(self):
        self.assertIsNotNone(cli._git_clean(self.root))      # not a repository
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        run = lambda *a: subprocess.run(["git", *a], cwd=self.root, env=env, capture_output=True, check=True)
        run("init", "-q")
        self.assertIsNotNone(cli._git_clean(self.root))      # untracked files
        run("add", "-A")
        run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
        self.assertIsNone(cli._git_clean(self.root))
        with open(os.path.join(self.root, self.main), "a") as fh:
            fh.write("<!-- edit -->")
        self.assertIsNotNone(cli._git_clean(self.root))


if __name__ == "__main__":
    unittest.main()
