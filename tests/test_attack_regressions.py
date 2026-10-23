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
from masaudit import cli, safety


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
            os.chmod(path, 0o755)
        subprocess.run([git, "config", "core.hooksPath", hooks], cwd=self.tmp, check=True, env=env)
        with open(os.path.join(self.tmp, "a.txt"), "w") as fh:
            fh.write("x")
        subprocess.run([git, "add", "a.txt"], cwd=self.tmp, check=True, env={**env, "GIT_OPTIONAL_LOCKS": "0"},
                       capture_output=True)
        if os.path.exists(marker):
            os.remove(marker)   # `git add` above legitimately ran the hook; only masaudit's call matters
        cli._git_clean(self.tmp)
        self.assertFalse(os.path.exists(marker), "git status ran a hook from the scanned repo")


if __name__ == "__main__":
    unittest.main()
