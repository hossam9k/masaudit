# SPDX-License-Identifier: Apache-2.0
"""Inline suppressions need a reason; the baseline round-trips."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import FIXTURES
from masaudit import cli, suppress
from masaudit.model import Finding, Location, Rule

VULN = os.path.join(FIXTURES, "AND-001", "vulnerable")
NSC = "app/src/main/res/xml/network_security_config.xml"

def _read(path, mode="r", **kw):
    with open(path, mode, **kw) as fh:
        return fh.read()


def _write(path, data, **kw):
    with open(path, "w", **kw) as fh:
        fh.write(data)



def rule(rid="AND-001"):
    return Rule(id=rid, title="t", platform="android", severity="high", profiles=["L1"], why="w",
                fix="f", verify="v", effort="minutes", book="§7.1", book_url="u", detector="x")


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Parse(unittest.TestCase):
    def test_comment_syntaxes(self):
        self.assertEqual(suppress.parse_line("// masaudit:ignore AND-001 legacy host"), [("AND-001", "legacy host")])
        self.assertEqual(suppress.parse_line("# masaudit:ignore CI-002 read-only job"), [("CI-002", "read-only job")])
        self.assertEqual(suppress.parse_line("<!-- masaudit:ignore AND-001 lab build only -->"),
                         [("AND-001", "lab build only")])
        self.assertEqual(suppress.parse_line("/* masaudit:ignore AND-001 */"), [("AND-001", "")])
        self.assertEqual(suppress.parse_line("<!-- masaudit:ignore AND-001 -->"), [("AND-001", "")])


class Inline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "p")
        shutil.copytree(VULN, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _prepend_comment(self, comment):
        path = os.path.join(self.root, NSC)
        lines = _read(path, encoding="utf-8").split("\n")
        lines.insert(2, comment)          # directly above <base-config> (now line 4)
        _write(path, "\n".join(lines), encoding="utf-8")

    def _scan(self):
        res = cli.scan(self.root, cli_type="banking", allow_prompt=False)
        return res, [f for f in res.findings if f.rule.id == "AND-001" and f.location.path == NSC]

    def test_with_reason_suppresses(self):
        self._prepend_comment("    <!-- masaudit:ignore AND-001 only used by the offline lab build -->")
        res, hits = self._scan()
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, "suppressed")
        self.assertEqual(hits[0].suppression_reason, "only used by the offline lab build")

    def test_without_reason_is_ignored_and_noted(self):
        self._prepend_comment("    <!-- masaudit:ignore AND-001 -->")
        res, hits = self._scan()
        self.assertEqual(hits[0].status, "open")
        self.assertTrue(any("reason is required" in n for n in res.notes))

    def test_other_rule_id_does_not_suppress(self):
        self._prepend_comment("    <!-- masaudit:ignore AND-999 not this one -->")
        _res, hits = self._scan()
        self.assertEqual(hits[0].status, "open")

    def test_same_line_and_unit(self):
        root = self.tmp.name
        with open(os.path.join(root, "A.kt"), "w") as fh:
            fh.write("x\nbad() // masaudit:ignore AND-001 reviewed in #42\n")
        f = Finding(rule=rule(), location=Location(path="A.kt", line=2))
        self.assertEqual(suppress.apply_inline([f], root), [])
        self.assertEqual(f.status, "suppressed")


class Baseline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip(self):
        path = os.path.join(self.tmp.name, "base.json")
        a = Finding(rule=rule(), location=Location(path="a.xml", line=1, snippet="<a/>"))
        b = Finding(rule=rule(), location=Location(path="b.xml", line=1, snippet="<b/>"), status="suppressed")
        self.assertEqual(suppress.write_baseline(path, [a, b]), 1)
        fps = suppress.load_baseline(path)
        self.assertEqual(fps, {a.fingerprint()})
        fresh = Finding(rule=rule(), location=Location(path="a.xml", line=9, snippet="<a/>"))
        self.assertEqual(suppress.apply_baseline([fresh], fps), 1)    # line moved, same fingerprint
        self.assertEqual(fresh.status, "baselined")

    def test_bad_baseline(self):
        path = os.path.join(self.tmp.name, "bad.json")
        _write(path, "[1, 2]")
        with self.assertRaises(suppress.BaselineError):
            suppress.load_baseline(path)
        with self.assertRaises(suppress.BaselineError):
            suppress.load_baseline(os.path.join(self.tmp.name, "missing.json"))

    def test_cli_round_trip(self):
        base = os.path.join(self.tmp.name, "masaudit-baseline.json")
        out = os.path.join(self.tmp.name, "r.json")
        code, _o, _e = run_cli(VULN, "--app-type", "banking", "--format", "json", "--output", out,
                               "--baseline", base, "--update-baseline", "--fail-on", "low")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(_read(base))["findings"])
        code, _o, _e = run_cli(VULN, "--app-type", "banking", "--format", "json", "--output", out,
                               "--baseline", base, "--fail-on", "low")
        self.assertEqual(code, 0)
        data = json.loads(_read(out))
        self.assertTrue(all(f["status"] in ("baselined", "suppressed") for f in data["findings"]
                            if f["bucket"] in ("fix-before-release", "fix-soon")))
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--baseline",
                                os.path.join(self.tmp.name, "nope.json"), "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("baseline", err)


if __name__ == "__main__":
    unittest.main()
