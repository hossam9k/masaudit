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

    def test_page_break_earlier_in_the_file_keeps_lines_aligned(self):
        # str.splitlines() also splits at U+0085 and U+2028 (and form feeds); line numbers count "\n" only.
        path = os.path.join(self.root, NSC)
        lines = _read(path, encoding="utf-8").split("\n")
        lines[0] += "<!-- next line \x85 and line separator \u2028 -->"
        _write(path, "\n".join(lines), encoding="utf-8")
        self._prepend_comment("    <!-- masaudit:ignore AND-001 only used by the offline lab build -->")
        res, hits = self._scan()
        self.assertEqual(hits[0].status, "suppressed")
        self.assertNotIn("masaudit:ignore", hits[0].location.snippet)

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

    def test_a_new_copy_of_a_baselined_line_is_not_covered(self):
        first = Finding(rule=rule(), location=Location(path="a.xml", line=1, snippet="<a/>"))
        fp_before = first.fingerprint()
        path = os.path.join(self.tmp.name, "base.json")
        suppress.write_baseline(path, [first])
        old = Finding(rule=rule(), location=Location(path="a.xml", line=1, snippet="<a/>"))
        copy = Finding(rule=rule(), location=Location(path="a.xml", line=7, snippet="<a/>"))
        cli._number_occurrences([copy, old])
        self.assertEqual(old.fingerprint(), fp_before)      # baselines written by earlier versions still match
        self.assertEqual(suppress.apply_baseline([old, copy], suppress.load_baseline(path)), 1)
        self.assertEqual((old.status, copy.status), ("baselined", "open"))

    def test_a_baseline_from_an_earlier_version_still_covers_identical_lines(self):
        # Before 0.6.1 identical lines shared one fingerprint; upgrading must not turn accepted findings new.
        path = os.path.join(self.tmp.name, "old.json")
        first = Finding(rule=rule(), location=Location(path="a.xml", line=1, snippet="<a/>"))
        _write(path, json.dumps({"schema_version": 1, "tool": "masaudit", "findings": {first.fingerprint(): {}}}))
        old = Finding(rule=rule(), location=Location(path="a.xml", line=1, snippet="<a/>"))
        copy = Finding(rule=rule(), location=Location(path="a.xml", line=7, snippet="<a/>"))
        cli._number_occurrences([old, copy])
        self.assertEqual(suppress.apply_baseline([old, copy], suppress.load_baseline(path)), 2)

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



class BaselineReasonsAndExpiry(unittest.TestCase):
    """Schema 3: each entry may say why it was accepted and until when; stale entries are reported."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "base.json")

    def tearDown(self):
        self.tmp.cleanup()

    def finding(self, name="a.xml"):
        return Finding(rule=rule(), location=Location(path=name, line=1, snippet=f"<{name}/>"))

    def test_reason_and_expiry_round_trip_and_survive_an_update(self):
        a = self.finding("a.xml")
        suppress.write_baseline(self.path, [a], reason="legacy host, fixed in 3.0", expires="2027-01-31")
        entry = json.loads(_read(self.path))["findings"][a.fingerprint()]
        self.assertEqual((entry["reason"], entry["expires"]), ("legacy host, fixed in 3.0", "2027-01-31"))
        self.assertEqual(json.loads(_read(self.path))["schema_version"], 3)
        # A refresh keeps hand-written reasons; a new entry gets this run's reason.
        b = self.finding("b.xml")
        previous = suppress.load_baseline(self.path)
        suppress.write_baseline(self.path, [self.finding("a.xml"), b], previous=previous, reason="new reason")
        found = json.loads(_read(self.path))["findings"]
        self.assertEqual(found[a.fingerprint()]["reason"], "legacy host, fixed in 3.0")
        self.assertEqual(found[a.fingerprint()]["expires"], "2027-01-31")      # an update never renews expiry
        self.assertEqual(found[b.fingerprint()]["reason"], "new reason")
        self.assertNotIn("expires", found[b.fingerprint()])

    def test_reason_is_shown_and_expired_entries_count_again(self):
        a, b = self.finding("a.xml"), self.finding("b.xml")
        suppress.write_baseline(self.path, [a], reason="accepted risk")
        suppress.write_baseline(self.path + "2", [b], expires="2026-01-01")
        merged = json.loads(_read(self.path))
        merged["findings"].update(json.loads(_read(self.path + "2"))["findings"])
        _write(self.path, json.dumps(merged))
        base = suppress.load_baseline(self.path)
        a2, b2 = self.finding("a.xml"), self.finding("b.xml")
        outcome = suppress.apply([a2, b2], base, today="2026-06-01")
        self.assertEqual((a2.status, a2.suppression_reason), ("baselined", "accepted risk"))
        self.assertEqual(b2.status, "open")                                    # expired on 2026-01-01
        self.assertEqual((outcome.matched, len(outcome.expired), outcome.stale), (1, 1, []))
        self.assertIn("expired (the first on 2026-01-01)", " ".join(outcome.notes("base.json")))
        # The day it expires, it still holds.
        b3 = self.finding("b.xml")
        suppress.apply([b3], base, today="2026-01-01")
        self.assertEqual(b3.status, "baselined")

    def test_stale_entries_are_reported(self):
        a, gone = self.finding("a.xml"), self.finding("gone.xml")
        suppress.write_baseline(self.path, [a, gone])
        outcome = suppress.apply([self.finding("a.xml")], suppress.load_baseline(self.path), today="2026-06-01")
        self.assertEqual([e["path"] for e in outcome.stale], ["gone.xml"])
        self.assertIn("1 entry in base.json no longer match", " ".join(outcome.notes("base.json")))

    def test_bad_dates_and_reasons_are_refused(self):
        a = self.finding()
        for bad in ("2027-13-01", "tomorrow", 20270101):
            _write(self.path, json.dumps({"schema_version": 3, "findings": {a.fingerprint(): {"expires": bad}}}))
            with self.subTest(bad=bad), self.assertRaises(suppress.BaselineError):
                suppress.load_baseline(self.path)
        _write(self.path, json.dumps({"schema_version": 3, "findings": {a.fingerprint(): {"reason": ["x"]}}}))
        with self.assertRaises(suppress.BaselineError):
            suppress.load_baseline(self.path)
        with self.assertRaises(suppress.BaselineError):
            suppress.write_baseline(self.path, [a], expires="31/01/2027")

    def test_a_hostile_reason_is_one_masked_line(self):
        a = self.finding()
        evil = "ok\n## Injected\n" + "token=ghp_" + "a" * 36
        _write(self.path, json.dumps({"schema_version": 3, "findings": {a.fingerprint(): {"reason": evil}}}))
        reason = suppress.load_baseline(self.path).entries[a.fingerprint()]["reason"]
        self.assertNotIn("\n", reason)
        self.assertNotIn("a" * 36, reason)

    def test_cli_reason_expiry_and_report(self):
        base = os.path.join(self.tmp.name, "b.json")
        out = os.path.join(self.tmp.name, "r.md")
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--format", "md", "--output", out,
                                "--baseline", base, "--baseline-reason", "release 1.2 exception")
        self.assertEqual(code, 2)
        self.assertIn("only work together with --update-baseline", err)
        run_cli(VULN, "--app-type", "banking", "--format", "md", "--output", out, "--baseline", base,
                "--update-baseline", "--baseline-reason", "release 1.2 exception", "--baseline-expires", "2099-12-31")
        md = _read(out)
        self.assertIn("in the baseline file: `release 1.2 exception`", md)
        from masaudit.report import markdown
        self.assertIn("release 1.2 exception", markdown.job_summary(md))   # a pull request's reviewer sees it
        # A baseline entry for code that no longer exists is reported as stale in JSON and the report.
        doc = json.loads(_read(base))
        doc["findings"]["0" * 32] = {"rule": "AND-001", "path": "gone.xml", "line": 1}
        _write(base, json.dumps(doc))
        jout = os.path.join(self.tmp.name, "r.json")
        run_cli(VULN, "--app-type", "banking", "--format", "json", "--output", jout, "--baseline", base)
        data = json.loads(_read(jout))
        self.assertEqual(data["baseline"]["stale"], 1)
        self.assertTrue(any("no longer match a finding" in n for n in data["notes"]))

if __name__ == "__main__":
    unittest.main()
