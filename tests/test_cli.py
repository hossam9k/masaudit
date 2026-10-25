# SPDX-License-Identifier: Apache-2.0
"""End-to-end CLI: exit codes, reports, config, the first-run question, imports, zipapp."""

import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from helpers import FIXTURES
from masaudit import cli
from masaudit.model import SEVERITY_RANK

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(ROOT, "src")
VULN = os.path.join(FIXTURES, "AND-001", "vulnerable")


def run_cli(*argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    environ = {"CI": "1"}
    environ.update(env or {})
    with mock.patch.dict(os.environ, environ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_run_writes_report_and_summary(self):
        report = os.path.join(self.dir, "SECURITY-AUDIT.md")
        code, out, _err = run_cli(VULN, "--app-type", "banking", "--output", report)
        self.assertEqual(code, 0)
        md = read(report)
        self.assertIn("Cleartext (plain HTTP) traffic is allowed", md)
        self.assertIn("## Fix before release", md)
        self.assertIn("banking", md)
        self.assertIn(f"Report: {report}", out)
        self.assertTrue(out.strip().splitlines()[-1].startswith("Next: open SECURITY-AUDIT.md"))
        self.assertTrue(all(ord(c) < 128 for c in out))
        self.assertFalse(os.path.exists(os.path.join(VULN, "SECURITY-AUDIT.md")))

    def test_fail_on(self):
        code, _o, _e = run_cli(VULN, "--app-type", "banking", "--format", "json", "--fail-on", "high",
                               "--output", os.path.join(self.dir, "r.json"))
        self.assertEqual(code, 1)          # AND-001 is high for a banking app
        for level in ("critical", "high", "medium", "low"):
            with self.subTest(level=level):
                out = os.path.join(self.dir, f"{level}.json")
                code, _o, _e = run_cli(VULN, "--app-type", "banking", "--format", "json", "--fail-on", level,
                                       "--output", out)
                data = json.loads(read(out))
                expect = any(f["status"] == "open" and f["bucket"] in ("fix-before-release", "fix-soon")
                             and SEVERITY_RANK[f["effective_severity"]] <= SEVERITY_RANK[level]
                             for f in data["findings"])
                self.assertEqual(code, 1 if expect else 0)
        code, _o, _e = run_cli(VULN, "--app-type", "banking", "--format", "json",
                               "--output", os.path.join(self.dir, "x.json"))
        self.assertEqual(code, 0)          # no --fail-on: never fails

    def test_empty_project_passes(self):
        open(os.path.join(self.dir, "README.md"), "w").close()
        code, _o, err = run_cli(self.dir, "--format", "json", "--fail-on", "low",
                                "--output", os.path.join(self.dir, "out.json"))
        self.assertEqual(code, 0)
        self.assertIn(cli.ASSUMED_LINE, err)

    def test_tool_errors_exit_2(self):
        self.assertEqual(run_cli(os.path.join(self.dir, "missing"))[0], 2)
        self.assertEqual(run_cli(VULN, "--app-type", "spaceship", "--format", "json")[0], 2)
        self.assertEqual(run_cli(VULN, "--format", "pdf")[0], 2)
        self.assertEqual(run_cli(VULN, "--yes")[0], 2)

    def test_config(self):
        proj = os.path.join(self.dir, "p")
        shutil.copytree(VULN, proj)
        ini = os.path.join(proj, ".masaudit.ini")
        with open(ini, "w") as fh:
            fh.write("[masaudit]\napp_type = news\nfail_on = high\n")
        out = os.path.join(self.dir, "r.json")
        code, _o, _e = run_cli(proj, "--format", "json", "--output", out)
        self.assertEqual(code, 1)
        data = json.loads(read(out))
        self.assertEqual((data["profile"]["app_type"], data["profile"]["source"]), ("content", "config"))
        code, _o, _e = run_cli(proj, "--format", "json", "--output", out, "--app-type", "health")
        self.assertEqual(json.loads(read(out))["profile"]["source"], "flag")
        with open(ini, "w") as fh:
            fh.write("[masaudit]\napp_type = banking\nexclude = app/src/main/res/*\n")
        run_cli(proj, "--format", "json", "--output", out)
        paths = {f["path"] for f in json.loads(read(out))["findings"]}
        self.assertNotIn("app/src/main/res/xml/network_security_config.xml", paths)
        with open(ini, "w") as fh:
            fh.write("[masaudit]\napptype = banking\n")
        code, _o, err = run_cli(proj, "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("unknown key", err)

    def test_first_run_question(self):
        proj = os.path.join(self.dir, "p")
        shutil.copytree(VULN, proj)
        with open(os.path.join(proj, "app", "build.gradle"), "w") as fh:
            fh.write("dependencies { implementation 'com.stripe:stripe-android:20.0.0' }\n")
        out = os.path.join(self.dir, "r.json")
        answers = iter(["1", "y"])
        with mock.patch.object(cli, "_is_interactive", return_value=True), \
                mock.patch("builtins.input", lambda: next(answers)):
            code, _o, err = run_cli(proj, "--format", "json", "--output", out)
        self.assertEqual(code, 0)
        self.assertIn("What kind of app is this?", err)
        self.assertIn("payment SDK", err)
        data = json.loads(read(out))
        self.assertEqual((data["profile"]["app_type"], data["profile"]["source"]), ("banking", "prompt"))
        self.assertIn("app_type = banking", read(os.path.join(proj, ".masaudit.ini")))

    def test_never_picks_a_type_from_clues(self):
        proj = os.path.join(self.dir, "p")
        shutil.copytree(VULN, proj)
        with open(os.path.join(proj, "app", "build.gradle"), "w") as fh:
            fh.write("dependencies { implementation 'com.stripe:stripe-android:20.0.0' }\n")
        out = os.path.join(self.dir, "r.json")
        code, _o, err = run_cli(proj, "--format", "json", "--output", out)
        data = json.loads(read(out))
        self.assertEqual((data["profile"]["app_type"], data["profile"]["source"]), ("general", "default"))
        self.assertTrue(any("payment SDK" in s for s in data["profile"]["suggestions"]))
        self.assertIn(cli.ASSUMED_LINE, err)
        self.assertNotIn("What kind of app", err)

    def test_explain_list_version_help(self):
        code, out, _e = run_cli("--explain", "and-001")
        self.assertEqual(code, 0)
        self.assertIn("Cleartext (plain HTTP) traffic is allowed", out)
        self.assertEqual(run_cli("--explain", "NOPE-999")[0], 2)
        code, out, _e = run_cli("--list-rules")
        self.assertIn("AND-001", out)
        code, out, _e = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn("masaudit", out)
        code, out, _e = run_cli("--help")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip().splitlines()[-1], cli.SPONSOR_LINE)

    def test_no_network(self):
        def refuse(*_a, **_k):
            raise AssertionError("masaudit tried to open a socket")

        report = os.path.join(self.dir, "r.md")
        with mock.patch.object(socket, "socket", refuse), mock.patch.object(socket, "create_connection", refuse):
            code, _o, err = run_cli(VULN, "--app-type", "banking", "--output", report, "--fail-on", "high")
        self.assertEqual(code, 1, err)
        self.assertIn("AND-001", read(report))


class ImportSarif(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _sarif(self, results, name="Android Lint", rules=None):
        path = os.path.join(self.dir, f"{len(os.listdir(self.dir))}.sarif")
        doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": name, "rules": rules or []}},
                                             "results": results}]}
        with open(path, "w") as fh:
            json.dump(doc, fh)
        return path

    def test_mapped_and_imported(self):
        path = self._sarif([
            {"ruleId": "InsecureBaseConfiguration", "level": "warning", "message": {"text": "Insecure base"},
             "locations": [{"physicalLocation": {"artifactLocation": {
                 "uri": "app/src/main/res/xml/network_security_config.xml"}, "region": {"startLine": 3}}}]},
            {"ruleId": "InsecureBaseConfiguration", "level": "warning", "message": {"text": "dup elsewhere"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "other/res/xml/nsc.xml"},
                                                 "region": {"startLine": 7}}}]},
            {"ruleId": "SomethingNew", "level": "error", "message": {"text": "AKIAIOSFODNN7EXAMPLE leaked"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/src/main/AndroidManifest.xml"},
                                                 "region": {"startLine": 2}}}]},
        ])
        out = os.path.join(self.dir, "r.json")
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--format", "json", "--output", out,
                                "--import-sarif", path)
        self.assertEqual(code, 0, err)
        findings = json.loads(read(out))["findings"]
        nsc = [f for f in findings if f["path"] == "app/src/main/res/xml/network_security_config.xml"]
        self.assertEqual(len(nsc), 1)                                   # merged with the native hit
        mapped = [f for f in findings if f["path"] == "other/res/xml/nsc.xml"]
        self.assertEqual(mapped[0]["rule_id"], "AND-001")
        new = [f for f in findings if f["imported"]]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["effective_severity"], "high")          # from level "error"
        self.assertEqual(new[0]["bucket"], "fix-before-release")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", read(out))

    def test_zizmor_ids_map_by_title(self):
        from masaudit import importers
        from masaudit.model import Rule

        def r(rid, title):
            return Rule(id=rid, title=title, platform="ci", severity="high", profiles=["L1"], why="w", fix="f",
                        verify="v", effort="minutes", book="§1.1", book_url="u", detector="x")

        rules = [r("CI-101", "Third-party action is pinned to a tag or branch, not a commit SHA"),
                 r("CI-102", "Workflow token permissions are not restricted"),
                 r("CI-103", "Untrusted event text is pasted into a run script")]
        loc = [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/ci.yml"},
                                     "region": {"startLine": 4}}}]
        path = self._sarif([{"ruleId": rid, "level": "error", "message": {"text": "m"}, "locations": loc}
                            for rid in ("zizmor/unpinned-uses", "excessive-permissions", "template-injection",
                                        "zizmor/obfuscation")], name="zizmor")
        findings, _notes = importers.import_sarif(path, self.dir, rules)
        self.assertEqual([f.rule.id for f in findings], ["CI-101", "CI-102", "CI-103", "zizmor:zizmor/obfuscation"])
        self.assertEqual(findings[0].scope, "ci")

    def test_path_after_import_sarif_is_still_the_scan_root(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--import-sarif", "lint.sarif", FIXTURES])
        self.assertEqual(args.import_sarif, ["lint.sarif", FIXTURES])     # argparse alone gets it wrong
        with mock.patch.object(cli, "_main", side_effect=lambda a: (a.path, a.import_sarif)):
            self.assertEqual(cli.main(["--import-sarif", "lint.sarif", FIXTURES]), (FIXTURES, ["lint.sarif"]))

    def test_every_mapping_lands_on_the_rule_it_names(self):
        from masaudit import engine, importers

        rules = engine.load_rules()
        for ext_id, (_platform, rule_id, _title) in importers.MAPPING.items():
            with self.subTest(ext_id=ext_id):
                found = importers._find_rule(ext_id, rules)
                self.assertIsNotNone(found)
                self.assertEqual(found.id, rule_id)
        # Lint's SetJavaScriptEnabled has no masaudit equivalent; it must not borrow AND-012's title.
        self.assertIsNone(importers._find_rule("SetJavaScriptEnabled", rules))

    def test_bad_sarif_exits_2(self):
        bad = os.path.join(self.dir, "bad.sarif")
        with open(bad, "w") as fh:
            fh.write("{not json")
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--format", "json", "--import-sarif", bad)
        self.assertEqual(code, 2)
        self.assertIn("not valid SARIF", err)
        with open(bad, "w") as fh:
            fh.write('{"runs": 5}')
        self.assertEqual(run_cli(VULN, "--format", "json", "--import-sarif", bad)[0], 2)
        self.assertEqual(run_cli(VULN, "--format", "json", "--import-sarif", bad + ".missing")[0], 2)

    def test_odd_tool_values_are_skipped_not_internal_errors(self):
        odd = os.path.join(self.dir, "odd.sarif")
        with open(odd, "w") as fh:
            fh.write('{"version": "2.1.0", "runs": [{"tool": 5, "results": []}, {"tool": {"driver": 5}}]}')
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--format", "json", "--import-sarif", odd)
        self.assertNotIn("internal error", err)
        self.assertIn(code, (0, 1))

    def test_baseline_that_cant_be_written_is_a_clean_error(self):
        code, _o, err = run_cli(VULN, "--app-type", "banking", "--format", "json", "--update-baseline",
                                "--baseline", self.dir)                 # a folder, not a file
        self.assertEqual(code, 2)
        self.assertIn("Couldn't write the baseline", err)
        self.assertNotIn("internal error", err)


class Subprocess(unittest.TestCase):
    def _env(self):
        env = dict(os.environ, PYTHONPATH=SRC, CI="1")
        env.pop("SOURCE_DATE_EPOCH", None)
        return env

    def test_module_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = [sys.executable, "-m", "masaudit", VULN, "--app-type", "banking", "--output",
                    os.path.join(tmp, "r.md")]
            self.assertEqual(subprocess.run(base + ["--fail-on", "high"], env=self._env(),
                                            capture_output=True).returncode, 1)
            self.assertEqual(subprocess.run(base, env=self._env(), capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(base + ["--app-type", "nope"], env=self._env(),
                                            capture_output=True).returncode, 2)


class Zipapp(unittest.TestCase):
    def test_reproducible_and_runnable(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a", "masaudit.pyz"), os.path.join(tmp, "b", "masaudit.pyz")
            script = os.path.join(ROOT, "scripts", "build_zipapp.py")
            env = dict(os.environ)
            env.pop("SOURCE_DATE_EPOCH", None)
            for out in (a, b):
                subprocess.run([sys.executable, script, "--output", out], check=True, capture_output=True, env=env)
            with open(a, "rb") as fa, open(b, "rb") as fb:
                self.assertEqual(fa.read(), fb.read())
            run_env = dict(os.environ, CI="1")
            run_env.pop("PYTHONPATH", None)
            proc = subprocess.run([sys.executable, "-I", a, "--list-rules"], capture_output=True, text=True,
                                  cwd=tmp, env=run_env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("AND-001", proc.stdout)
            report = os.path.join(tmp, "r.md")
            proc = subprocess.run([sys.executable, "-I", a, VULN, "--app-type", "banking", "--output", report,
                                   "--fail-on", "high"], capture_output=True, text=True, cwd=tmp, env=run_env)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("AND-001", read(report))


if __name__ == "__main__":
    unittest.main()
