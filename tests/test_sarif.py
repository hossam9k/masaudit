# SPDX-License-Identifier: Apache-2.0
"""SARIF 2.1.0 output: structure, severities per profile, fingerprints, suppressions."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from helpers import FIXTURES
from masaudit import cli, engine, profile
from masaudit.model import Finding, Location, Project, Rule
from masaudit.report import sarif

VULN = os.path.join(FIXTURES, "AND-001", "vulnerable")


def validate(test, doc):
    """Basic structural checks from the SARIF 2.1.0 schema (no network, no jsonschema)."""
    test.assertEqual(doc["version"], "2.1.0")
    test.assertIn("sarif-2.1.0", doc["$schema"])
    test.assertEqual(len(doc["runs"]), 1)
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    test.assertEqual(driver["name"], "masaudit")
    test.assertTrue(driver["version"])
    test.assertTrue(driver["informationUri"].startswith("https://"))
    ids = [r["id"] for r in driver["rules"]]
    test.assertEqual(len(ids), len(set(ids)))
    for r in driver["rules"]:
        for key in ("id", "name", "shortDescription", "fullDescription", "help", "properties"):
            test.assertIn(key, r)
        test.assertTrue(r["help"]["text"] and r["help"]["markdown"])
        test.assertIn("security", r["properties"]["tags"])
        test.assertGreater(float(r["properties"]["security-severity"]), 0)
    test.assertTrue(run["automationDetails"]["id"].startswith("masaudit/"))
    for res in run["results"]:
        test.assertIn(res["ruleId"], ids)
        test.assertEqual(ids[res["ruleIndex"]], res["ruleId"])
        test.assertIn(res["level"], ("error", "warning", "note"))
        test.assertTrue(res["message"]["text"])
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        test.assertNotIn("\\", uri)
        test.assertFalse(uri.startswith("/") or "://" in uri)
        test.assertGreaterEqual(loc["region"]["startLine"], 1)
        test.assertIn("masaudit/v1", res["partialFingerprints"])
    return run


def rule(rid, **kw):
    base = dict(id=rid, title="Pinning is missing", platform="android", severity="high", profiles=["L1"],
                why="w", fix="f", verify="v", effort="hours", book="§8.8", book_url="https://example.invalid",
                maswe="MASWE-0047", masvs="MASVS-NETWORK-2", detector="x")
    base.update(kw)
    return Rule(**base)


def make_result(findings, app_type):
    prof = profile.make(app_type, "flag")
    engine.calibrate(findings, prof)
    project = Project(root="/tmp/x", platforms=["android", "ci"], files=[])
    return cli.ScanResult(root="/tmp/x", project=project, profile=prof, findings=findings, rules=[],
                          rules_version="1.0.0")


class Sarif(unittest.TestCase):
    def test_fixture_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.sarif")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main([VULN, "--app-type", "banking", "--format", "sarif", "--output", out])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
        run = validate(self, doc)
        hits = [r for r in run["results"] if r["ruleId"] == "AND-001"]
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(r["level"] == "error" for r in hits))
        self.assertEqual(run["automationDetails"]["id"], "masaudit/android")
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in hits}
        self.assertIn("app/src/main/AndroidManifest.xml", uris)

    def test_severity_follows_profile_and_not_needed_is_omitted(self):
        r = rule("AND-950", app_types=["banking"], not_needed_reason="Only banking.")
        def mk():
            return [Finding(rule=r, location=Location(path="a\\b.kt", line=0))]

        banking = sarif.to_dict(make_result(mk(), "banking"))
        validate(self, banking)
        self.assertEqual(banking["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "7.5")
        self.assertEqual(banking["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        content = sarif.to_dict(make_result(mk(), "content"))
        self.assertEqual(content["runs"][0]["results"], [])
        included = sarif.to_dict(make_result(mk(), "content"), include_not_needed=True)
        validate(self, included)
        self.assertEqual(included["runs"][0]["results"][0]["level"], "note")
        self.assertEqual(included["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "1.0")

    def test_suppressions(self):
        r = rule("AND-951", severity="medium")
        a = Finding(rule=r, location=Location(path="a.kt", line=2), status="suppressed",
                    suppression_reason="reviewed")
        b = Finding(rule=r, location=Location(path="b.kt", line=2), status="baselined")
        doc = sarif.to_dict(make_result([a, b], "general"))
        validate(self, doc)
        kinds = sorted(res["suppressions"][0]["kind"] for res in doc["runs"][0]["results"])
        self.assertEqual(kinds, ["external", "inSource"])
        self.assertTrue(all(res["level"] == "warning" for res in doc["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
