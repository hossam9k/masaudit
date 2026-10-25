# SPDX-License-Identifier: Apache-2.0
"""The iOS detectors added or widened for recall must stay linear on crafted files: thousands of
calls, declarations or guards in one file, and one very long line."""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, engine, profile, safety
from masaudit.model import Project

SIZE = 200_000
HANDLER = "func urlSession(_ s: URLSession, didReceive challenge: URLAuthenticationChallenge) {\n"


class IosDetectorsAreLinear(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scan(self, rule_id, name, text):
        root = tempfile.mkdtemp(dir=self.tmp)
        os.makedirs(os.path.join(root, "App"))
        with open(os.path.join(root, "App", name), "w", encoding="utf-8") as fh:
            fh.write(text)
        files = safety.walk(root)
        project = Project(root=root, platforms=detect.platforms(files) or ["ios"], files=files)
        rule = next(r for r in engine.load_rules() if r.id == rule_id)
        start = time.monotonic()
        findings = engine.run(project, [rule], profile.make("banking", "flag"))
        return time.monotonic() - start, findings

    def test_crafted_files(self):
        cases = [  # (rule, file, prefix, repeated text, suffix, reports something)
            ("IOS-004", "A.swift", HANDLER + "completionHandler(.useCredential, URLCredential(trust: t))\n",
             "guard let t = challenge.protectionSpace.serverTrust else { completionHandler(.cancelAuthentication"
             "Challenge, nil); return }\n", "}\n", True),
            ("IOS-004", "B.swift", HANDLER, "guard ", "", False),
            ("IOS-031", "A.swift", "", "static let d = FileManager.default.urls(for: .documentDirectory)\n"
                                       "func f() { w.loadFileURL(u, allowingReadAccessTo: d) }\n", "", True),
            ("IOS-033", "A.swift", "", "sec_protocol_options_set_min_tls_protocol_version(o,\n(", "", False),
            ("IOS-043", "A.swift", "", "let pinField = UITextField()\npinField.placeholder = \"PIN\"\n", "", True),
            ("IOS-043", "A.storyboard", "", '<textField placeholder="Password" id="a">', "", True),
            ("IOS-044", "A.swift", "func f() {\n", "NWConnection(host: \"a.example.com\", port: p, using: .tcp)\n",
             "", True),
            ("IOS-044", "B.swift", "func f() {\n", "let p = 80\nNWConnection(host: h, port: p, using: .tcp)\n", "",
             True),
            ("IOS-045", "A.swift", "func f() {\n",
             "let html = \"<input type='password'>\"\nweb.loadHTMLString(html, baseURL: nil)\n", "", True),
            ("IOS-045", "B.swift", "func f() {\n<input type=\"password\">\n",
             'let html = """\nweb.loadHTMLString(html, baseURL: nil)\n', "", False),
            ("IOS-046", "A.swift", "let docs = documentDirectory\n",
             'func g() { try d.write(to: docs.appendingPathComponent("token.json")) }\n', "", True),
            ("IOS-046", "B.swift", "func f() {\nlet docs = documentDirectory\n",
             "let name = \"report.pdf\"\ntry d.write(to: docs.appendingPathComponent(name))\n", "", False),
        ]
        for rule_id, name, prefix, unit, suffix, reports in cases:
            with self.subTest(rule=rule_id, file=name):
                elapsed, findings = self._scan(rule_id, name, prefix + unit * (SIZE // len(unit)) + suffix)
                self.assertLess(elapsed, 3.0)
                self.assertEqual(bool(findings), reports)


if __name__ == "__main__":
    unittest.main()
