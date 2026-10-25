# SPDX-License-Identifier: Apache-2.0
"""Crafted worst cases for the React Native platform rules (RN-009 to RN-013, RN-020).

A repository masaudit scans can't be trusted, so a 200 KB file built to hit a rule's worst case must still scan in
a few seconds: many sources, many sinks, unclosed brackets, long declarations, many bridge methods.
"""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import engine, profile, safety
from masaudit.model import Project

N = 200_000
PKG = ('{"name": "a", "dependencies": {"react-native": "0.76.0", "expo-sqlite": "15.0.0", '
       '"expo-local-authentication": "15.0.0", "crypto-js": "4.2.0"}}')
JS = "src/App.tsx"
KT = "android/app/src/main/java/a/M.kt"
OBJC = "ios/App/M.m"


def rep(unit: str) -> str:
    return unit * (N // len(unit))


CASES = [  # (rule, files)
    ("RN-009", {JS: "import { Linking } from 'react-native';\n"
                    + rep("Linking.addEventListener('url', ({ url }) => { const a = url; Linking.openURL(a); });\n")}),
    ("RN-009", {JS: "import { Linking } from 'react-native';\nLinking.addEventListener('url', (u) => {\n"
                    + rep("const a = u; f(a); navigate('X', { url: a }); fetch(a);\n")}),
    ("RN-009", {JS: "import { Linking } from 'react-native';\n"
                    + "".join(f"function handleDeepLink{i}(u) {{ h{i + 1}(u); }}\n" for i in range(N // 40))}),
    ("RN-009", {JS: "import { Linking } from 'react-native';\nconst url = Linking.useURL();\n" + rep("{")}),
    ("RN-009", {JS: "import { Linking } from 'react-native';\n" + rep("const a = await Linking.getInitialURL()\n")}),
    ("RN-010", {JS: rep("eval(x + ")}),
    ("RN-010", {JS: rep("new Function(a, b);\n")}),
    ("RN-011", {JS: "import * as SQLite from 'expo-sqlite';\n" + rep("db.getAllAsync(`SELECT ${a}` + b);\n")}),
    ("RN-011", {JS: "import * as SQLite from 'expo-sqlite';\n" + rep("const sql = 'SELECT ' + x\n")
                    + "db.runAsync(sql);\n"}),
    ("RN-011", {JS: "import * as SQLite from 'expo-sqlite';\ndb.execAsync(`SELECT " + rep("${(") + "`)\n"}),
    ("RN-012", {JS: "import * as L from 'expo-local-authentication';\n" + rep("L.authenticateAsync();\n")}),
    ("RN-013", {JS: "import CryptoJS from 'crypto-js';\n" + rep("CryptoJS.AES.encrypt(m, k);\n")}),
    ("RN-013", {JS: "import CryptoJS from 'crypto-js';\n" + rep("const k = 'a';\n") + "CryptoJS.AES.encrypt(m, k);\n"}),
    ("RN-020", {KT: "class M {\n" + rep("@ReactMethod fun f(p: String, q: Promise) { val a = p\n File(a) }\n") + "}\n"}),
    ("RN-020", {KT: "class M {\n@ReactMethod fun f(p: String) {\n" + rep("val a = p + b\n") + "}\n}\n"}),
    ("RN-020", {OBJC: rep("RCT_EXPORT_METHOD(f:(NSString *)p) { [NSData dataWithContentsOfFile:p]; }\n")}),
]


class CraftedRnPlatform(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files):
        root = tempfile.mkdtemp(dir=self.tmp)
        for rel, text in dict({"package.json": PKG}, **files).items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        project = Project(root=root, platforms=["react-native", "android", "ios"], files=safety.walk(root))
        rule = next(r for r in engine.load_rules() if r.id == rule_id)
        start = time.monotonic()
        engine.run(project, [rule], profile.make("banking", "flag"))
        return time.monotonic() - start

    def test_crafted_files_scan_fast(self):
        for rule_id, files in CASES:
            with self.subTest(rule=rule_id, files=sorted(files)):
                self.assertLess(self._run(rule_id, files), 3.0)


if __name__ == "__main__":
    unittest.main()
