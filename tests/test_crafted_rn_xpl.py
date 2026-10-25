# SPDX-License-Identifier: Apache-2.0
"""Crafted worst cases for the XPL rules' React Native (JavaScript and TypeScript) checks.

Each case is a 200 KB file built to make one check repeat work: unclosed calls, long member chains,
thousands of candidate matches on one line. Every rule must still scan it in under 3 seconds.
"""

import json
import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, engine, profile, safety
from masaudit.model import Project

N = 200_000
J = "src/a.tsx"
PACKAGE = json.dumps({"name": "a", "dependencies": {"react-native": "0.76.1", "crypto-js": "4.1.1"}})
MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application><activity android:name=".M"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/></intent-filter></activity></application></manifest>')


def rep(unit: str) -> str:
    """unit repeated to about 100 KB, in lines of about 300 characters (a single huge line would be skipped as
    a minified bundle, which is not the case under test)."""
    line = unit * max(1, 300 // len(unit)) + "\n"
    return line * (N // 2 // len(line))


CASES = [  # (rule, files)
    ("XPL-001", {J: rep("const sk = 'sk-aaaa' + ")}),
    ("XPL-002", {J: rep("'AIza")}),
    ("XPL-003", {J: rep("a.") + "password = 'x'\n" + rep("jwt.sign(a, ") + rep("'https://u:")}),
    ("XPL-003", {J: rep("clientSecret: '") + rep("btoa('a:")}),
    ("XPL-043", {J: "const password = 'pass123';\n" + rep("a.b.c.d.e.f.g.h.i.j === ") + rep("'abc' === ")}),
    ("XPL-043", {J: "const PASS = 'x1y2z3';\n" + rep("p === PASS;\n")}),
    ("XPL-009", {J: rep("fetch('http://a.b") + rep("'http://' + ")}),
    ("XPL-010", {J: rep("console.log('token =', token, ") + rep("console.log(")}),
    ("XPL-012", {J: "import Clipboard from '@react-native-clipboard/clipboard';\n" + rep("Clipboard.setString(t")
                 + rep("const t = 1;\nClipboard.setString(t);\n")}),
    ("XPL-004", {J: rep("mode.ECB ")}),
    ("XPL-006", {J: rep("const iv = 'abcd';\n") + "x = { iv: iv }\n"}),
    ("XPL-006", {J: rep("createCipheriv(a, b, ")}),
    ("XPL-007", {J: rep("function password() { CryptoJS.MD5(")}),
    ("XPL-008", {J: rep("const token = Math.random() + Math.random() + ")}),
    ("XPL-008", {J: rep("function token() {\nreturn Math.random()\n}\n")}),
    ("XPL-011", {J: rep("AES.encrypt(a, KEY") + "const KEY = 'abcdef';\n"}),
    ("XPL-011", {J: "import { MMKV } from 'react-native-mmkv';\n" + rep("new MMKV({ encryptionKey: 'abc', ")}),
    ("XPL-013", {J: rep("CryptoJS.DES.encrypt(")}),
    ("XPL-014", {J: rep("generateKeyPair({ bits: 512, ")}),
    ("XPL-015", {J: rep("CryptoJS.PBKDF2(") + rep("pbkdf2Sync(p, s, N, ")}),
    ("XPL-016", {J: rep("CryptoJS.PBKDF2(p, SALT, {}) ")}),
    ("XPL-045", {J: rep("const nonce = Date.now() + ")}),
    ("XPL-018", {J: rep("ACCESS_CONTROL.DEVICE_PASSCODE ")}),
    ("XPL-029", {J: rep("injectJavaScript(`${token}") + rep("<WebView injectedJavaScript={`${token}`} ")}),
    ("XPL-031", {J: "import SQLite from 'react-native-sqlite-storage';\nimport Realm from 'realm';\n"
                 + rep("CREATE TABLE t (") + rep("properties: { password: 'string', ")}),
    ("XPL-032", {J: rep("notifee.displayNotification({ body: otp, ")}),
    ("XPL-033", {J: "import F from './F';\n" + rep("<TextInput placeholder=\"Password\" ") + rep("<F ")}),
    ("XPL-034", {J: "import analytics from '@react-native-firebase/analytics';\n" + rep("setUserId(email, ")}),
    ("XPL-036", {J: rep("'http://10.0.0.1/") + rep("'https://a.b/api/debug/")}),
    ("XPL-037", {J: rep("usePKCE: false, ")}),
    ("XPL-044", {J: "import RNFS from 'react-native-fs';\n" + rep("RNFS.writeFile(token, ")}),
    ("XPL-046", {J: rep("dangerouslySetInnerHTML={{ __html: x ") + rep("<WebView source={{ html: `${x}` }} ")}),
    ("XPL-038", {J: rep("root security ") + rep("isEmulator( ")}),
    ("XPL-040", {J: rep("forceUpdate minVersion ")}),
]


class CraftedReactNativeInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files):
        root = tempfile.mkdtemp(dir=self.tmp)
        files = dict({"package.json": PACKAGE, "android/app/src/main/AndroidManifest.xml": MANIFEST}, **files)
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        found = safety.walk(root)
        platforms = detect.platforms(found, root)
        self.assertIn("react-native", platforms)
        project = Project(root=root, platforms=platforms, files=found)
        rule = next(r for r in engine.load_rules() if r.id == rule_id)
        start = time.monotonic()
        engine.run(project, [rule], profile.make("banking", "flag"))
        return time.monotonic() - start

    def test_crafted_files_scan_fast(self):
        for rule_id, files in CASES:
            with self.subTest(rule=rule_id):
                self.assertLess(self._run(rule_id, files), 3.0)


if __name__ == "__main__":
    unittest.main()
