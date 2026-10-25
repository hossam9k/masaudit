# SPDX-License-Identifier: Apache-2.0
"""Crafted files from the 0.5.0 code review: each one made a rule quadratic (or crash) before its fix.

A repository masaudit scans can't be trusted, so a 200 KB file built to hit a rule's worst case must still
scan in a few seconds. Each case names the rule, the files, and what the review measured before the fix.
"""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, engine, profile, safety
from masaudit.model import Project

N = 200_000
K = "app/src/main/java/a/A.kt"
MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application/></manifest>')


def rep(unit: str) -> str:
    return unit * (N // len(unit))


CASES = [  # (rule, files, Android project, time before the fix)
    ("AND-073", {K: "fun f() {\nval s = SSLSocketFactory.getDefault().createSocket(h, 443)\ns.startHandshake()\n}\n"
                    "val x = verify" + "Host" * (N // 4) + "\n"}, True, "32 s"),
    ("AND-076", {"app/src/main/res/layout/a.xml": rep("<EditText ")}, True, "1.1 s"),
    ("XPL-033", {"app/src/main/res/layout/a.xml": rep("<EditText ")}, True, "about 4 s; 19.7 s at 1 MB"),
    ("AND-046", {K: "val p = Button(c).apply { filterTouchesWhenObscured = true }\n",
                 "app/src/main/res/layout/a.xml": rep("<Button ")}, True, "slow"),
    ("AND-046", {K: "val p = Button(c).apply { filterTouchesWhenObscured = true }\n",
                 "app/src/main/res/layout/a.xml": '<Button android:text="@string/a"/>',
                 "app/src/main/res/values/strings.xml": rep('<string name="a" ')}, True, "slow"),
    ("AND-020", {K: "class P {\nval qb = SQLiteQueryBuilder()\noverride fun query(u: Uri, p: X, " + "a" * 40_000
                    + "!, d: X, e: X): Cursor? {\nreturn qb.query(db)\n}\n}\n"}, True, "15 s"),
    ("AND-074", {K: "val b = KeyGenParameterSpec.Builder(a, 1).setUserAuthenticationRequired(true)"
                    ".setUserAuthenticationValidityDurationSeconds(" + "9" * 5000 + ")\n"}, True, "ValueError"),
    ("XPL-009", {K: "".join(f'val a{i} = "http://"\n' for i in range(N // 18))
                    + "".join(f"val u{i} = a{i} + host\n" for i in range(200))}, True, "19.7 s"),
    ("XPL-010", {K: "fun f() {\n" + rep("user.a" + "token" * 400 + "\n" + "println(user)\n" * 140) + "}\n"}, True,
     "19 s"),
    ("XPL-011", {K: "".join(f'fun f{i}(k: ByteArray) {{ SecretKeySpec(k, "AES") }}\n' for i in range(N // 50))}, True,
     "6.4 s"),
    ("XPL-015", {K: "".join(f"fun k{i}(p: CharArray, s: ByteArray, n: Int) {{ PBEKeySpec(p, s, n, 256) }}\n"
                            for i in range(N // 75))}, True, "11.7 s"),
    ("XPL-016", {K: "".join(f"fun k{i}(p: CharArray, s: ByteArray, n: Int) {{ PBEKeySpec(p, s, n, 256) }}\n"
                            for i in range(N // 75))}, True, "9.3 s"),
    ("XPL-031", {"App/User.swift": "import RealmSwift\nclass User: Object {\n" + rep("@a\n") + "}\n"}, False, "94 s"),
    ("XPL-031", {"App/User.m": "#import <Realm/Realm.h>\n@interface User : RLMObject\n@property " + "a" * N
                 + "\n@end\n"}, False, "over 120 s"),
    ("XPL-031", {"App/Model.xcdatamodeld/Model.xcdatamodel/contents": rep("<entity>"),
                 "App/A.swift": "let u = User(context: c)\n"}, False, "10.6 s"),
    ("XPL-031", {"App/Model.xcdatamodeld/Model.xcdatamodel/contents":
                 '<entity name="User"><attribute ' + rep('name="a" ') + "</entity>",
                 "App/A.swift": "let u = User(context: c)\n"}, False, "2.5 s"),
]


class CraftedInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files, android):
        root = tempfile.mkdtemp(dir=self.tmp)
        if android:
            files = dict({"app/src/main/AndroidManifest.xml": MANIFEST}, **files)
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        found = safety.walk(root)
        project = Project(root=root, platforms=detect.platforms(found, root) or ["ios"], files=found)
        rule = next(r for r in engine.load_rules() if r.id == rule_id)
        start = time.monotonic()
        engine.run(project, [rule], profile.make("banking", "flag"))
        return time.monotonic() - start

    def test_crafted_files_scan_fast(self):
        for rule_id, files, android, before in CASES:
            with self.subTest(rule=rule_id, before=before):
                self.assertLess(self._run(rule_id, files, android), 3.0)


if __name__ == "__main__":
    unittest.main()
