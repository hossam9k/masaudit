# SPDX-License-Identifier: Apache-2.0
"""Crafted files with thousands of hits must scan in linear time in the Android rules added for recall."""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, engine, profile, safety
from masaudit.model import Project

MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a.b">'
            '<application><activity android:name=".Main" android:exported="true"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/></intent-filter></activity>'
            '<provider android:name=".P" android:authorities="a.b" android:exported="true"/>'
            '</application></manifest>')

CASES = [  # (rule, file, prefix, repeated text, reports something)
    ("AND-012", "A.kt", "", "webView.apply {\naddJavascriptInterface(B(), \"b\")\n}\n", True),
    ("AND-034", "A.kt", "fun encrypt(s: String) = s\n", 'prefs.edit().putString("token", v{n}).apply()\n', False),
    ("AND-054", "A.kt", "", 'val i = Intent("a.b.X"); i.putExtra("pin", f{n}); startActivity(i)\n', True),
    ("AND-018", "A.kt", "", 'PendingIntent.getBroadcast(c, 0, Intent("a.b.X"), 0)\n', True),
    ("AND-020", "A.kt", "class P {\noverride fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, "
                        "o: String?): Cursor? {\nval qb = SQLiteQueryBuilder()\n",
     "qb.appendWhere(\"\" + f)\nqb.query(db, p, s, a, null, null, o)\n", True),
    ("AND-043", "A.kt", "fun f() {\nvar n = \"x\"\n",
     "n = c.getString(c.getColumnIndex(OpenableColumns.DISPLAY_NAME))\nFile(dir, n)\n", True),
    ("AND-046", "A.kt", "val p = Button(c).apply { filterTouchesWhenObscured = true }\n",
     'val b = Button(c).apply { text = "Pay" }\n', True),
    ("AND-060", "A.kt", "", "fun f() {\nresolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, "
                            "\"secret.txt\")\n}\n", True),
    ("AND-073", "A.kt", "", "fun f() {\nval s = SSLSocketFactory.getDefault().createSocket(h, 443)\n"
                            "s.startHandshake()\n}\n", True),
    ("AND-074", "A.kt", "", "KeyGenParameterSpec.Builder(a, 1).setUserAuthenticationRequired(true)"
                            ".setUserAuthenticationValidityDurationSeconds(3600)\n", True),
    ("AND-075", "A.kt", "val x = settings.javaScriptEnabled = true\n",
     "object : WebViewClient() {\noverride fun shouldOverrideUrlLoading(v: WebView?, r: WebResourceRequest?): "
     "Boolean {\nreturn false\n}\n}\n", True),
    ("AND-076", "A.kt", "", 'val e = EditText(c).apply { hint = "Password" }\n', True),
]


class AndroidLinearTime(unittest.TestCase):
    def test_thousands_of_sites_in_one_file(self):
        rules = {r.id: r for r in engine.load_rules()}
        tmp = tempfile.mkdtemp()
        try:
            for rule_id, name, prefix, unit, reports in CASES:
                with self.subTest(rule=rule_id):
                    root = tempfile.mkdtemp(dir=tmp)
                    src = os.path.join(root, "app/src/main/java")
                    os.makedirs(src)
                    with open(os.path.join(root, "app/src/main/AndroidManifest.xml"), "w") as fh:
                        fh.write(MANIFEST)
                    count = 200_000 // len(unit)
                    body = "".join(unit.replace("{n}", str(i)) for i in range(count))
                    with open(os.path.join(src, name), "w") as fh:
                        fh.write(prefix + body)
                    files = safety.walk(root)
                    project = Project(root=root, platforms=detect.platforms(files), files=files)
                    start = time.monotonic()
                    findings = engine.run(project, [rules[rule_id]], profile.make("banking", "flag"))
                    self.assertLess(time.monotonic() - start, 3.0)
                    self.assertEqual(bool(findings), reports)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
