# SPDX-License-Identifier: Apache-2.0
"""Crafted files from the 0.6.1 and 0.6.2 safety audits: each one made a full scan quadratic (or worse) in the
release before."""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import cli, fix

N = 200_000

# Enough of a project that every rule runs: an Android app module, an iOS app, a Flutter package.
ANDROID = {"app/build.gradle": "plugins { id 'com.android.application' }\n",
           "app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                                               '<uses-permission android:name="android.permission.INTERNET"/>'
                                               '<application/></manifest>\n'}
IOS = {"App/Info.plist": '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                         "<key>CFBundleIdentifier</key><string>a.b</string></dict></plist>\n"}
FLUTTER = {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n"}
KMP = {"settings.gradle.kts": 'include(":shared")\n',
       "shared/build.gradle.kts": 'plugins { kotlin("multiplatform") }\nkotlin { androidTarget(); iosArm64() }\n'}
COMMON = "shared/src/commonMain/kotlin/a/A.kt"


def rep(text: str) -> str:
    return text * (N // len(text))


CASES = [  # (what, {path: text}); each was 25 s to hours at this size
    ("Swift raw-string #", {**IOS, "App/A.swift": "#" * N}),
    ("Math.random on one line", {**ANDROID, "app/src/main/java/a/A.java":
                                 "class A { void f() { " + "Math.random(" * (N // 12)}),
    ("Random( on one line in Dart", {**FLUTTER, "lib/a.dart": "void f() { " + "Random(" * (N // 7)}),
    ("unclosed Cipher.getInstance", {**ANDROID, "app/src/main/java/a/A.kt": "Cipher.getInstance(\n" * (N // 20)}),
    ("nested Cipher.getInstance", {**ANDROID, "app/src/main/java/a/A.kt": "Cipher.getInstance(" * (N // 20)
                                   + ")" * (N // 20)}),
    ("spaces after a Gradle name", {**ANDROID, "app/build.gradle": "plugins { id 'com.android.application' }\na"
                                                                    + " " * N}),
    ("blank lines in an xcconfig", {**IOS, "App/A.swift": "import UIKit\n", "App/Config.xcconfig": "\n" * N
                                                                                                 + "$(TEAM_ID)"}),
    # 0.6.2
    ("xcconfig include fan-out", {**IOS, "App/A.swift": "import UIKit\n",
                                  **{f"App/F{k}.xcconfig": f'#include "F{k + 1}.xcconfig"\n' * 6 for k in range(9)}}),
    ("a self-including 200 KB xcconfig", {**IOS, "App/A.swift": "import UIKit\n",
                                          "App/Base.xcconfig": '#include "Base.xcconfig"\n'
                                                               + "".join(f"K{i} = v{i}\n" for i in range(N // 12)),
                                          "App/Release.xcconfig": '#include "Base.xcconfig"\n' * 600}),
    ("FLT-008 folded build commands", {**FLUTTER, ".github/workflows/a.yml": "jobs:\n  b:\n    steps:\n"
                                       "      - run: >\n" + rep("          flutter build apk\n")}),
    ("FLT-001 callback references", {**FLUTTER, "lib/a.dart": rep("c.badCertificateCallback = f;\n")}),
    ("FLT-002 setString with constants", {**FLUTTER, "lib/a.dart": "SharedPreferences p;\n"
                                                                   + rep("p.setString(kTokenKey, t);\n")}),
    ("FLT-003 nested PrettyDioLogger", {**FLUTTER, "lib/a.dart": rep("PrettyDioLogger(responseBody: false, ")
                                                                 + ")" * (N // 37)}),
    ("FLT-004 nested settings", {**FLUTTER, "lib/a.dart": rep("InAppWebViewSettings(allowFileAccess: true, ")
                                                          + ")" * (N // 44)}),
    ("FLT-005 nested handlers", {**FLUTTER, "lib/a.dart": rep("onReceivedSslError: (c, e) { ") + "e.proceed();"
                                                          + "}" * (N // 29)}),
    ("KMP-004 nested Logging blocks", {**KMP, COMMON: "Logging LogLevel\n" + rep("install(Logging) { ")
                                                      + "level = LogLevel.BODY" + "}" * (N // 19)}),
    ("AND putString with many constants", {**ANDROID, "app/src/main/java/a/A.kt": "class A { fun f(p: Prefs) {\n"
                                           + "".join(f"p.putString(k{i}.v{i}, x)\n" for i in range(N // 28)) + "} }"}),
    ("KMP-006 settings writes", {**KMP, COMMON: "import com.russhwolf.settings.Settings\nval s = Settings()\n"
                                                + rep("prefs.putString(kToken, v)\n")}),
]


class CraftedAudit(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_crafted_files_scan_fast(self):
        for what, files in CASES:
            with self.subTest(what=what):
                root = os.path.join(self.root, str(len(os.listdir(self.root))))
                for rel, text in files.items():
                    path = os.path.join(root, rel)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(text)
                start = time.monotonic()
                cli.scan(root, cli_type="banking", allow_prompt=False)
                self.assertLess(time.monotonic() - start, 3.0)

    def test_fix_on_a_crafted_manifest_is_fast(self):
        # 0.6.1 walked back over every comment for every attribute: hours on this 160 KB file.
        manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android"><x>'
                    + "<!-- <c> -->\n" * 4000 + 'android:debuggable="true"\n' * 4000
                    + '</x><application android:debuggable="true"/></manifest>')
        start = time.monotonic()
        out = fix.remove_debuggable(manifest)
        self.assertLess(time.monotonic() - start, 3.0)
        self.assertIn("<application/>", out)
        self.assertEqual(out.count("debuggable"), 4000)            # text content is never edited

if __name__ == "__main__":
    unittest.main()
