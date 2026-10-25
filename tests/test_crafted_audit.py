# SPDX-License-Identifier: Apache-2.0
"""Crafted files from the 0.6.1 safety audit: each one made a full scan quadratic in 0.6.0."""

import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import cli

N = 200_000

# Enough of a project that every rule runs: an Android app module, an iOS app, a Flutter package.
ANDROID = {"app/build.gradle": "plugins { id 'com.android.application' }\n",
           "app/src/main/AndroidManifest.xml": '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                                               '<uses-permission android:name="android.permission.INTERNET"/>'
                                               '<application/></manifest>\n'}
IOS = {"App/Info.plist": '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
                         "<key>CFBundleIdentifier</key><string>a.b</string></dict></plist>\n"}
FLUTTER = {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n"}

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


if __name__ == "__main__":
    unittest.main()
