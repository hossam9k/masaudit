# SPDX-License-Identifier: Apache-2.0
"""Crafted worst cases for the React Native and Expo evidence the Android and iOS rules read (rn_expo.py).

Each case is a 200 KB file shaped to make a JS scan walk the rest of the file per match (unclosed or nested
calls, repeated props, long identifiers). Every rule must still finish in under 3 seconds.
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
PKG = ('{"name": "bank", "dependencies": {"react-native": "0.76.0", "expo": "~52.0.0", '
       '"react-native-keychain": "10.0.0", "expo-secure-store": "~14.0.0", "react-native-webview": "13.12.0"}}')
MANIFEST = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bank.app">'
            '<uses-permission android:name="android.permission.INTERNET"/><application/></manifest>')
XCODE = "ios/Bank/AppDelegate.swift"
JS = "src/a.ts"
KC = "import * as Keychain from 'react-native-keychain';\nimport * as SecureStore from 'expo-secure-store';\n"
WV = "import { WebView } from 'react-native-webview';\n"


def rep(unit: str) -> str:
    return unit * (N // len(unit))


CASES = [  # (rule, files)
    ("AND-007", {JS: rep("initializeSslPinning(")}),
    ("AND-008", {JS: rep("initializeSslPinning({")}),
    ("AND-008", {JS: "initializeSslPinning({" + rep("'a': {publicKeyHashes: [") + "})"}),
    ("IOS-006", {JS: "initializeSslPinning({" + rep("a" * 300 + ": {") + "})"}),
    ("IOS-007", {JS: "import { fetch } from 'react-native-ssl-pinning';\n" + rep("sslPinning ")}),
    ("IOS-009", {JS: KC + rep("Keychain.setGenericPassword(")}),
    ("IOS-009", {JS: KC + rep("SecureStore.setItemAsync(k, v, {")}),
    ("IOS-009", {JS: KC + "if (__DEV__) {\n" + rep("x = { accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED };\n")}),
    ("IOS-009", {JS: KC + "Keychain.setGenericPassword(" * 7000 + ")" * 7000}),
    ("AND-008", {JS: "initializeSslPinning(" * 9000 + ")" * 9000}),
    ("IOS-008", {JS: KC + rep("keychainAccessible: SecureStore.ALWAYS,")}),
    ("AND-013", {"src/a.tsx": WV + rep("<WebView webviewDebuggingEnabled />\n")}),
    ("IOS-014", {"src/a.tsx": WV + rep("<WebView webviewDebuggingEnabled={") + "true"}),
    ("AND-011", {"src/a.tsx": WV + rep("<AWebView mixedContentMode=\"always\" ")}),
    ("IOS-030", {JS: rep("AppState.addEventListener(") + "x"}),
    ("IOS-034", {JS: "FileSystem.writeAsStringAsync(x)\n" + rep("FileSystem.documentDirectory + '")}),
    ("AND-027", {"android/app/build.gradle": "android {\nbuildTypes {\nrelease {\n"
                 + rep("minifyEnabled flagA\n") + "}\n}\n}\n" + rep("def flagA = (findProperty('a') ?: false).toBoolean()\n")}),
]


class CraftedReactNative(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files):
        root = tempfile.mkdtemp(dir=self.tmp)
        base = {"package.json": PKG, "android/app/src/main/AndroidManifest.xml": MANIFEST,
                XCODE: "import UIKit\n", "ios/Bank/Info.plist": "<plist><dict><key>UIFileSharingEnabled</key><true/>"
                                                                "</dict></plist>"}
        for rel, text in dict(base, **files).items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        found = safety.walk(root)
        project = Project(root=root, platforms=detect.platforms(found, root), files=found)
        self.assertIn("react-native", project.platforms)
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
