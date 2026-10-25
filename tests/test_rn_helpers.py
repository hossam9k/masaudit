# SPDX-License-Identifier: Apache-2.0
"""The shared React Native helpers: imports, JSX props, literals, package.json, Expo config."""

import json
import os
import shutil
import tempfile
import time
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, engine, lexer, profile, safety
from masaudit.detectors import cross
from masaudit.detectors import reactnative as rn
from masaudit.model import Project


def _strip(code):
    return lexer.strip(code, "js"), lexer.strip(code, "js", keep_strings=False)


class Imports(unittest.TestCase):
    def test_import_forms(self):
        code = ("import AsyncStorage from '@react-native-async-storage/async-storage';\n"
                "import { MMKV, type Mode as M } from 'react-native-mmkv'\n"
                "import * as SecureStore from \"expo-secure-store\";\n"
                "import Config, { API_KEY as key } from 'react-native-config'\n"
                "const Clipboard = require('@react-native-clipboard/clipboard')\n"
                "const { WebView, WebViewMessageEvent: Msg } = require('react-native-webview')\n")
        got = rn.imports(code)
        self.assertEqual(got["AsyncStorage"], ("@react-native-async-storage/async-storage", "default"))
        self.assertEqual(got["MMKV"], ("react-native-mmkv", "MMKV"))
        self.assertEqual(got["M"], ("react-native-mmkv", "Mode"))
        self.assertEqual(got["SecureStore"], ("expo-secure-store", "*"))
        self.assertEqual(got["Config"], ("react-native-config", "default"))
        self.assertEqual(got["key"], ("react-native-config", "API_KEY"))
        self.assertEqual(got["Clipboard"], ("@react-native-clipboard/clipboard", "default"))
        self.assertEqual(got["Msg"], ("react-native-webview", "WebViewMessageEvent"))
        self.assertEqual(rn.names_from(code, "react-native-mmkv", imported=("MMKV",)), ["MMKV"])


class Jsx(unittest.TestCase):
    def test_props(self):
        code, blank = _strip(
            "return <WebView\n  source={{ uri: url }}\n  originWhitelist={['*']}\n  allowFileAccess\n"
            "  mixedContentMode=\"always\"\n  onMessage={(e) => { if (x) { go(e) } }}\n  {...rest}\n/>;\n")
        els = list(rn.jsx_elements(code, blank, ["WebView"]))
        self.assertEqual(len(els), 1)
        el = els[0]
        self.assertTrue(el.spread)
        self.assertEqual(rn.literal(el.props["originWhitelist"].text(code)), ["*"])
        self.assertEqual(el.props["allowFileAccess"].kind, "true")
        self.assertEqual(el.props["mixedContentMode"].text(code), "always")
        self.assertIn("go(e)", el.props["onMessage"].text(code))
        self.assertEqual(el.props["source"].text(code).strip(), "{ uri: url }")

    def test_not_jsx(self):
        code, blank = _strip("if (a <WebView) {}\nconst x: Array<WebView> = []\n")
        self.assertEqual(list(rn.jsx_elements(code, blank, ["WebView"])), [])

    def test_crafted_tags_are_linear(self):
        for crafted in ("<WebView " * 100_000, "<WebView a={" * 50_000, "<WebView a=\"" * 50_000,
                        "<WebView " + "a " * 400_000):
            code, blank = _strip(crafted)
            start = time.monotonic()
            list(rn.jsx_elements(code, blank, ["WebView"]))
            self.assertLess(time.monotonic() - start, 3.0, crafted[:20])


class Literals(unittest.TestCase):
    def test_values(self):
        self.assertEqual(rn.literal("'*'"), "*")
        self.assertEqual(rn.literal('["https://*", "about:blank"]'), ["https://*", "about:blank"])
        self.assertEqual(rn.literal("true"), True)
        self.assertEqual(rn.literal(" 30 "), 30)
        self.assertEqual(rn.literal("`plain`"), "plain")
        self.assertIs(rn.literal("`a${b}`"), rn.UNKNOWN)
        self.assertIs(rn.literal("someVar"), rn.UNKNOWN)
        self.assertIs(rn.literal("[a, 'b']"), rn.UNKNOWN)


class Project_(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _ctx(self):
        files = safety.walk(self.root)
        return engine.Context(Project(root=self.root, platforms=detect.platforms(files, self.root), files=files))

    def test_detection_needs_a_react_native_dependency(self):
        self._write("package.json", json.dumps({"dependencies": {"express": "4"}}))
        self._write("index.js", "require('express')\n")
        self.assertNotIn("react-native", self._ctx().project.platforms)        # a Node server isn't RN
        self._write("package.json", json.dumps({"dependencies": {"react-native": "0.76.1"},
                                                "devDependencies": {"jest": "29"}}))
        ctx = self._ctx()
        self.assertIn("react-native", ctx.project.platforms)
        self.assertEqual(rn.package_deps(ctx)["react-native"], "0.76.1")
        self.assertTrue(rn.has_dep(ctx, "jest"))

    def test_expo_config(self):
        self._write("package.json", json.dumps({"dependencies": {"expo": "~52.0.0"}}))
        self._write("app.json", json.dumps({"expo": {"name": "a", "jsEngine": "jsc"}}))
        ctx = self._ctx()
        self.assertIn("react-native", ctx.project.platforms)
        self.assertEqual(rn.expo_config(ctx)["jsEngine"], "jsc")

    def test_broken_json_is_ignored(self):
        self._write("package.json", "{ not json")
        self._write("app.json", "[" * 100_000)
        ctx = self._ctx()
        self.assertEqual(rn.package_deps(ctx), {})
        self.assertEqual(rn.expo_config(ctx), {})

    def test_dependency_sections_only(self):
        # `react-native` as a key outside the dependency sections (a Jest mapper, an override) is not an RN app.
        self._write("package.json", json.dumps({"dependencies": {"express": "4"},
                                                "jest": {"moduleNameMapper": {"react-native": "x"}},
                                                "overrides": {"expo": "1"}}))
        self._write("app.json", json.dumps({"expo": {"name": "a"}}))
        self.assertNotIn("react-native", self._ctx().project.platforms)
        self.assertFalse(detect.depends_on('{"dependencies": ["react-native"]}', "react-native"))
        self.assertFalse(detect.depends_on("[" * 100_000, "react-native"))
        self.assertTrue(detect.depends_on('{"peerDependencies": {"expo": "*"}}', "expo"))

    def test_dev_only_token_write_is_debug_code(self):
        self._write("package.json", json.dumps({"dependencies": {"react-native": "0.76.1"}}))
        self._write("src/a.ts", "import AsyncStorage from '@react-native-async-storage/async-storage';\n"
                                "if (__DEV__) {\n  AsyncStorage.setItem('authToken', t);\n}\n"
                                "AsyncStorage.setItem('refreshToken', r);\n")
        rule = [r for r in engine.load_rules() if r.id == "RN-001"]
        found = {f.location.line: f.scope for f in engine.run(self._ctx().project, rule, profile.make("banking", "flag"))}
        self.assertEqual(found, {3: "debug", 5: "main"})

    def test_template_sdk_versions_resolve_from_the_root_ext_block(self):
        # The React Native template: android/app/build.gradle reads rootProject.ext.minSdkVersion.
        self._write("package.json", json.dumps({"dependencies": {"react-native": "0.79.0"}}))
        self._write("android/build.gradle", "buildscript {\n    ext {\n        minSdkVersion = 26\n"
                                            "        targetSdkVersion = 36\n    }\n}\n")
        self._write("android/app/build.gradle", "android {\n    defaultConfig {\n"
                                                "        minSdkVersion rootProject.ext.minSdkVersion\n"
                                                "        targetSdkVersion rootProject.ext.targetSdkVersion\n    }\n}\n")
        ctx = self._ctx()
        rules = [r for r in engine.load_rules() if r.id in ("AND-028", "AND-029")]
        self.assertEqual(engine.run(ctx.project, rules, profile.make("banking", "flag")), [])
        self.assertFalse([u for u in ctx.project.unknowns if "resolve" in u])

    def test_odd_expo_values_dont_stop_the_scan(self):
        # Untrusted app.json: numbers, objects, and empty lists where Expo expects lists.
        self._write("package.json", json.dumps({"dependencies": {"expo": "~52.0.0", "react-native": "0.76.1"}}))
        rules = engine.load_rules()
        for expo in ({"plugins": 1}, {"plugins": {"a": 1}}, {"plugins": [[]]}, {"plugins": [[1], None, {}]},
                     {"android": {"blockedPermissions": {"a": 1}}}, {"android": {"blockedPermissions": 7}},
                     {"ios": {"infoPlist": []}, "android": [], "plugins": "expo-camera"}):
            with self.subTest(expo=expo):
                self._write("app.json", json.dumps({"expo": {"name": "a", **expo}}))
                ctx = self._ctx()
                engine.run(ctx.project, rules, profile.make("banking", "flag"))


class Scope(unittest.TestCase):
    def test_js_test_folders_hold_only_js_side_files(self):
        self.assertEqual(detect.scope_of("src/__tests__/api.ts"), "test")
        self.assertEqual(detect.scope_of("__mocks__/creds.json"), "test")
        self.assertEqual(detect.scope_of("e2e/flows/login.yaml"), "test")
        # Native code in a package or group that happens to be named like a JS test folder ships.
        self.assertEqual(detect.scope_of("android/app/src/main/java/com/x/e2e/Login.kt"), "main")
        self.assertEqual(detect.scope_of("ios/App/jest/Keys.swift"), "main")

    def test_story_folders_and_source_sets(self):
        # A Stories feature ships, in native and JS code; Storybook's own folder and files don't.
        self.assertEqual(detect.scope_of("feature/stories/src/main/kotlin/com/x/StoriesApi.kt"), "main")
        self.assertEqual(detect.scope_of("Instagram/Stories/StoryUploader.swift"), "main")
        self.assertEqual(detect.scope_of("app/features/stories/storiesApi.ts"), "main")
        self.assertEqual(detect.scope_of(".storybook/preview.tsx"), "debug")
        self.assertEqual(detect.scope_of("src/Button.stories.tsx"), "debug")
        # Lower-case test source sets are tests; an attestation folder is not.
        self.assertEqual(detect.scope_of("app/src/androidtest/java/x/A.kt"), "test")
        self.assertEqual(detect.scope_of("app/src/integrationtest/kotlin/x/A.kt"), "test")
        self.assertEqual(detect.scope_of("app/src/attestation/check.ts"), "main")


class DevGuards(unittest.TestCase):
    def _dev_only(self, code):
        keep, blank = _strip(code)
        return code.index("SINK") in rn.DevGuard(keep, blank)

    def test_negations_and_comparisons(self):
        for code, dev in (("if (!(__DEV__)) { SINK(); }", False),
                          ("if (false === __DEV__) { SINK(); }", False),
                          ("if (true !== global.__DEV__) { SINK(); }", False),
                          ("if ('production' === process.env.NODE_ENV) { SINK(); }", False),
                          ("const a = false === __DEV__ && SINK();", False),
                          ("if (!(__DEV__ && verbose)) { SINK(); }", False),
                          ("const a = ! __DEV__ && SINK();", False),
                          ("if (__DEV__ && verbose) { SINK(); }", True),
                          ("if ((__DEV__)) { SINK(); }", True),
                          ("if (!!__DEV__) { SINK(); }", True),
                          ("const a = __DEV__ && SINK();", True),
                          ("if (!(__DEV__)) { a(); } else { SINK(); }", True),
                          ("function f() { if (!(__DEV__)) return; SINK(); }", True)):
            with self.subTest(code=code):
                self.assertEqual(self._dev_only(code), dev)


class CraftedLiterals(unittest.TestCase):
    def test_deeply_nested_arrays(self):
        self.assertIs(rn.literal("[" * 999 + "]" * 999), rn.UNKNOWN)       # was a RecursionError
        self.assertEqual(rn.literal("[['a'], ['b']]"), [["a"], ["b"]])

    def test_import_after_long_spaces_is_linear(self):
        text = ("import" + " " * 400) * 2500                     # a blanked comment after each `import`: was 96 s
        start = time.monotonic()
        self.assertEqual(rn.imports(text), {})
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertEqual(rn.imports("import   {  a  }   from   'm'")["a"], ("m", "a"))


class MinifiedLines(unittest.TestCase):
    def test_many_imports_on_one_line_are_linear(self):
        text = "x=import;" * 200_000                    # 1.8 MB on one line: was 40 s
        start = time.monotonic()
        self.assertFalse(cross._has_test_import(text))
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertTrue(cross._has_test_import(text + "\nimport org.junit.Test\n"))


if __name__ == "__main__":
    unittest.main()
