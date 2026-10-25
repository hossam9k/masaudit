# SPDX-License-Identifier: Apache-2.0
"""Crafted worst cases for the React Native build rules (RN-014 to RN-018): each 200 KB input must scan fast.

A repository masaudit scans can't be trusted. These files aim at the loops in rn_build.py: the __DEV__ guard
index (nested and unclosed `if (__DEV__)` blocks, chains of `__DEV__ &&`, `if (!__DEV__) return`), the
console count, the Reactotron loader search across many files, and the Gradle and Podfile scans.
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
PKG = '{"name": "app", "dependencies": {"react-native": "0.81.4", "expo-updates": "~29.0.0", ' \
      '"reactotron-react-native": "5.1.14", "remote-redux-devtools": "0.5.16"}}'
BABEL = "module.exports = { presets: ['module:@react-native/babel-preset'] };\n"


def rep(unit: str) -> str:
    return unit * (N // len(unit))


CASES = [  # (rule, files)
    ("RN-015", {"src/a.js": rep("if (__DEV__) { console.log(a);\n")}),
    ("RN-015", {"src/a.js": rep("if (__DEV__) console.log(a) ")}),
    ("RN-015", {"src/a.js": rep("__DEV__ && __DEV__ && console.log(a) ")}),
    ("RN-015", {"src/a.js": "function f() {\n" + rep("if (!__DEV__) return;\nconsole.log(a);\n") + "}\n"}),
    ("RN-015", {"src/a.js": rep("if (!__DEV__) x ")}),
    ("RN-015", {"src/a.js": rep("if (!__DEV__) {} else { console.debug(b) ")}),
    ("RN-015", {"src/a.js": rep("if (process.env.NODE_ENV !== 'production' && (") + "\nconsole.log(1)\n"}),
    ("RN-015", {"src/a.js": rep("x = process.env.NODE_ENV !== 'production' ? console.log(a) : (")}),
    ("RN-015", {"src/a.js": rep("console.log = console.log = ")}),
    ("RN-015", {f"src/f{i}.js": "console.log(1)\n" for i in range(2000)}),
    ("RN-018", {"index.js": "import Reactotron from 'reactotron-react-native'\n" + rep("if (__DEV__) { Reactotron.configure().connect(\n")}),
    ("RN-018", {"index.js": "import Reactotron from 'reactotron-react-native'\n" + rep("Reactotron.configure()" + " " * 1400 + ".connect(\n")}),
    ("RN-018", {"src/s.js": "import { composeWithDevTools } from 'remote-redux-devtools'\n" + rep("__DEV__ && composeWithDevTools(")}),
    ("RN-018", dict({f"src/R{i}.js": "import Reactotron from 'reactotron-react-native'\nReactotron.configure().connect()\n"
                     for i in range(1000)},
                    **{f"src/u{i}.js": "".join(f"import './R{k}'\n" for k in range(i, i + 20)) for i in range(1000)})),
    ("RN-018", {"eas.json": '{"build": {' + ",".join(f'"p{i}": {{"extends": "p{i + 1}"}}' for i in range(N // 30))
                + ', "production": {"extends": "p0"}}}'}),
    ("RN-016", {"android/app/build.gradle": rep("project.ext.react = [ enableHermes: true, ")}),
    ("RN-016", {"ios/Podfile": rep(":hermes_enabled => false # ") + "\n", "android/gradle.properties": rep("hermesEnabled=false\n"),
                "android/settings.gradle": "include ':app'\n"}),
    ("RN-017", {"android/app/build.gradle": rep('from "a.map"\n')}),
    ("RN-017", {"android/app/build.gradle": rep('assets.srcDirs += "x" ') + "\n" + rep('from "a.map" into "y" ')}),
    ("RN-017", {"android/bundle.sh": rep("--sourcemap-output android/app/src/main/assets/a.map ")}),
    ("RN-017", {"ios/A.xcodeproj/project.pbxproj": rep("/* main.jsbundle.map in Resources */ ")}),
    ("RN-014", {"app.config.js": rep("updates: { url: 'http://x', ") + "\n"}),
    ("RN-014", {"app.json": '{"expo": {"updates": {"url": "https://u.expo.dev/x"}, "a": "' + "x" * N + '"}}'}),
]


class CraftedRnBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files):
        root = tempfile.mkdtemp(dir=self.tmp)
        files = dict({"package.json": PKG, "babel.config.js": BABEL}, **files)
        for rel, text in files.items():
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
        for k, (rule_id, files) in enumerate(CASES):
            with self.subTest(rule=rule_id, case=k):
                self.assertLess(self._run(rule_id, files), 3.0)


if __name__ == "__main__":
    unittest.main()
