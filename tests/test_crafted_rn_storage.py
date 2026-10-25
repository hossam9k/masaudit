# SPDX-License-Identifier: Apache-2.0
"""Crafted worst cases for RN-001, RN-002, RN-003, RN-004, and RN-019: each 200 KB input must scan in a few seconds.

A repository masaudit scans can't be trusted. Each case targets a spot that would be quadratic if a detector
searched the whole file once per match: storage keys resolved through constants, MMKV setters, persist configs
named by a variable, react-native-config members, handlers named by interceptors, `__DEV__` look-backs,
package.json dependencies, and JSON configs with many secret-looking entries.
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
PKG = json.dumps({"name": "a", "dependencies": {"react-native": "0.76.1", "react-native-config": "1.5.3",
                                                "expo": "~52.0.0"}})
F = "src/a.ts"
ASYNC = "import AsyncStorage from '@react-native-async-storage/async-storage';\n"


def rep(unit: str, size: int = N) -> str:
    return unit * (size // len(unit))


CASES = [  # (rule, files)
    ("RN-001", {F: ASYNC + "".join(f"const K{i} = 'auth_token';\n" for i in range(3000))
                + rep("AsyncStorage.setItem(K1, t);\n", N - 60_000)}),
    ("RN-001", {F: ASYNC + rep("AsyncStorage.setItem(UNKNOWN_KEY, res.data.value);\n")}),
    ("RN-001", {F: ASYNC + "AsyncStorage.multiSet([" + rep("['a', b], ") + "]);\n"}),
    ("RN-001", {F: ASYNC + "AsyncStorage.setItem(" + rep("(") + "\n"}),
    ("RN-001", {F: "import { MMKV } from 'react-native-mmkv';\n" + rep("const s = new MMKV();\ns.set('jwt', t);\n")}),
    ("RN-001", {F: "import { MMKV } from 'react-native-mmkv';\n" + rep("new MMKV({ id: 'a' }) ")}),
    ("RN-001", {F: ASYNC + "import { persistReducer } from 'redux-persist';\n"
                + "".join(f"const c{i} = {{ key: 'auth', storage: AsyncStorage }};\n" for i in range(2000))
                + rep("persistReducer(c1999, r);\n", N - 100_000)}),
    ("RN-001", {F: ASYNC + "import { persistReducer } from 'redux-persist';\npersistReducer({" + rep("a: [{") + "\n"}),
    ("RN-002", {F: "import Config from 'react-native-config';\n" + rep("x = Config.API_SECRET;\n")}),
    ("RN-002", {F: "import Config from 'react-native-config';\n" + rep("{ a" + "b" * 597) + "} = Config;\n"}),
    ("RN-002", {F: rep("x\n") + "import { " + ", ".join(f"A_SECRET_{i}" for i in range(8000)) + " } from '@env';\n"}),
    ("RN-002", {F: rep("process.env.EXPO_PUBLIC_API_SECRET;\n")}),
    ("RN-002", {"app.config.js": "export default { extra: {" + rep("a:'") + "} };\n"}),
    ("RN-002", {"app.json": json.dumps({"expo": {"extra": {f"k{i}": {"password": "q9Vr2Lx7Tn4Kd8Wm3Hz6Pb"}
                                                           for i in range(5000)}}})}),
    ("RN-002", {"eas.json": json.dumps({"build": {f"p{i}": {"env": {f"S{j}_SECRET": "q9Vr2Lx7Tn4Kd8Wm3Hz6Pb"
                                                                     for j in range(400)}} for i in range(20)}})}),
    ("RN-002", {".env": rep("STRIPE_SECRET_KEY=q9Vr2Lx7Tn4Kd8Wm3Hz6Pb\n")}),
    ("RN-003", {F: "import axios from 'axios';\n" + rep("if (a) { b(); }\n", 60_000)
                + rep("api.interceptors.request.use(h);\n", 140_000) + "function h(c) { console.log(c); return c; }\n"}),
    ("RN-003", {F: rep("api.interceptors.request.use((c) => { console.log(c.url); return c; });\n")}),
    ("RN-003", {F: "import logger from 'redux-logger';\n" + rep("if (__DEV__) { m.push(logger); }\n")}),
    ("RN-003", {F: "import { startNetworkLogging } from 'react-native-network-logger';\n"
                + rep("startNetworkLogging(); ")}),
    ("RN-004", {F: "import RNFetchBlob from 'rn-fetch-blob';\n" + rep("RNFetchBlob.config({ trusty: true });\n")}),
    ("RN-004", {F: "import { fetch } from 'react-native-ssl-pinning';\n" + rep("if (x) { fetch(u, { disableAllSecurity: true }) }\n")}),
    ("RN-019", {"package.json": json.dumps({"name": "a", "dependencies": dict(
        {"react-native": "0.76.1"}, **{f"lib{i}": f"github:acme/lib{i}#main" for i in range(5000)})})}),
    ("RN-019", {"package.json": PKG, ".npmrc": rep("strict-ssl=false\n") + rep("a" * 299 + " " * 300 + "\n", 50_000)}),
    ("RN-019", {"package.json": PKG, ".yarnrc.yml": rep("unsafeHttpWhitelist:\n") + rep("npmAuthToken: x\n", 40_000)}),
]


class CraftedRnStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, files):
        root = tempfile.mkdtemp(dir=self.tmp)
        files = dict({"package.json": PKG}, **files)
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
        for i, (rule_id, files) in enumerate(CASES):
            with self.subTest(rule=rule_id, case=i):
                self.assertLess(self._run(rule_id, files), 3.0)


if __name__ == "__main__":
    unittest.main()
