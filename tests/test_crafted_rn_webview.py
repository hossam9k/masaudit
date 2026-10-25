# SPDX-License-Identifier: Apache-2.0
"""Crafted React Native files for the react-native-webview rules (RN-005 to RN-008).

A repository masaudit scans can't be trusted, so a 200 KB file built to hit a rule's worst case must still scan
in a few seconds. Each case is a shape that would be quadratic if a lookup rescanned the file per WebView, per
handler, or per script: many WebViews, nested tags and calls, unclosed brackets, and long scripts.
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
PACKAGE = '{"name": "app", "dependencies": {"react-native": "0.76.1", "react-native-webview": "13.12.0"}}'
HEAD = "import { WebView } from 'react-native-webview';\n"
RULES = ("RN-005", "RN-006", "RN-007", "RN-008")


def rep(unit: str) -> str:
    return unit * (N // len(unit))


def many(fmt: str) -> str:
    """fmt with {i} filled in, repeated until the text is about N characters."""
    out, size, i = [], 0, 0
    while size < N:
        s = fmt.format(i=i)
        out.append(s)
        size += len(s)
        i += 1
    return "".join(out)


CASES = [
    # Each WebView has its own variable, handler, and script: every lookup must use the per-file index.
    many("const {{ u{i} }} = route.params;\nconst h{i} = (e) => {{ JSON.parse(e.nativeEvent.data); }};\n"
         "const s{i} = `document.title='${{n{i}}}'`;\n<WebView source={{{{ uri: u{i} }}}} originWhitelist={{['*']}} "
         "onMessage={{h{i}}} injectedJavaScript={{s{i}}} allowFileAccess />\n"),
    # Many WebViews whose handler names a function that never closes.
    "const h = useCallback((e) => {\n" + rep("<WebView source={{ uri: url }} onMessage={h} />\n"),
    # Tags nested in the source prop, and tags that never close.
    rep("<WebView source={") + rep("}"),
    rep("<WebView source={{ uri: "),
    rep("<WebView originWhitelist={['*'] "),
    # A source object with many keys, and many objects.
    rep("<WebView source={{ " + "a: 1, " * 400 + "uri: x }} />\n"),
    rep("<WebView source={{ a: [1, {b: (2)}], " + "c: `${d}`, " * 50 + "html: `${e}` }} />\n"),
    # Scripts: nested injectJavaScript calls, many interpolations, quotes that never close.
    rep(".injectJavaScript(") + rep(")"),
    rep("ref.current.injectJavaScript(`'${a}${b}${c}${d}'`);\n"),
    "ref.current.injectJavaScript(`" + rep("'${a}") + "`);\n",
    rep("<WebView injectedJavaScript={`\"${x.y}\" + '${z}'`} />\n"),
    rep("x.injectJavaScript('a' + b + 'c' + d + 'e');\n"),
    # __DEV__ blocks around WebViews, and many that never close.
    rep("if (__DEV__) { <WebView allowFileAccess /> }\n"),
    rep("if (__DEV__) {\n<WebView allowFileAccess />\n"),
    # Declarations, destructuring, and state the RN-007 lookups index.
    rep("const { a, b: c, d = 1 } = route.params; const [u, setU] = useState(); setU(p); onChangeText={setP}\n")
    + "<WebView source={{ uri: u }} />\n",
    rep("const {") + "\n<WebView source={{ uri: u }} />\n",
    rep("isUrl") + "\n<WebView source={{ uri: route.params.u }} />\n",
]


class CraftedRnWebView(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, rule_id, body):
        root = tempfile.mkdtemp(dir=self.tmp)
        os.makedirs(os.path.join(root, "src"))
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as fh:
            fh.write(PACKAGE)
        with open(os.path.join(root, "src", "Screen.tsx"), "w", encoding="utf-8") as fh:
            fh.write(HEAD + body)
        found = safety.walk(root)
        platforms = detect.platforms(found, root)
        self.assertIn("react-native", platforms)
        project = Project(root=root, platforms=platforms, files=found)
        rule = next(r for r in engine.load_rules() if r.id == rule_id)
        start = time.monotonic()
        engine.run(project, [rule], profile.make("banking", "flag"))
        return time.monotonic() - start

    def test_crafted_files_scan_fast(self):
        for n, body in enumerate(CASES):
            for rule_id in RULES:
                with self.subTest(case=n, rule=rule_id):
                    self.assertLess(self._run(rule_id, body), 3.0)


if __name__ == "__main__":
    unittest.main()
