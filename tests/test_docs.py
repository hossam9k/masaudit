# SPDX-License-Identifier: Apache-2.0
"""The numbers and tables in README.md and docs/ match the code, so they can't quietly go stale."""

import collections
import json
import os
import re
import unittest

from helpers import scan_dir  # noqa: F401  (sets sys.path)
from masaudit import __version__, cli, engine, profile
from masaudit.report import terminal

ROOT = os.path.join(os.path.dirname(__file__), "..")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


README = read("README.md")
README_FLAT = " ".join(README.split())          # prose checks ignore where lines wrap


class ReadmeNumbers(unittest.TestCase):
    def test_rule_counts(self):
        rules = [r for r in engine.load_rules() if not r.retired]
        by = collections.Counter(r.platform for r in rules)
        m = re.search(r"(\d+) rules: (\d+) Android, (\d+) iOS, (?:(\d+) React Native, )?(\d+) cross-platform code, "
                      r"(\d+) Flutter, (\d+) CI and supply chain, (\d+) Kotlin\s+Multiplatform", README_FLAT)
        self.assertIsNotNone(m, "README rule-count sentence not found")
        found = [int(x) if x is not None else 0 for x in m.groups()]
        self.assertEqual(found, [len(rules), by["android"], by["ios"], by["react-native"], by["cross"], by["flutter"],
                                 by["ci"], by["kmp"]])

    def test_owasp_coverage(self):
        rules = engine.load_rules()
        with open(os.path.join(ROOT, "src/masaudit/rules/_maswe.json"), encoding="utf-8") as fh:
            catalog = json.load(fh)
        maswe = {r.maswe for r in rules if r.maswe and not r.retired}
        mastg = {t for r in rules for t in r.mastg if t.startswith("MASTG-TEST")}
        self.assertIn(f"{len(maswe)} of the {len(catalog)} weaknesses", README_FLAT)
        self.assertIn(f"cite {len(mastg)} OWASP MASTG tests", README_FLAT)

    def test_demo_app_table(self):
        demo = os.path.join(ROOT, "examples", "acme-wallet")
        rows = {}
        for app_type in ("banking", "news"):
            counts = collections.Counter(
                f.bucket for f in cli.scan(demo, cli_type=app_type, allow_prompt=False).findings)
            rows[app_type] = [counts["fix-before-release"], counts["fix-soon"], counts["check-by-hand"],
                              counts["hardening"], counts["not-needed"]]
        table = {}
        for label in ("Fix before release", "Fix soon", "Check by hand",
                      "Hardening checklist", "Not needed for your app"):
            m = re.search(r"^\| " + re.escape(label) + r"[^|]* \| (\d+) \| (\d+)", README, re.M)
            self.assertIsNotNone(m, label)
            table[label] = (int(m.group(1)), int(m.group(2)))
        self.assertEqual([t[0] for t in table.values()], rows["banking"])
        self.assertEqual([t[1] for t in table.values()], rows["news"])

    def test_versions(self):
        for rel, pattern in (("plugin/.claude-plugin/plugin.json", r'"version": "([^"]+)"'),
                             ("plugin/skills/masaudit/SKILL.md", r'version: "([^"]+)"'),
                             ("CITATION.cff", r"^version: (\S+)")):
            with self.subTest(file=rel):
                self.assertEqual(re.search(pattern, read(rel), re.M).group(1), __version__)
        for rel in ("README.md", "docs/ci.md", "docs/team.md"):
            text = read(rel)
            for found in re.findall(r"(?:# v|rev: v|masaudit |masaudit==)(\d+\.\d+\.\d+)", text):
                with self.subTest(file=rel):
                    self.assertEqual(found, __version__)


    def test_documented_commands_parse(self):
        # Every masaudit command in a code block of the docs is one the real parser accepts: a wrong option or
        # format name (`--format markdown`) would fail the reader's CI with exit code 2.
        import contextlib
        import glob
        import io
        import itertools
        import shlex
        prefixes = {"-m", "run", "uvx", "run:", "script:", "-", "content:", "|"}
        names = {"masaudit", "masaudit.pyz", "dist/masaudit.pyz"}
        files = ["README.md"] + sorted(os.path.relpath(f, ROOT) for f in glob.glob(os.path.join(ROOT, "docs", "*.md")))
        checked = 0
        for rel in files:
            for block in re.findall(r"```(?:bash|sh|shell|console|yaml)\n(.*?)```", read(rel), re.S):
                text = re.sub(r"\\\n\s*", " ", block).replace('"', " ").replace("'", " ")
                for line in text.splitlines():
                    for part in re.split(r"&&|;|\|\||\|(?!\|)", line):
                        try:
                            tokens = shlex.split(part)
                        except ValueError:
                            continue
                        for i, tok in enumerate(tokens):
                            if tok not in names or (i and tokens[i - 1] not in prefixes and not tokens[i - 1].startswith("python")):
                                continue
                            args = list(itertools.takewhile(lambda a: not a.startswith("#"), tokens[i + 1:]))
                            if any("[" in a or "<" in a for a in args):
                                continue                      # a usage line: `masaudit [PATH] [options]`
                            with self.subTest(file=rel, command=part.strip()), \
                                    contextlib.redirect_stderr(io.StringIO()):
                                try:
                                    cli.build_parser().parse_args(args)
                                except SystemExit as e:
                                    self.fail(f"masaudit {' '.join(args)}: exit {e.code}")
                            checked += 1
        self.assertGreater(checked, 10)


class TerminalSamples(unittest.TestCase):
    """The terminal output shown in README.md and the tutorial is what the demo app really prints."""

    def _blocks(self, rel):
        return [b for b in re.findall(r"```text\n(.*?)```", read(rel), re.S) if "Fix before release:" in b]

    def _real_output(self, block):
        demo = os.path.join(ROOT, "examples", "acme-wallet")
        app_type = re.search(r"Profile:\s+(\S+)", block).group(1)
        res = cli.scan(demo, cli_type=app_type, cfg={}, allow_prompt=False)
        if "from your answer" in block:
            res.profile.source = "prompt"
        return terminal.render(res, report_path=os.path.join(demo, "SECURITY-AUDIT.md"), color=False)

    def test_samples_match_the_demo_app(self):
        for rel in ("README.md", "docs/getting-started.md"):
            blocks = self._blocks(rel)
            self.assertTrue(blocks, rel)
            for block in blocks:
                # Windows prints the report path with backslashes; the samples use forward slashes.
                out = self._real_output(block).replace("\\", "/").splitlines()
                for line in block.splitlines():
                    if not line.strip() or line.startswith("$ ") or line.strip() == "...":
                        continue
                    # "..." in a sample stands for a shortened path or a cut-off line end.
                    pattern = ".*".join(re.escape(part) for part in line.rstrip().split("...")) + ".*"
                    with self.subTest(file=rel, line=line):
                        self.assertTrue(any(re.fullmatch(pattern, o.rstrip()) for o in out), line)


class UsageGuide(unittest.TestCase):
    def test_app_type_table_matches_the_code(self):
        usage = read("docs/app-type.md")
        rows = dict(re.findall(r"^\| `([a-z-]+)` \| [^|]+ \| ([^|]+) \|$", usage, re.M))
        self.assertEqual(set(rows), set(profile.APP_TYPES))
        for key, (profiles, description) in profile.APP_TYPES.items():
            with self.subTest(app_type=key):
                self.assertEqual(rows[key].strip(), ", ".join(p for p in ("L1", "L2", "R", "P") if p in profiles))
                self.assertIn(f"| `{key}` | {description} |", usage)



REPO_URL = "https://github.com/hossam9k/masaudit/"
RAW_URL = "https://raw.githubusercontent.com/hossam9k/masaudit/main/"


def _slug(heading):
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(rel):
    text = read(rel)
    text = re.sub(r"```.*?```", "", text, flags=re.S)          # headings in code blocks don't count
    return {_slug(h) for h in re.findall(r"^#{1,6} (.+)$", text, re.M)}


class Links(unittest.TestCase):
    """Every link from the README and docs/ to this repository points to a file and heading that exist."""

    def test_links_resolve(self):
        sources = ["README.md"] + ["docs/" + n for n in sorted(os.listdir(os.path.join(ROOT, "docs")))
                                   if n.endswith(".md") and not n.startswith("sample-report")]
        for src in sources:
            for target in re.findall(r"\]\(([^)\s]+)\)", read(src)):
                if target.startswith(REPO_URL):
                    rest = target[len(REPO_URL):]
                    if rest.startswith("#"):
                        path, anchor = "README.md", rest[1:]
                    elif rest.startswith(("blob/main/", "tree/main/")):
                        path, _, anchor = rest[len("blob/main/"):].partition("#")
                    else:
                        continue                                  # releases, issues, sponsors
                elif target.startswith(RAW_URL):
                    path, anchor = target[len(RAW_URL):], ""            # images such as docs/demo.gif
                elif target.startswith(("http:", "https:", "mailto:")):
                    continue
                else:
                    base, _, anchor = target.partition("#")
                    path = os.path.normpath(os.path.join(os.path.dirname(src), base)) if base else src
                with self.subTest(source=src, link=target):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, path)), f"missing file {path}")
                    if anchor and path.endswith(".md"):
                        self.assertIn(anchor, _anchors(path), f"no heading #{anchor} in {path}")

if __name__ == "__main__":
    unittest.main()
