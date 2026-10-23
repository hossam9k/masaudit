# SPDX-License-Identifier: Apache-2.0
"""The stdlib-only workflow YAML reader: structure, scalars, and exact line numbers."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit.parsers import workflows as wf
from masaudit.parsers.workflows import Map, Scalar, Seq


class Load(unittest.TestCase):
    def test_block_scalar_keeps_lines_and_hash_text(self):
        doc = wf.load("a:\n  run: |\n    echo one\n    # still script\n\n    echo two\n  next: x\n")
        run = doc["a"]["run"]
        self.assertEqual(run, "echo one\n# still script\n\necho two")
        self.assertEqual(run.line, 2)
        self.assertEqual(run.line_map, [3, 4, 5, 6])
        self.assertEqual(doc["a"]["next"], "x")

    def test_folded_and_chomping_indicators(self):
        doc = wf.load("a: >-\n  one\n  two\nb: |+\n  keep\nc: |2\n    indented\n")
        self.assertEqual(doc["a"], "one\ntwo")
        self.assertEqual(doc["a"].line_map, [2, 3])
        self.assertEqual(doc["b"], "keep")
        self.assertEqual(doc["c"], "  indented")

    def test_flow_collections(self):
        doc = wf.load('on: [push, "pull_request_target"]\nx: { a: [1, 2], b: "c, d" }\ny: [\n  one,\n  two\n]\nz: []\n')
        self.assertEqual(doc["on"], ["push", "pull_request_target"])
        self.assertIsInstance(doc["x"], Map)
        self.assertEqual(doc["x"]["a"], ["1", "2"])
        self.assertEqual(doc["x"]["b"], "c, d")
        self.assertEqual(doc["y"], ["one", "two"])
        self.assertEqual(doc["z"], [])

    def test_comments_and_quotes(self):
        doc = wf.load("a: plain # comment\nb: \"has # hash\"\nc: 'it''s'\nd: \"q\\\"uote\"\n# whole line\ne: x#not-a-comment\n")
        self.assertEqual(doc["a"], "plain")
        self.assertEqual(doc["b"], "has # hash")
        self.assertEqual(doc["c"], "it's")
        self.assertEqual(doc["d"], 'q"uote')
        self.assertEqual(doc["e"], "x#not-a-comment")

    def test_sequence_at_key_indent_and_inline_maps(self):
        doc = wf.load("steps:\n- uses: a/b@v1\n  with:\n    k: v\n- run: echo\n- plain\n")
        steps = doc["steps"]
        self.assertIsInstance(steps, Seq)
        self.assertEqual(steps[0]["uses"], "a/b@v1")
        self.assertEqual(steps[0]["uses"].line, 2)
        self.assertEqual(steps[0]["with"]["k"], "v")
        self.assertEqual(steps[1]["run"], "echo")
        self.assertEqual(steps[2], "plain")

    def test_anchors_aliases_urls_and_quoted_keys(self):
        doc = wf.load('base: &defaults\n  a: 1\nother: *defaults\nurl: https://h:8080/p\n"on": push\n')
        self.assertEqual(doc["base"]["a"], "1")
        self.assertEqual(doc["other"], "*defaults")
        self.assertEqual(doc["url"], "https://h:8080/p")
        self.assertEqual(doc["on"], "push")

    def test_never_raises(self):
        for text in ("", "---\n", "\t- : [\n", "a: [unclosed\n", "- - -\n", "key: |\n", ":\n"):
            wf.load(text)
        self.assertIsNone(wf.load(""))
        self.assertIsNone(wf.parse_workflow("- just\n- a list\n"))


class ParseWorkflow(unittest.TestCase):
    TEXT = """name: ci
on:
  pull_request_target:
    types: [opened]
  push:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@v4 # v4
        with:
          persist-credentials: false
      - run: |
          echo "${{ github.event.pull_request.title }}"
        env:
          A: b
  reuse:
    uses: org/repo/.github/workflows/x.yml@main
"""

    def test_structure_and_lines(self):
        w = wf.parse_workflow(self.TEXT)
        self.assertEqual(w.triggers, {"pull_request_target": 3, "push": 5})
        self.assertEqual(w.permissions, "write-all")
        self.assertEqual(w.permissions_line, 6)
        self.assertEqual(w.jobs_line, 7)
        build, reuse = w.jobs
        self.assertEqual(build.id, "build")
        self.assertEqual(dict(build.permissions), {"contents": "read"})
        checkout, script = build.steps
        self.assertEqual(checkout.name, "Checkout")
        self.assertEqual((checkout.uses, checkout.uses.line), ("actions/checkout@v4", 14))
        self.assertEqual(checkout.with_["persist-credentials"], "false")
        self.assertEqual(checkout.with_.key_lines["persist-credentials"], 16)
        self.assertIn("github.event.pull_request.title", script.run)
        self.assertEqual(script.run.line_map, [18])
        self.assertEqual(script.env["A"], "b")
        self.assertEqual((reuse.uses, reuse.uses.line), ("org/repo/.github/workflows/x.yml@main", 22))
        self.assertIsNone(reuse.permissions)

    def test_trigger_forms(self):
        self.assertEqual(list(wf.parse_workflow("on: push\njobs: {}\n").triggers), ["push"])
        self.assertEqual(list(wf.parse_workflow("on: [push, pull_request]\n").triggers), ["push", "pull_request"])
        w = wf.parse_workflow("name: x\njobs:\n  a:\n    steps: []\n")
        self.assertEqual(w.triggers, {})
        self.assertIsNone(w.permissions)
        self.assertEqual(w.jobs[0].steps, [])

    def test_empty_permissions_is_not_absent(self):
        w = wf.parse_workflow("on: push\npermissions: {}\njobs: {}\n")
        self.assertIsInstance(w.permissions, Map)
        self.assertEqual(len(w.permissions), 0)
        self.assertIsInstance(wf.load("a: b\n")["a"], Scalar)


if __name__ == "__main__":
    unittest.main()
