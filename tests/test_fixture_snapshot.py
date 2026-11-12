# SPDX-License-Identifier: Apache-2.0
"""Every rule against every fixture: a changed count anywhere fails, with a per-rule diff.

test_rules checks each rule on its own fixtures only. This catches the other direction: a new or changed rule
that starts firing on another rule's fixtures (a new false alarm), or stops firing there (a lost finding). The
expected counts live in fixture_snapshot.json, one entry per fixture folder with the rules that fire there.

After a change you meant to make, check every line of the diff, then regenerate:

    python3 tests/test_fixture_snapshot.py --write
"""

import json
import os
import sys
import unittest
from collections import Counter

from helpers import FIXTURES, scan_dir

SNAPSHOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture_snapshot.json")


def current() -> dict:
    """{"RULE-ID/variant": {"rule id": hits}} for every fixture folder, with every rule enabled."""
    out = {}
    for rule_id in sorted(os.listdir(FIXTURES)):
        base = os.path.join(FIXTURES, rule_id)
        if not os.path.isdir(base):
            continue
        for variant in sorted(os.listdir(base)):
            folder = os.path.join(base, variant)
            if os.path.isdir(folder):
                counts = Counter(f.rule.id for f in scan_dir(folder))
                out[f"{rule_id}/{variant}"] = dict(sorted(counts.items()))
    return out


def diff(expected: dict, actual: dict) -> list:
    lines = []
    for key in sorted(set(expected) | set(actual)):
        want, got = expected.get(key), actual.get(key)
        if want is None:
            lines.append(f"{key}: new fixture folder, not in the snapshot ({got})")
            continue
        if got is None:
            lines.append(f"{key}: in the snapshot but no longer a fixture folder")
            continue
        for rule in sorted(set(want) | set(got)):
            a, b = want.get(rule, 0), got.get(rule, 0)
            if a != b:
                lines.append(f"{key}: {rule} {a} -> {b} ({'more' if b > a else 'fewer'} hits)")
    return lines


class FixtureSnapshot(unittest.TestCase):
    def test_every_rule_on_every_fixture(self):
        with open(SNAPSHOT, encoding="utf-8") as fh:
            expected = json.load(fh)
        changes = diff(expected, current())
        self.assertEqual(changes, [], "\n" + "\n".join(changes) +
                         "\nIf every change is intended: python3 tests/test_fixture_snapshot.py --write")


if __name__ == "__main__":
    if "--write" in sys.argv:
        data = current()
        with open(SNAPSHOT, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"Wrote {len(data)} fixture folders to {os.path.relpath(SNAPSHOT)}")
    else:
        unittest.main()
