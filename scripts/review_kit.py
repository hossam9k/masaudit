#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A blind review kit for a benchmark round, for a reviewer who isn't an AI and wrote no rule.

    python3 scripts/review_kit.py make 5 review.csv            # the round's judged findings, shuffled, blind
    python3 scripts/review_kit.py compare 5 review.csv         # agreement with the published verdicts

`make` writes one row per finding judged in the round: an id, a link to the exact line at the commit that
was scanned (open it in a browser, nothing to clone), the rule ID, and the message. Tool names and the
published verdicts are left out, and the rows are shuffled. The reviewer fills in `verdict` (real,
overrated, false, or unclear, as defined in docs/benchmark.md) and a short `reason`.

`compare` reads the filled-in file back and prints how often the reviewer and the published verdicts
agree (with Cohen's kappa), and each tool's false-alarm rate under the reviewer's verdicts.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import random
import sys
from typing import Dict, List, Optional

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
VERDICTS = ("real", "overrated", "false", "unclear")
FIELDS = ["id", "link", "rule", "message", "verdict", "reason"]


def _judgments(round_no: str) -> dict:
    name = "benchmark-judgments.json" if round_no == "1" else f"benchmark-judgments-{round_no}.json"
    with open(os.path.join(ROOT, "docs", name), encoding="utf-8") as fh:
        return json.load(fh)


def _apps(round_no: str) -> Dict[str, tuple]:
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import benchmark_compare
    out = {}
    for line in benchmark_compare.ROUNDS[round_no].strip().splitlines():
        folder, repo, commit, sub = line.split()[:4]
        out[folder] = (repo, commit, "" if sub == "." else sub)
    return out


def _titles() -> Dict[str, str]:
    """masaudit rule titles, the claim to judge when a round's judgments don't keep the message (rounds 1-4)."""
    out = {}
    folder = os.path.join(ROOT, "src", "masaudit", "rules")
    for name in sorted(os.listdir(folder)):
        if name.endswith(".json") and not name.startswith("_"):
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                out.update({r["id"]: r["title"] for r in json.load(fh).get("rules", [])})
    return out


def make(round_no: str, out: str, seed: int) -> int:
    data, apps, titles = _judgments(round_no), _apps(round_no), _titles()
    rows = []
    for i, x in enumerate(data["judged"]):
        repo, commit, sub = apps[x["app"]]
        path = f"{sub}/{x['path']}" if sub else x["path"]
        rows.append({"id": i, "link": f"https://github.com/{repo}/blob/{commit}/{path}#L{x['line']}",
                     "rule": x["rule"], "message": x.get("message") or titles.get(x["rule"], ""),
                     "verdict": "", "reason": ""})
    random.Random(seed).shuffle(rows)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} findings written to {out}; fill in verdict ({', '.join(VERDICTS)}) and reason")
    return 0


def _kappa(pairs: List[tuple]) -> Optional[float]:
    n = len(pairs)
    if not n:
        return None
    agree = sum(a == b for a, b in pairs) / n
    ca, cb = collections.Counter(a for a, _ in pairs), collections.Counter(b for _, b in pairs)
    chance = sum(ca[v] * cb[v] for v in VERDICTS) / (n * n)
    return None if chance == 1 else (agree - chance) / (1 - chance)


def compare(round_no: str, path: str) -> int:
    judged = _judgments(round_no)["judged"]
    with open(path, newline="", encoding="utf-8") as fh:
        reviewed = {int(r["id"]): r["verdict"].strip().lower() for r in csv.DictReader(fh)
                    if r.get("verdict", "").strip()}
    bad = sorted(i for i, v in reviewed.items() if v not in VERDICTS or not 0 <= i < len(judged))
    if bad:
        print(f"rows with an unknown id or verdict: {bad[:10]}", file=sys.stderr)
        return 2
    pairs = [(judged[i]["verdict"], v) for i, v in reviewed.items()]
    same = sum(a == b for a, b in pairs)
    print(f"{len(pairs)} of {len(judged)} reviewed; same verdict on {same} ({100 * same / max(1, len(pairs)):.0f}%)")
    k = _kappa(pairs)
    print("Cohen's kappa:", "n/a" if k is None else f"{k:.2f}")
    flips = collections.Counter((a, b) for a, b in pairs if a != b)
    for (a, b), n in flips.most_common():
        print(f"  published {a:9} -> reviewer {b:9} {n}")
    print("false alarms under the reviewer's verdicts:")
    groups: Dict[tuple, List[str]] = collections.defaultdict(list)
    for i, v in reviewed.items():
        groups[(judged[i]["tool"], judged[i].get("pool", ""))].append(v)
    for (tool, pool), vs in sorted(groups.items()):
        print(f"  {tool:10} {pool:38} {vs.count('false'):3} of {len(vs):3} false")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("make", help="write the blind review file")
    p.add_argument("round")
    p.add_argument("out")
    p.add_argument("--seed", type=int, default=1)
    p = sub.add_parser("compare", help="compare a filled-in review with the published verdicts")
    p.add_argument("round")
    p.add_argument("csv")
    args = parser.parse_args(argv)
    if args.cmd == "make":
        return make(args.round, args.out, args.seed)
    return compare(args.round, args.csv)


if __name__ == "__main__":
    sys.exit(main())
