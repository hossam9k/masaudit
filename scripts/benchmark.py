#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Time the rules on a project, to find the slow ones before and after a change.

    python3 scripts/benchmark.py                          # examples/acme-wallet, 5 runs
    python3 scripts/benchmark.py ~/src/big-app -n 3 --app-type banking --top 20

Each run scans the directory from scratch (a fresh file cache, as a real scan has) and times engine.run,
which is where the rules spend their time. It prints the time of every run and the rules that took the
longest in total. A rule's time includes reading and stripping comments from the files it is the first
to touch, so the first few code rules always carry some of that cost.
"""

from __future__ import annotations

import argparse
import collections
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from masaudit import detect, engine, profile, safety  # noqa: E402
from masaudit.model import Project  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", nargs="?", default=os.path.join(ROOT, "examples", "acme-wallet"),
                        help="project to scan (default: examples/acme-wallet)")
    parser.add_argument("-n", "--runs", type=int, default=5, help="number of scans (default: 5)")
    parser.add_argument("--app-type", default="banking", help="app type to calibrate for (default: banking)")
    parser.add_argument("--top", type=int, default=10, help="rules to list (default: 10)")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        parser.error(f"not a directory: {root}")
    rules = engine.load_rules()
    prof = profile.make(args.app_type, "flag")
    per_rule: "collections.Counter[str]" = collections.Counter()

    # Time every detector and pattern rule by wrapping what engine.run calls.
    engine._import_detectors()
    for name, fn in list(engine._DETECTORS.items()):
        def timed(ctx, rule, _fn=fn):
            start = time.perf_counter()
            try:
                return list(_fn(ctx, rule))
            finally:
                per_rule[rule.id] += time.perf_counter() - start
        engine._DETECTORS[name] = timed
    run_pattern = engine.run_pattern

    def timed_pattern(ctx, rule):
        start = time.perf_counter()
        try:
            return list(run_pattern(ctx, rule))
        finally:
            per_rule[rule.id] += time.perf_counter() - start
    engine.run_pattern = timed_pattern

    runs = []
    findings = 0
    files = []
    for i in range(args.runs):
        files = safety.walk(root)
        project = Project(root=root, platforms=detect.platforms(files), files=files)
        start = time.perf_counter()
        findings = len(engine.run(project, rules, prof))
        runs.append(time.perf_counter() - start)
        print(f"run {i + 1}: {runs[-1]:.3f}s")
    total = sum(runs)
    print(f"\n{os.path.basename(root)}: {len(files)} files, {findings} findings, {args.runs} run(s), "
          f"total {total:.3f}s, best {min(runs):.3f}s, mean {total / len(runs):.3f}s")
    print(f"\nslowest rules (total over {args.runs} run(s)):")
    for rule_id, seconds in per_rule.most_common(args.top):
        print(f"  {rule_id:<9} {seconds:7.3f}s  {100 * seconds / total:5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
