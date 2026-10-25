#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download the precision corpus, scan it, and compare two scans: the method in docs/precision.md.

    python3 scripts/corpus.py fetch DIR                   # clone the 19 apps at their recorded commits
    python3 scripts/corpus.py scan DIR OUT [--src SRC]    # JSON per app (banking: every rule runs)
    python3 scripts/corpus.py diff BEFORE AFTER [RULE ...]  # per-rule counts, added and removed findings

Typical use when changing a rule: scan with the last release's source as BEFORE and this checkout's
`src` as AFTER, then open every added finding in its real file and judge it, and confirm every removed
one was a false alarm. `fetch` needs git and network access; masaudit itself never does.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (folder, repository, commit). Commits recorded on 2026-10-25.
APPS = [
    ("Signal-Android", "signalapp/Signal-Android", "16f138410a4ab940864a2791ae281dd1b2318611"),
    ("Signal-iOS", "signalapp/Signal-iOS", "3ace2d5b98ca5be0c1cf57fce5154ee3c05f0fb8"),
    ("bitwarden-android", "bitwarden/android", "d3f8e2d01c1825f0efe1fc2a1b592a2a94f73980"),
    ("bitwarden-ios", "bitwarden/ios", "1291ddef6bd1b8c32dcad83ca6322aa51130bbbc"),
    ("apps-android-wikipedia", "wikimedia/apps-android-wikipedia", "747806bf4e6d4d817c5f2a9ca896bdb7e4394638"),
    ("wikipedia-ios", "wikimedia/wikipedia-ios", "2031b8955e61ab78ae192026f62310be66c33578"),
    ("nextcloud-android", "nextcloud/android", "cae2070490b4460827433b9fd56ba917cbb53646"),
    ("nextcloud-ios", "nextcloud/ios", "7568e344bd23498e5eda1908ad81ace14a32280a"),
    ("element-x-android", "element-hq/element-x-android", "4b62a99d925e5ecb051f635874bc47edc43b59e7"),
    ("element-x-ios", "element-hq/element-x-ios", "2f9bac80087934e76edc39be58a3bb3947fbfe1d"),
    ("duckduckgo-android", "duckduckgo/Android", "71cba3eafee571cd88682a4fc4932e539bab2efe"),
    ("thunderbird-android", "thunderbird/thunderbird-android", "de8a03268415ce8e0c8b0327d3bbcb6b40a06a91"),
    ("Tusky", "tuskyapp/Tusky", "43ae0bb4556392393a3d759ce42a93f3a003e83a"),
    ("NewPipe", "TeamNewPipe/NewPipe", "acb7dfd658a8478686d0f8a0c389269d0ca8df95"),
    ("AntennaPod", "AntennaPod/AntennaPod", "3d105d598dfa582c6cb22ba40b56d11780366890"),
    ("mastodon-ios", "mastodon/mastodon-ios", "d43ae0d6406865a4672e2ced1846ffda8a65d732"),
    ("kotlinconf-app", "JetBrains/kotlinconf-app", "907ce238e1ffe2472991eeb2d2bfa386bdb4ea8f"),
    ("lichess-mobile", "lichess-org/mobile", "6b18f0c00dbc8e6a4096989830ff14b91faf9ad6"),
    ("immich", "immich-app/immich", "256eb55dbe92ac77e02794442f9487e88ffed2b1"),
]


def _git(*args: str, cwd: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def fetch(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)
    for folder, repo, commit in APPS:
        dest = os.path.join(directory, folder)
        if not os.path.isdir(os.path.join(dest, ".git")):
            os.makedirs(dest, exist_ok=True)
            _git("init", "-q", cwd=dest)
            _git("remote", "add", "origin", f"https://github.com/{repo}", cwd=dest)
        # Hooks and filters from these repositories never run: only fetch and a plain checkout.
        _git("-c", "protocol.version=2", "fetch", "-q", "--depth", "1", "origin", commit, cwd=dest)
        _git("-c", "core.hooksPath=/dev/null", "checkout", "-q", "--detach", "FETCH_HEAD", cwd=dest)
        print(f"{folder:24} {commit[:12]}")


def _scan_one(job):
    src, directory, out_dir, folder = job
    out = os.path.join(out_dir, folder + ".json")
    env = {**os.environ, "PYTHONPATH": src, "CI": "1", "SOURCE_DATE_EPOCH": "1767225600"}
    proc = subprocess.run([sys.executable, "-m", "masaudit", "--app-type", "banking", "--format", "json",
                           "--output", out, "--", os.path.join(directory, folder)],
                          env=env, capture_output=True, text=True)
    return folder, proc.returncode, (proc.stderr.strip().splitlines() or [""])[-1]


def scan(directory: str, out_dir: str, src: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    folders = [f for f, _, _ in APPS if os.path.isdir(os.path.join(directory, f))]
    failed = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=min(6, os.cpu_count() or 1)) as pool:
        for folder, code, last in pool.map(_scan_one, [(src, directory, out_dir, f) for f in folders]):
            print(f"{folder:24} {'ok' if code == 0 else f'exit {code}: {last}'}")
            failed += code != 0
    return 1 if failed else 0


def _load(directory: str) -> dict:
    found = {}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                for f in json.load(fh)["findings"]:
                    found[(f["rule_id"], name[:-5], f["path"], f["line"], f["snippet"].strip())] = f
    return found


def diff(before_dir: str, after_dir: str, rules: set) -> None:
    before, after = _load(before_dir), _load(after_dir)
    keep = (lambda key: key[0] in rules) if rules else (lambda key: True)
    count_before = collections.Counter(k[0] for k in before if keep(k))
    count_after = collections.Counter(k[0] for k in after if keep(k))
    print("rule      before  after")
    for rule in sorted(set(count_before) | set(count_after)):
        if rules or count_before[rule] != count_after[rule]:
            print(f"{rule:9} {count_before[rule]:7} {count_after[rule]:6}")
    added = sorted(k for k in after if k not in before and keep(k))
    removed = sorted(k for k in before if k not in after and keep(k))
    print(f"\nAdded ({len(added)}): open each one and judge it.")
    for key in added:
        rule, app, path, line, snippet = key
        print(f"+ {rule} {app}/{path}:{line} [{after[key]['bucket']}, {after[key]['scope']}] {snippet[:140]}")
    print(f"\nRemoved ({len(removed)}): each must be a fixed false alarm, not a lost true finding.")
    for rule, app, path, line, snippet in removed:
        print(f"- {rule} {app}/{path}:{line} {snippet[:140]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch", help="clone the corpus at its recorded commits")
    p.add_argument("dir")
    p = sub.add_parser("scan", help="scan every app as a banking app")
    p.add_argument("dir")
    p.add_argument("out")
    p.add_argument("--src", default=os.path.join(ROOT, "src"), help="masaudit source to run (default: this checkout)")
    p = sub.add_parser("diff", help="compare two scans")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("rules", nargs="*")
    args = parser.parse_args()
    if args.cmd == "fetch":
        fetch(args.dir)
        return 0
    if args.cmd == "scan":
        return scan(args.dir, args.out, os.path.abspath(args.src))
    diff(args.before, args.after, set(args.rules))
    return 0


if __name__ == "__main__":
    sys.exit(main())
