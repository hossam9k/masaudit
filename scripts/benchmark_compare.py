#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare masaudit with other free scanners on apps no rule was tuned on: the method in docs/benchmark.md.

    python3 scripts/benchmark_compare.py fetch DIR                 # clone the apps at their recorded commits
    python3 scripts/benchmark_compare.py scan DIR OUT [--src SRC]  # every tool on every app, as SARIF
    python3 scripts/benchmark_compare.py summary OUT               # findings per tool and app, shipping code only
    python3 scripts/benchmark_compare.py sample OUT N [--seed S]   # N random findings per tool, to judge by hand

The tools: masaudit (this checkout's `src`, or --src), mobsfscan, Semgrep Community Edition with its free
registry rulesets for the languages each app uses, and rnsec on React Native apps. Each runs with its
defaults; each writes SARIF, so all four are read the same way. `fetch` and the tools need network
access (and uvx, npm); masaudit itself never does.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import random
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# folder, repository, commit, subfolder scanned (`.`: all of it), kind, app type. Commits recorded on
# 2026-10-26. A monorepo is scanned at its mobile app, so desktop, web, or server code isn't counted as the
# app's. The app type is what the app does (an authenticator is identity, a smart-home client device-control,
# a reader content), fixed for every app; `scan --calibrated` uses it, the default `banking` runs every rule.
APPS_TEXT = """
aegis                beemdevelopment/Aegis                  d6f4e5925a97e4e91593f1542085eae03432a759 .                          android  identity
keepassdx            Kunzisoft/KeePassDX                    25493ea30139adab14d937602f28d5243d3f9ecc .                          android  identity
ha-android           home-assistant/android                 0dc5a8aff8cd440c3d9e811df688f68c8b5ff69d .                          android  device-control
jellyfin-android     jellyfin/jellyfin-android              07f1a283570d5536dc4b4b8bf88761d2abeea624 .                          android  content
mihon                mihonapp/mihon                         007ec9a868bfa9a335217e16fd96a7aba03bb0f0 .                          android  content
proton-mail-android  ProtonMail/android-mail                17fe04fd0f8b9b7dc45c188d4d5e2d55033128c0 .                          android  social
kickstarter-android  kickstarter/android-oss                773ac7421fb6f70ec95bcc0ac6cfb99e942ce329 .                          android  ecommerce-cards
ha-ios               home-assistant/iOS                     696cf217ee1efb0c1551d5bbf2e5dee6f2db4f76 .                          ios  device-control
netnewswire          Ranchero-Software/NetNewsWire          70c5dce656487bdab9e0226c318acc1a15071cf4 .                          ios  content
firefox-ios          mozilla-mobile/firefox-ios             0dacdb1ae7ea8ce41209d1de1055abcd31db304d .                          ios  general
ddg-apple            duckduckgo/apple-browsers              b8af851524386ba3109496429a4644b41d153f05 iOS                        ios  general
zulip-mobile         zulip/zulip-mobile                     d7cf6da79b4b9467e240b42f24330e97390a8aff .                          react-native  social
valora               valora-xyz/wallet                      f54f9520032a03443d72268a8667ce829e83ffc8 .                          react-native  banking
inaturalist-rn       inaturalist/iNaturalistReactNative     a13a0869f049cfadbea6b2bfd3b0f1813d8ed5aa .                          react-native  social
ente                 ente/ente                              1f328d4d8de4118e447af644afc6d6ce253ff526 mobile/apps/auth           flutter  identity
fluffychat           krille-chan/fluffychat                 3f26c84068eae32909f4b7d331e98620036321e2 .                          flutter  social
appflowy             AppFlowy-IO/AppFlowy                   5cf3a365dec0d59f64bad1ee4bb1050471a39b93 frontend/appflowy_flutter  flutter  general
localsend            localsend/localsend                    cfd699125f2aa4c69f48fd274cf4bb1876a5e08d app                        flutter  general
bitkey               proto-at-block/bitkey                  ca5d443f41b3a93d219b1f441b66010e4871269e app                        kmp  banking
droidcon             touchlab/DroidconKotlin                27f3e87c12f7fa76f74002a8443605c2ff16dabc .                          kmp  content
confetti             joreilly/Confetti                      4e0057039ebb1e0806578fd19fc3bad14742be72 .                          kmp  content
"""

TOOLS = ("masaudit", "mobsfscan", "semgrep", "rnsec")
MOBSFSCAN = "mobsfscan==1.0.1"
SEMGREP = "semgrep==1.182.1"
RNSEC = "rnsec@1.4.0"
SEMGREP_CONFIGS = {
    "android": ("p/kotlin", "p/java"),
    "ios": ("p/swift",),
    "react-native": ("p/javascript", "p/typescript", "p/react"),
    "flutter": (),                 # the registry has no Dart ruleset
    "kmp": ("p/kotlin",),
}

# Test and sample code is left out for every tool, by the same path rules.
_NOT_SHIPPED = re.compile(
    r"(?:^|/)(?:test|tests|androidTest|androidUnitTest|testDebug|testRelease|commonTest|iosTest|jvmTest|"
    r"__tests__|__mocks__|e2e|integration_test|UITests|UnitTests|[A-Za-z]*Tests|fixtures?|testing|sample|samples|"
    r"example|examples|demo|benchmark|benchmarks|detox|storybook)(?:/|$)"
    r"|\.(?:test|spec)\.[jt]sx?$|Tests?\.(?:swift|kt|java|m)$", re.IGNORECASE)


def _apps() -> List[Tuple[str, str, str, str, str]]:
    return [(folder, repo, commit, "" if sub == "." else sub, kind) for folder, repo, commit, sub, kind, _t in _rows()]


def _app_types() -> Dict[str, str]:
    return {row[0]: row[5] for row in _rows()}


def _rows() -> List[List[str]]:
    return [(line.split() + [""] * 6)[:6] for line in APPS_TEXT.strip().splitlines()]


def _run(cmd: List[str], cwd: Optional[str] = None, env: Optional[dict] = None, timeout: int = 3600) -> int:
    try:
        return subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return -1


def fetch(directory: str) -> int:
    os.makedirs(directory, exist_ok=True)
    for folder, repo, commit, _sub, _kind in _apps():
        path = os.path.join(directory, folder)
        if not os.path.isdir(path):
            os.makedirs(path)
            subprocess.run(["git", "init", "-q"], cwd=path, check=True)
            subprocess.run(["git", "remote", "add", "origin", f"https://github.com/{repo}.git"], cwd=path, check=True)
        env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", commit], cwd=path, check=True, env=env)
        subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=path, check=True)
        print(f"{folder:22} {commit[:12]}")
    return 0


def _command(tool: str, target: str, kind: str, out: str, src: str, rnsec: str,
             app_type: str = "banking") -> Optional[List[str]]:
    if tool == "masaudit":
        return [sys.executable, "-m", "masaudit", "--app-type", app_type, "--format", "sarif", "--output", out,
                "--", target]
    if tool == "mobsfscan":
        if kind == "react-native":
            return None                   # mobsfscan reads Java, Kotlin, Swift, and Objective-C
        return ["uvx", MOBSFSCAN, "--sarif", "-o", out, target]
    if tool == "semgrep":
        configs = SEMGREP_CONFIGS.get(kind, ())
        if not configs:
            return None
        cmd = ["uvx", SEMGREP, "scan", "--metrics=off", "--sarif", "--output", out, "--quiet"]
        for c in configs:
            cmd += ["--config", c]
        return cmd + [target]
    if tool == "rnsec":
        if kind != "react-native":
            return None
        return ["node", rnsec, "scan", "--path", target, "--sarif", out, "--silent"]
    return None


def scan(directory: str, out_dir: str, src: str, rnsec: str, only: Optional[List[str]] = None,
         calibrated: bool = False) -> int:
    times: Dict[str, Dict[str, float]] = collections.defaultdict(dict)
    times_path = os.path.join(out_dir, "times.json")
    if os.path.exists(times_path):
        with open(times_path, encoding="utf-8") as fh:
            times.update(json.load(fh))
    for tool in TOOLS:
        if only and tool not in only:
            continue
        os.makedirs(os.path.join(out_dir, tool), exist_ok=True)
        for folder, _repo, _commit, sub, kind in _apps():
            target = os.path.join(directory, folder, sub)
            out = os.path.join(out_dir, tool, folder + ".sarif")
            app_type = _app_types()[folder] if calibrated else "banking"
            cmd = _command(tool, target, kind, out, src, rnsec, app_type)
            if cmd is None:
                continue
            env = {**os.environ, "PYTHONPATH": src, "CI": "1"} if tool == "masaudit" else None
            start = time.monotonic()
            code = _run(cmd, env=env, cwd=out_dir)      # rnsec also writes reports into its working folder
            times[tool][folder] = round(time.monotonic() - start, 1)
            ok = os.path.exists(out)
            print(f"{tool:10} {folder:22} {'ok' if ok else 'FAILED'} (exit {code}, {times[tool][folder]} s)",
                  flush=True)
    with open(times_path, "w", encoding="utf-8") as fh:
        json.dump(times, fh, indent=1, sort_keys=True)
    return 0


def _results(path: str, app_root: str) -> List[dict]:
    """One dict per SARIF result: rule, path (relative to the scanned folder), line, level."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for run in doc.get("runs") or []:
        for res in run.get("results") or []:
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri") or ""
            uri = re.sub(r"^file://", "", uri)
            if uri.startswith(app_root.rstrip("/") + "/"):
                uri = uri[len(app_root.rstrip("/")) + 1:]
            uri = uri.lstrip("./") if uri.startswith("./") else uri
            line = (phys.get("region") or {}).get("startLine") or 0
            out.append({"rule": str(res.get("ruleId") or ""), "path": uri, "line": line,
                        "level": res.get("level") or "warning",
                        "message": ((res.get("message") or {}).get("text") or "")[:300]})
    return out


def _shipped(results: List[dict]) -> List[dict]:
    return [r for r in results if r["path"] and not _NOT_SHIPPED.search(r["path"])]


def load(out_dir: str, directory: str) -> Dict[str, Dict[str, List[dict]]]:
    data: Dict[str, Dict[str, List[dict]]] = {}
    for tool in TOOLS:
        for folder, _repo, _commit, sub, _kind in _apps():
            path = os.path.join(out_dir, tool, folder + ".sarif")
            if os.path.exists(path):
                root = os.path.realpath(os.path.join(directory, folder, sub))
                data.setdefault(tool, {})[folder] = _shipped(_results(path, root))
    return data


def summary(out_dir: str, directory: str) -> int:
    data = load(out_dir, directory)
    tools = [t for t in TOOLS if t in data]
    print("app".ljust(22) + "".join(t.rjust(11) for t in tools))
    for folder, _repo, _commit, _sub, kind in _apps():
        row = folder.ljust(22)
        for tool in tools:
            row += (str(len(data[tool][folder])) if folder in data[tool] else "-").rjust(11)
        print(row + f"  ({kind})")
    print("total".ljust(22) + "".join(str(sum(len(v) for v in data[t].values())).rjust(11) for t in tools))
    return 0


def sample(out_dir: str, directory: str, n: int, seed: int) -> int:
    data = load(out_dir, directory)
    rng = random.Random(seed)
    picked = {}
    for tool, apps in data.items():
        pool = [{"app": app, **r} for app, results in sorted(apps.items()) for r in results]
        picked[tool] = rng.sample(pool, min(n, len(pool)))
    json.dump(picked, sys.stdout, indent=1)
    print()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch", help="clone the apps at their recorded commits")
    p.add_argument("dir")
    p = sub.add_parser("scan", help="run every tool on every app")
    p.add_argument("dir")
    p.add_argument("out")
    p.add_argument("--src", default=os.path.join(ROOT, "src"), help="masaudit source to run")
    p.add_argument("--rnsec", default="rnsec", help="path to the rnsec CLI (npm install rnsec@1.4.0)")
    p.add_argument("--tool", action="append", choices=TOOLS, help="run only this tool (repeatable)")
    p.add_argument("--calibrated", action="store_true", help="masaudit with each app's own type, not banking")
    p = sub.add_parser("summary", help="findings per tool and app, shipping code only")
    p.add_argument("out")
    p.add_argument("dir")
    p = sub.add_parser("sample", help="N random findings per tool, as JSON")
    p.add_argument("out")
    p.add_argument("dir")
    p.add_argument("n", type=int)
    p.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    if args.cmd == "fetch":
        return fetch(args.dir)
    if args.cmd == "scan":
        return scan(args.dir, args.out, os.path.abspath(args.src), args.rnsec, args.tool, args.calibrated)
    if args.cmd == "summary":
        return summary(args.out, args.dir)
    return sample(args.out, args.dir, args.n, args.seed)


if __name__ == "__main__":
    sys.exit(main())
