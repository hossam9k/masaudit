#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare masaudit with other free scanners on apps no rule was tuned on: the method in docs/benchmark.md.

    python3 scripts/benchmark_compare.py fetch DIR                 # clone the apps at their recorded commits
    python3 scripts/benchmark_compare.py scan DIR OUT [--src SRC]  # every tool on every app, as SARIF
    python3 scripts/benchmark_compare.py summary OUT               # findings per tool and app, shipping code only
    python3 scripts/benchmark_compare.py sample OUT N [--seed S]   # N random findings per tool, to judge by hand

`--round 2` to `5` (before the subcommand) uses a later set of apps. `--buckets fix` (after `summary` or
`sample`) keeps only masaudit's fix lists (*Fix before release*, *Fix soon*); `--buckets soft` only its *Check by
hand* and *Hardening checklist* findings (0.6.5 and later). The default counts both, as rounds 1-3 did.
`sample --where app` or `--where ci` draws only from app code or only from `.github/` workflows.

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

# Round 2: 18 more apps, chosen after 0.6.3 was released, to measure it on code its fixes never saw.
APPS2_TEXT = """
catima               CatimaLoyalty/Android                  4be0ce14489d825e16b48d7d04aed3558ac1eabb .                          android       loyalty
habitica-android     HabitRPG/habitica-android              52fbfd7a1bc76b153fb55fba7220644798de54b2 .                          android       game
wireguard-android    WireGuard/wireguard-android            e7b3a3c118836e112620b1302a8ba1873ad4daac .                          android       general
materialfiles        zhanghai/MaterialFiles                 93c333960aa897836ba3f215a19d0cb0de494db1 .                          android       general
seal                 JunkFood02/Seal                        7677f61a20fda4210e84215fef9e9b51d25daa47 .                          android       content
nextcloud-notes      nextcloud/notes-android                8c0ec80063533062eea36379ee70d44129ae966e .                          android       general
pocket-casts-android Automattic/pocket-casts-android        d93024e86a492be2c5deab0b4a9f8b24727a92fb .                          android       content
icecubes             Dimillian/IceCubesApp                  98098b9c4b5928f89f338203193c2bf40ab7f38c .                          ios           social
simplenote-ios       Automattic/simplenote-ios              29bd22351aaa45934c5dce41577571c64e1cbfbe .                          ios           general
woocommerce-ios      woocommerce/woocommerce-ios            c81156dcc72473fdda889a9af35f160a4b66b576 .                          ios           ecommerce
wire-ios             wireapp/wire-ios                       c0a21787419724ae5696c17e0c664b9dba3df173 .                          ios           social
ledger-live          LedgerHQ/ledger-live                   b36f95c01377fc63e74fe6fe3b6045ac76e009a8 apps/ledger-live-mobile    react-native  banking
blixt                smolcars/blixt-wallet                  b0408dd1d45a24d7e5a38221adeb79d6309f0e87 .                          react-native  banking
thunder              thunder-app/thunder                    d5de00be11fd3256c9debcf4a8cea8bc9fe91ce3 .                          flutter       social
aves                 deckerst/aves                          716425a3136249f960ce371c6789eb64f7421ecc .                          flutter       content
hiddify              hiddify/hiddify-app                    8ab20b01ea5165ebc3719711ad3001388d0247c4 .                          flutter       general
rustdesk             rustdesk/rustdesk                      59f2953c94b8373f124dc38d4fd0635098f7c5cd flutter                    flutter       device-control
spotube              team-spotube/spotube                   0d5b5b094e9dc8a08a80c88729472a71db4f3d78 .                          kmp           content
"""

# Round 3: 16 more apps, chosen after 0.6.4 was released.
APPS3_TEXT = """
feeder               spacecowboy/Feeder                     7fb9e2263afcb750bb07d159cff0a138eb57c6f4 .                          android       content
fossify-messages     FossifyOrg/Messages                    194fc3a117dca658389e0719ae83cdeb8145b542 .                          android       social
breezy-weather       breezy-weather/breezy-weather          a4716932d963be09cb121fb9eeacee68ff30f4ea .                          android       general
etar                 Etar-Group/Etar-Calendar               51bf4ecf0b13659fae753ae6cf129bee1f987d52 .                          android       general
bitchat-android      permissionlesstech/bitchat-android     b8016545e00cc7317fd9dc938b8cb7796db190ff .                          android       social
pocket-casts-ios     Automattic/pocket-casts-ios            2fc29b28d3a9a84f93738f9306209ef927774ada .                          ios           content
bitchat-ios          permissionlesstech/bitchat             04995f68e470a18d1fc99f86fa326c2a87bab4f2 .                          ios           social
element-ios          element-hq/element-ios                 7ba8beb088978786a6fc0aa3c9324a33ee77c38a .                          ios           social
protonvpn-ios        ProtonVPN/ios-mac-app                  6973fc1f7703314d80cada3eba377766c55710e5 .                          ios           general
discourse-mobile     discourse/DiscourseMobile              0e5d85ff18e8cff70b455824b1b9c0991bdc99ca .                          react-native  social
jitsi-meet           jitsi/jitsi-meet                       3860ada65d279a46492ba8cef0f43557fefaa14b .                          react-native  social
cake-wallet          cake-tech/cake_wallet                  162a688d103a4f956ec0738f656f53df097db6dd .                          flutter       banking
saber                saber-notes/saber                      c0af8662b777bd3afa595eb35747c028719f4772 .                          flutter       general
openreads            mateusz-bak/openreads                  74b613b0b3fc3a6e106fdc5aaede354e45ed4e58 .                          flutter       general
authpass             authpass/authpass                      ceb3b3ea22f64ead1eb93b31b1f0657b7844631a .                          flutter       identity
keyguard             AChep/keyguard-app                     cf9538ce4103e7fab247933036db1e88e69b359c .                          kmp           identity
"""

# Round 4: 16 more apps, chosen after 0.6.5 was released, the first version with the Hardening checklist and
# Check by hand buckets.
APPS4_TEXT = """
termux               termux/termux-app                      8629e632fcb95da272221be327db653fb24befe9 .                          android       general
deltachat-android    deltachat/deltachat-android            b0360819f7225fe55025da71cc73174b5a449db1 .                          android       social
tasks                tasks/tasks                            1e159ce86c431edd842cc05c6718c441af60bc60 .                          android       general
proton-pass-android  protonpass/android-pass                d03bd115db30f9fb2653e12d3af8dc7119619a44 .                          android       identity
mullvad-android      mullvad/mullvadvpn-app                 0508389502500fdd8e375d1e53756d4053ca23de android                    android       general
kickstarter-ios      kickstarter/ios-oss                    5f5463cfb830413d253efed45bfcec0322c9f152 .                          ios           ecommerce-cards
kiwix-apple          kiwix/kiwix-apple                      f410135964333775373ce851a43eeb05c966dace .                          ios           content
session-ios          session-foundation/session-ios         195c9fbddfc5a66c62c5494c6bd1d65417fe436b .                          ios           social
monal                monal-im/Monal                         8cdbe7479edb38e045e9ff58d3489ec2271961f0 .                          ios           social
zeus                 ZeusLN/zeus                            7d468f37812ad2fcea59b660f5f1a2be43f15794 .                          react-native  banking
edge-wallet          EdgeApp/edge-react-gui                 e39bc73141898813f62a2a4edc3dd6443f955ae2 .                          react-native  banking
bluebubbles          BlueBubblesApp/bluebubbles-app         7e5f1bce5cacf2e7194e329a4aeae6728e872049 .                          flutter       social
wger                 wger-project/flutter                   6814711fe6c49ffde4c61bac031420e287bfd6c7 .                          flutter       health
proxypin             wanghongenpin/proxypin                 2c98385438b0ada5666574cce3f8cc562fbd8f98 .                          flutter       general
mangayomi            kodjodevf/mangayomi                    04fcda0ea92195e18e4a88a7d7278eb9045d3003 .                          flutter       content
tivi                 chrisbanes/tivi                        a0c62c2c763c83e3a0ecf79b283224374bb06c4a .                          kmp           content
"""

# Round 5: 16 more apps, chosen after 0.7.0 was released, the first version that reads which Gradle modules,
# Xcode files, and functions ship.
APPS5_TEXT = """
ankidroid            ankidroid/Anki-Android                 4fc7d4340c6895ee43f5b219705a00481f6671e2 .                          android       general
libretube            libre-tube/LibreTube                   8d6e98fff85f9fdd59c67f5c53b647a32a52c8e4 .                          android       content
streetcomplete       streetcomplete/StreetComplete          e7e1c7de957c97a81f8a99bab48975ea8725fa69 .                          android       general
openhab-android      openhab/openhab-android                ea4b853aaffbc33597ea54e81c6af7a3e0c321c9 .                          android       device-control
muun-android         muun/apollo                            b6191ed5ea17e880f5e42db0f8d293ce3f5b9e69 .                          android       banking
damus                damus-io/damus                         4a94f666d7e159e380e10b4dbbb2967d1688709e .                          ios           social
muun-ios             muun/falcon                            d6719c00f96d2ecbde2ab6588f95e54975ceea0e .                          ios           banking
owncloud-ios         owncloud/ios-app                       c7d460b3156d8efea359b431bf695db92f98d0fe .                          ios           general
onion-browser        OnionBrowser/OnionBrowser              ed3324efc87b39a332f68e8853347be82c1cd4c2 .                          ios           general
uniswap-mobile       Uniswap/interface                      bdbace621994b658dcc4c7744f9181a8570d2a86 apps/mobile                react-native  banking
notesnook-mobile     streetwriters/notesnook                7a183013af832ad7b69ba2d118be6c576b857146 apps/mobile                react-native  general
smooth-app           openfoodfacts/smooth-app               2b769f446b6fcd30567ef3296dcd4c66965c443f .                          flutter       general
stack-wallet         cypherstack/stack_wallet               292c895fc23b32e7ed2b9d3f85b04f010173013e .                          flutter       banking
kitchenowl           TomBursch/kitchenowl                   cac641c619963f13134aecb80fadfb81f0c9249b kitchenowl                 flutter       general
fladder              DonutWare/Fladder                      3eb06a5385d60bf8cb1f4dd77daf7694e5e3f9fc .                          flutter       content
simplex-chat         simplex-chat/simplex-chat              79d91e716dbb8aae80327f580aac9a6b42426466 apps                       kmp           social
"""

ROUNDS = {"1": APPS_TEXT, "2": APPS2_TEXT, "3": APPS3_TEXT, "4": APPS4_TEXT, "5": APPS5_TEXT}
_ROUND = ["1"]                                   # the round in use, set from --round

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
    return [(line.split() + [""] * 6)[:6] for line in ROUNDS[_ROUND[0]].strip().splitlines()]


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
    """One dict per SARIF result: rule, path (relative to the scanned folder), line, level. masaudit's notes
    (`properties.bucket == "notes"`: findings in test, debug, or build code, which its report lists apart
    from what to fix) are left out, as a reader of the report would."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for run in doc.get("runs") or []:
        for res in run.get("results") or []:
            if (res.get("properties") or {}).get("bucket") == "notes":
                continue
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri") or ""
            uri = re.sub(r"^file://", "", uri)
            if uri.startswith(app_root.rstrip("/") + "/"):
                uri = uri[len(app_root.rstrip("/")) + 1:]
            uri = uri.lstrip("./") if uri.startswith("./") else uri
            line = (phys.get("region") or {}).get("startLine") or 0
            out.append({"rule": str(res.get("ruleId") or ""), "path": uri, "line": line,
                        "bucket": (res.get("properties") or {}).get("bucket") or "",
                        "level": res.get("level") or "warning",
                        "message": ((res.get("message") or {}).get("text") or "")[:300]})
    return out


def _shipped(results: List[dict]) -> List[dict]:
    return [r for r in results if r["path"] and not _NOT_SHIPPED.search(r["path"])]


_SOFT = ("check-by-hand", "hardening")


def _in_buckets(r: dict, buckets: str) -> bool:
    """masaudit's buckets; other tools have none and are always kept."""
    if not r["bucket"] or buckets == "all":
        return True
    return (r["bucket"] in _SOFT) == (buckets == "soft")


def load(out_dir: str, directory: str, buckets: str = "all") -> Dict[str, Dict[str, List[dict]]]:
    data: Dict[str, Dict[str, List[dict]]] = {}
    for tool in TOOLS:
        for folder, _repo, _commit, sub, _kind in _apps():
            path = os.path.join(out_dir, tool, folder + ".sarif")
            if os.path.exists(path):
                root = os.path.realpath(os.path.join(directory, folder, sub))
                data.setdefault(tool, {})[folder] = [r for r in _shipped(_results(path, root))
                                                     if _in_buckets(r, buckets)]
    return data


def summary(out_dir: str, directory: str, buckets: str = "all") -> int:
    data = load(out_dir, directory, buckets)
    tools = [t for t in TOOLS if t in data]
    print("app".ljust(22) + "".join(t.rjust(11) for t in tools))
    for folder, _repo, _commit, _sub, kind in _apps():
        row = folder.ljust(22)
        for tool in tools:
            row += (str(len(data[tool][folder])) if folder in data[tool] else "-").rjust(11)
        print(row + f"  ({kind})")
    print("total".ljust(22) + "".join(str(sum(len(v) for v in data[t].values())).rjust(11) for t in tools))
    return 0


def sample(out_dir: str, directory: str, n: int, seed: int, buckets: str = "all", where: str = "all") -> int:
    data = load(out_dir, directory, buckets)
    rng = random.Random(seed)
    picked = {}
    for tool, apps in data.items():
        pool = [{"app": app, **r} for app, results in sorted(apps.items()) for r in results
                if where == "all" or r["path"].startswith(".github/") == (where == "ci")]
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
    p.add_argument("--buckets", choices=("all", "fix", "soft"), default="all", help="which masaudit buckets")
    p = sub.add_parser("sample", help="N random findings per tool, as JSON")
    p.add_argument("out")
    p.add_argument("dir")
    p.add_argument("n", type=int)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--buckets", choices=("all", "fix", "soft"), default="all", help="which masaudit buckets")
    p.add_argument("--where", choices=("all", "app", "ci"), default="all", help="app code, CI workflows, or both")
    parser.add_argument("--round", choices=sorted(ROUNDS), default="1", help="which set of apps (default 1)")
    args = parser.parse_args(argv)
    _ROUND[0] = args.round
    if args.cmd == "fetch":
        return fetch(args.dir)
    if args.cmd == "scan":
        return scan(args.dir, args.out, os.path.abspath(args.src), args.rnsec, args.tool, args.calibrated)
    if args.cmd == "summary":
        return summary(args.out, args.dir, args.buckets)
    return sample(args.out, args.dir, args.n, args.seed, args.buckets, args.where)


if __name__ == "__main__":
    sys.exit(main())
