# SPDX-License-Identifier: Apache-2.0
"""React Native detectors: Expo and EAS, over-the-air updates, build configuration, resilience, and privacy. Shared helpers are in reactnative.py.

- RN-014 rn_ota_unsigned: expo-updates or CodePush delivers JS bundles that the app never checks for a signature.
- RN-015 rn_console_release: console.log/info/debug calls ship, and nothing strips them from the release bundle.
- RN-016 rn_hermes_off: the release bundle is plain JavaScript because Hermes is turned off.
- RN-017 rn_sourcemap_shipped: the bundle's source map is packaged inside the app.
- RN-018 rn_debug_tool_release: Reactotron, Flipper's JS plugins, or remote Redux DevTools connect outside __DEV__.

Book: §19.5, §6.6, §14.3, §15.8, §14.1. Everything here is bounded and linear in the size of the input.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.detect import depends_on, scope_of
from masaudit.detectors import reactnative as rn
from masaudit.detectors.reactnative import JS, DevGuard, has_dep, js_files, memo
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.textscan import bracket_match


# ---------------------------------------------------------------------------- shared: project layout

def _dir(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _join(d: str, name: str) -> str:
    return f"{d}/{name}" if d else name


def _app_roots(ctx: Context) -> List[str]:
    """Folders whose package.json depends on react-native or expo (test packages left out), shallowest first."""
    def build() -> List[str]:
        roots = [_dir(p) for p in ctx.files(name="package.json")
                 if scope_of(p) == "main" and depends_on(ctx.text(p), "react-native", "expo")]
        return sorted(set(roots), key=lambda d: (d.count("/") if d else -1, d))
    return memo(ctx, "rn_build:roots", build)


def _owner(ctx: Context, path: str) -> Optional[str]:
    """The folder of the package.json closest above `path` (None when there is none)."""
    dirs = memo(ctx, "rn_build:pkgdirs", lambda: {_dir(p) for p in ctx.files(name="package.json")})
    d = _dir(path)
    for _ in range(64):
        if d in dirs:
            return d
        if not d:
            return None
        d = _dir(d)
    return None


def _json(text: Optional[str]) -> object:
    if not text or len(text) > safety.MAX_FILE_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _line_of_text(ctx: Context, text: str, needle: "re.Pattern[str]") -> int:
    m = needle.search(text)
    return ctx.line_of(text, m.start()) if m else 1


def _hit(ctx: Context, path: str, line: int, message: str, scope: str = "") -> Hit:
    return Hit(path, line, ctx.snippet(path, line), message, scope=scope)


def _strip_hash_comments(text: str) -> str:
    """Blank `# ...` comments (Ruby, .properties), keeping offsets. `#{...}` (Ruby interpolation) stays."""
    return re.sub(r"#(?!\{)[^\n]*", lambda m: " " * len(m.group(0)), text)


def _strip_xml_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.DOTALL)


# ---------------------------------------------------------------------------- shared: __DEV__ guards

def dev_guard(ctx: Context, path: str) -> DevGuard:
    return rn.dev_guard(ctx.code(path) or "", ctx.code(path, False) or "")


# ---------------------------------------------------------------------------- RN-014 OTA updates

_EXPO_UPDATES = ("expo-updates",)
_CODE_PUSH = ("react-native-code-push", "@code-push-next/react-native-code-push", "@revopush/react-native-code-push")
_LOCAL_URL = re.compile(r"^http://(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\])")
_APP_CONFIG = ("app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs", "app.config.json")


def _expo_plugin(plugins: object, name: str) -> bool:
    if not isinstance(plugins, list):
        return False
    return any(p == name or (isinstance(p, list) and p and p[0] == name) for p in plugins)


class _Ota:
    """What the project says about expo-updates, from app.json, app.config.*, Expo.plist and the manifest."""

    def __init__(self) -> None:
        self.anchor: Optional[Tuple[str, int]] = None
        self.urls: List[Tuple[str, int, str]] = []        # (path, line, url)
        self.signed = False
        self.disabled = False
        self.enabled_somewhere = False
        self.computed = False


def _ota_facts(ctx: Context) -> _Ota:
    ota = _Ota()
    for path in ctx.files(name="app.json"):
        if scope_of(path) != "main":
            continue
        text = ctx.text(path) or ""
        data = _json(text)
        if not isinstance(data, dict):
            continue
        expo = data.get("expo", data)
        if not isinstance(expo, dict):
            continue
        updates = expo.get("updates")
        if isinstance(updates, dict):
            line = _line_of_text(ctx, text, re.compile(r'"updates"\s*:'))
            ota.anchor = ota.anchor or (path, line)
            if updates.get("enabled") is False:
                ota.disabled = True
            else:
                ota.enabled_somewhere = True
            if updates.get("codeSigningCertificate"):
                ota.signed = True
            url = updates.get("url")
            if isinstance(url, str):
                ota.urls.append((path, _line_of_text(ctx, text, re.compile(r'"url"\s*:\s*"' + re.escape(url))), url))
        elif "runtimeVersion" in expo or _expo_plugin(expo.get("plugins"), "expo-updates"):
            ota.anchor = ota.anchor or (path, _line_of_text(ctx, text, re.compile(r'"runtimeVersion"|"expo-updates"')))
    for name in _APP_CONFIG:
        for path in ctx.files(name=name):
            if scope_of(path) != "main":
                continue
            code = ctx.code(path) or ""
            blank = ctx.code(path, False) or ""
            if "codeSigningCertificate" in code:
                ota.signed = True
            m = re.search(r"\bupdates\s*:\s*\{", blank)
            if not m:
                if "updates" in blank or "..." in blank:
                    ota.computed = True
                continue
            op = m.end() - 1
            close = min(bracket_match(blank, op, "{", "}"), len(blank))
            body = code[op:close]
            ota.anchor = ota.anchor or (path, ctx.line_of(code, m.start()))
            if re.search(r"\benabled\s*:\s*false\b", body):
                ota.disabled = True
            else:
                ota.enabled_somewhere = True
            u = re.search(r"\burl\s*:\s*(['\"`])([^'\"`\n]{0,300})\1", body)
            if u:
                ota.urls.append((path, ctx.line_of(code, op + u.start()), u.group(2)))
            elif re.search(r"\burl\s*:", body):
                ota.urls.append((path, ctx.line_of(code, op), ""))
    for path in ctx.files(name="Expo.plist"):
        if scope_of(path) != "main":
            continue
        text = _strip_xml_comments(ctx.text(path) or "")
        if "EXUpdatesCodeSigningCertificate" in text:
            ota.signed = True
        if re.search(r"<key>EXUpdatesEnabled</key>\s*<false\s*/>", text):
            ota.disabled = True
        elif "EXUpdatesEnabled" in text:
            ota.enabled_somewhere = True
        u = re.search(r"<key>EXUpdatesURL</key>\s*<string>([^<]{0,300})</string>", text)
        if u:
            ota.urls.append((path, ctx.line_of(text, u.start()), u.group(1).strip()))
    for path in ctx.files(name="AndroidManifest.xml"):
        if scope_of(path) != "main":
            continue
        text = _strip_xml_comments(ctx.text(path) or "")
        if "expo.modules.updates" not in text:
            continue
        if "expo.modules.updates.CODE_SIGNING_CERTIFICATE" in text:
            ota.signed = True
        u = re.search(r'expo\.modules\.updates\.EXPO_UPDATE_URL"\s+android:value="([^"]{0,300})"', text)
        if u:
            ota.urls.append((path, ctx.line_of(text, u.start()), u.group(1)))
    return ota


def _dep_line(ctx: Context, names: Tuple[str, ...]) -> Optional[Tuple[str, int]]:
    for path in ctx.files(name="package.json"):
        if scope_of(path) != "main":
            continue
        text = ctx.text(path) or ""
        for n in names:
            m = re.search(r'"' + re.escape(n) + r'"\s*:', text)
            if m:
                return path, ctx.line_of(text, m.start())
    return None


def _code_push_key(ctx: Context) -> bool:
    for path in ctx.files(name="Info.plist") + ctx.files(".xml"):
        if path.endswith(".xml") and not re.search(r"/res/values[^/]*/[^/]+\.xml$", path):
            continue
        if scope_of(path) == "test":
            continue
        text = ctx.text(path) or ""
        if "CodePushPublicKey" in text and "CodePushPublicKey" in _strip_xml_comments(text):
            return True
    return False


@detector("rn_ota_unsigned")
def ota_unsigned(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if has_dep(ctx, *_EXPO_UPDATES):
        ota = _ota_facts(ctx)
        remote = [u for u in ota.urls if u[2] != ""] or ota.urls
        if not ota.urls:
            if ota.computed or ota.anchor:
                ctx.note_unknown("expo-updates is installed, but its update URL comes from computed config; "
                                 "check by hand that code signing is configured.")
        elif ota.disabled and not ota.enabled_somewhere:
            pass
        elif not ota.signed:
            path, line = ota.anchor or (remote[0][0], remote[0][1])
            http = [u for u in remote if u[2].startswith("http://") and not _LOCAL_URL.match(u[2])]
            extra = " The update URL also uses plain HTTP." if http else ""
            yield _hit(ctx, path, line,
                       "expo-updates downloads new JavaScript bundles, but no `codeSigningCertificate` is set, so the "
                       "app runs any bundle the update server or a network attacker sends." + extra)
        else:
            for path, line, url in remote:
                if url.startswith("http://") and not _LOCAL_URL.match(url):
                    yield _hit(ctx, path, line,
                               "Update manifests are fetched over plain HTTP. Code signing stops a changed bundle, "
                               "but anyone on the network can block updates or replay an old signed one.")
    if has_dep(ctx, *_CODE_PUSH) and not _code_push_key(ctx):
        where = _dep_line(ctx, _CODE_PUSH)
        if where:
            yield _hit(ctx, where[0], where[1],
                       "CodePush is installed, but no `CodePushPublicKey` is set in Info.plist or strings.xml, so "
                       "the app installs update bundles without checking their signature.")


# ---------------------------------------------------------------------------- RN-015 console in release

_BABEL_NAMES = ("babel.config.js", "babel.config.cjs", "babel.config.mjs", "babel.config.json", "babel.config.ts",
                ".babelrc", ".babelrc.js", ".babelrc.cjs", ".babelrc.mjs", ".babelrc.json")
_METRO_NAMES = ("metro.config.js", "metro.config.cjs", "metro.config.mjs", "metro.config.ts", "metro.config.json")
_STRIPS = re.compile(r"remove-console|drop_console['\"]?\s*:\s*true|dropConsole\s*:\s*true"
                     r"|\bdrop\s*:\s*\[[^\]]{0,200}['\"]console['\"]|pure_funcs['\"]?\s*:\s*\[[^\]]{0,400}console\.log")
_LOCAL_REQUIRE = re.compile(r"\brequire\s*\(\s*['\"](\.{1,2}/[^'\"\n]{1,200})['\"]\s*\)")
_CONSOLE_CALL = re.compile(r"(?<![\w$.])console\s*\.\s*(?:log|info|debug)\s*\(")
# A release no-op for console: `console.log = () => {}`, `console[k] = noop` (chains such as
# `console.log = console.info = noop` included), a replaced `global.console`, or `Object.assign(console, ...)`.
_CONSOLE_NOOP = re.compile(
    r"(?<![\w$])console\s*(?:\.\s*(?:log|info|debug)|\[[^\]\n]{1,80}\])\s*=(?!=)\s*"
    r"(?:console\s*\.\s*\w+\s*=(?!=)\s*){0,4}"
    r"(?:\(\s*(?:\.\.\.\s*)?[\w$]{0,20}\s*\)\s*=>\s*(?:\{\s*\}|null\b|undefined\b|void\s+0\b)"
    r"|[\w$]{1,20}\s*=>\s*(?:\{\s*\}|null\b|undefined\b)"
    r"|function\s*[\w$]{0,40}\s*\([^)\n]{0,40}\)\s*\{\s*\}"
    r"|(?i:[\w$.]{0,40}(?:noop|nothing|empty|silent|blackhole)[\w$]{0,20})\b)"
    r"|\b(?:global|globalThis|window)\s*\.\s*console\s*=(?!=)"
    r"|\bObject\.assign\s*\(\s*console\s*,")
_NOT_SHIPPED = re.compile(r"(?:\.config\.[cm]?[jt]s|\.web\.[jt]sx?|\.d\.ts|\.electron\.[jt]sx?)$")
_NATIVE_DIR = re.compile(r"(?:^|/)(?:android|ios|web|server|backend|docs?|website)/")
# Build tools in an app package's own folders (packages/app/tools/...): scope_of only knows the repository's.
_PACKAGE_TOOLING = {"tools", "scripts", "bin", "build-tools"}


def _config_text(ctx: Context, path: str) -> str:
    if path.endswith(JS):
        return ctx.code(path) or ""
    return ctx.text(path) or ""


def _strips_console(ctx: Context, root: str) -> Optional[str]:
    """The babel or metro config that drops console calls from the bundle, else None. Looks in `root` and the
    folders above it (a monorepo's root config applies too), in package.json's "babel" key, and in local files
    the config requires."""
    d: Optional[str] = root
    seen: Set[str] = set()
    for _ in range(32):
        if d is None:
            break
        for name in _BABEL_NAMES + _METRO_NAMES + ("package.json",):
            path = _join(d, name)
            text = _config_text(ctx, path)
            if not text:
                continue
            if name == "package.json":
                data = _json(text)
                if isinstance(data, dict) and _STRIPS.search(json.dumps(data.get("babel", ""))):
                    return path
                continue
            if _STRIPS.search(text):
                return path
            for m in _LOCAL_REQUIRE.finditer(text):
                rel = posixpath.normpath(posixpath.join(d or ".", m.group(1)))
                for cand in (rel, rel + ".js", rel + ".cjs", rel + ".ts", rel + "/index.js"):
                    if cand in seen or cand.startswith(".."):
                        continue
                    seen.add(cand)
                    if _STRIPS.search(_config_text(ctx, cand)):
                        return path
        d = None if not d else _dir(d)
    return None


def _babel_anchor(ctx: Context, root: str) -> Tuple[str, int]:
    for name in _BABEL_NAMES:
        path = _join(root, name)
        text = ctx.text(path)
        if text:
            return path, _line_of_text(ctx, text, re.compile(r"\b(?:presets|plugins)\b"))
    pkg = _join(root, "package.json")
    return pkg, _line_of_text(ctx, ctx.text(pkg) or "", re.compile(r'"(?:react-native|expo)"\s*:'))


@detector("rn_console_release")
def console_release(ctx: Context, rule: Rule) -> Iterable[Hit]:
    roots = _app_roots(ctx)
    if not roots:
        return
    counts: Dict[str, int] = {r: 0 for r in roots}
    first: Dict[str, Tuple[str, int]] = {}
    overridden: Set[str] = set()
    for path in js_files(ctx):
        if scope_of(path) != "main" or _NOT_SHIPPED.search(path):
            continue
        root = _owner(ctx, path)
        rel = path[len(root) + 1:] if root else path
        if root not in counts or _NATIVE_DIR.search("/" + rel) or rel.split("/", 1)[0] in _PACKAGE_TOOLING:
            continue                          # native code, a web build, or the package's own build tools
        raw = ctx.text(path) or ""
        if "console" not in raw:
            continue
        blank = ctx.code(path, False) or ""
        if _CONSOLE_NOOP.search(blank):
            overridden.add(root)
        guard: Optional[DevGuard] = None
        for m in _CONSOLE_CALL.finditer(blank):
            if guard is None:
                guard = dev_guard(ctx, path)
            if m.start() in guard:
                continue
            counts[root] += 1
            if root not in first:
                first[root] = (path, ctx.line_of(blank, m.start()))
    for root in roots:
        if not counts[root] or root in overridden or _strips_console(ctx, root):
            continue
        path, line = _babel_anchor(ctx, root)
        fpath, fline = first[root]
        n = counts[root]
        calls = "call" if n == 1 else "calls"
        yield _hit(ctx, path, line,
                   f"{n} console.log/info/debug {calls} outside __DEV__ (first at {fpath}:{fline}) ship in the release "
                   "bundle, and no babel `transform-remove-console` or metro `drop_console` removes them. Release "
                   "builds send console output to logcat and the iOS system log.", scope="main")


# ---------------------------------------------------------------------------- RN-016 Hermes off

_HERMES_PROP = re.compile(r"^[ \t]*hermesEnabled[ \t]*=[ \t]*false[ \t]*$", re.MULTILINE)
_HERMES_POD = re.compile(r":hermes_enabled\s*=>\s*false\b|\bhermes_enabled:\s*false\b"
                         r"|ENV\[\s*['\"]USE_HERMES['\"]\s*\]\s*=\s*['\"](?:0|false)['\"]")
_JSC_JSON = re.compile(r'"jsEngine"\s*:\s*"jsc"')
_JSC_PROPS = re.compile(r'"expo\.jsEngine"\s*:\s*"jsc"')
_JSC_CODE = re.compile(r"\bjsEngine\s*:\s*['\"]jsc['\"]")
_EXT_REACT = re.compile(r"\bproject\.ext\.react\s*=\s*\[")
_HERMES_MSG = ("Hermes is turned off, so the release app ships its JavaScript as a plain-text bundle. Anyone who "
               "unzips the app reads and edits the code, including its security checks.")


@detector("rn_hermes_off")
def hermes_off(ctx: Context, rule: Rule) -> Iterable[Hit]:
    files = set(ctx.project.files)
    for path in ctx.files(name="gradle.properties"):
        d = _dir(path)
        if scope_of(path) == "test" or not ({_join(d, "settings.gradle"), _join(d, "settings.gradle.kts")} & files):
            continue                                  # a library module's properties, not the app's
        text = _strip_hash_comments(ctx.text(path) or "")
        for m in _HERMES_PROP.finditer(text):
            yield _hit(ctx, path, ctx.line_of(text, m.start()), _HERMES_MSG + " (`hermesEnabled=false`)")
    for path in ctx.files(name="Podfile"):
        if scope_of(path) == "test":
            continue
        text = _strip_hash_comments(ctx.text(path) or "")
        for m in _HERMES_POD.finditer(text):
            yield _hit(ctx, path, ctx.line_of(text, m.start()), _HERMES_MSG + " (Podfile)")
    for path in ctx.files(name="Podfile.properties.json") + ctx.files(name="app.json"):
        if scope_of(path) == "test":
            continue
        text = ctx.text(path) or ""
        rx = _JSC_PROPS if path.endswith("Podfile.properties.json") else _JSC_JSON
        for m in rx.finditer(text):
            yield _hit(ctx, path, ctx.line_of(text, m.start()), _HERMES_MSG + " (`jsEngine` is `jsc`)")
    for name in _APP_CONFIG:
        for path in ctx.files(name=name):
            if scope_of(path) == "test":
                continue
            code = ctx.code(path) or ""
            for m in _JSC_CODE.finditer(code):
                yield _hit(ctx, path, ctx.line_of(code, m.start()), _HERMES_MSG + " (`jsEngine` is `jsc`)")
    for path in ctx.files("build.gradle"):
        if scope_of(path) == "test":
            continue
        raw = ctx.text(path) or ""
        if "enableHermes" not in raw:
            continue
        blank = ctx.code(path, False) or ""
        for m in _EXT_REACT.finditer(blank):
            op = m.end() - 1
            close = min(bracket_match(blank, op, "[", "]"), len(blank), op + 4000)
            h = re.search(r"\benableHermes\s*:\s*false\b", blank[op:close])
            if h:
                yield _hit(ctx, path, ctx.line_of(blank, op + h.start()), _HERMES_MSG + " (`enableHermes: false`)")


# ---------------------------------------------------------------------------- RN-017 source map shipped

_SOURCEMAP_OUT = re.compile(r"--sourcemap-output['\"]?[ \t]*[,=\s][ \t]*['\"]?([^\s'\",\]]{1,300})")
_INTO = re.compile(r"\binto\s*\(?\s*(?:file\s*\(\s*)?['\"]([^'\"\n]{1,300})['\"]")
_FROM_MAP = re.compile(r"\bfrom\s*\(?\s*(?:file\s*\(\s*)?['\"]([^'\"\n]{1,300}\.map|[^'\"\n]{0,300}sourcemaps?[^'\"\n]{0,200})['\"]")
_ASSET_DIRS = re.compile(r"\bassets\.srcDirs\s*(?:\+?=|\()\s*\[?([^\n]{1,400})")
_PBX_MAP = re.compile(r"/\*\s*([\w.-]{1,200}\.(?:jsbundle|bundle|js)\.map)\s+in\s+Resources\s*\*/")
_MAP_MSG = ("The JavaScript source map ships inside the app. It turns the minified bundle back into the original "
            "file names, function names, and code layout for anyone who unzips the app.")


def _ships_to_assets(path: str) -> bool:
    p = path.replace("\\", "/")
    if "sourcemaps" in p.lower() or "/build/generated/sourcemaps" in p:
        return False
    return bool(re.search(r"(?:^|/)assets(?:/|$)", p)) and "/debug/" not in p


def _committed_maps(ctx: Context) -> Iterable[str]:
    """`*.map` files committed in an Android app's assets folder (masaudit doesn't list .map files otherwise)."""
    seen: Set[str] = set()
    for manifest in ctx.files(name="AndroidManifest.xml"):
        if scope_of(manifest) != "main" or not manifest.endswith("/src/main/AndroidManifest.xml"):
            continue
        src = manifest[: -len("/main/AndroidManifest.xml")]
        for variant in ("main", "release"):
            rel = f"{src}/{variant}/assets"
            if rel in seen:
                continue
            seen.add(rel)
            full = os.path.join(ctx.root, rel)
            if not safety.is_within(ctx.root, full) or os.path.islink(full) or not os.path.isdir(full):
                continue
            try:
                with os.scandir(full) as it:
                    names = sorted(e.name for _, e in zip(range(2000), it)
                                   if e.name.endswith(".map") and e.is_file(follow_symlinks=False))
            except OSError:
                continue
            for name in names:
                yield f"{rel}/{name}"


@detector("rn_sourcemap_shipped")
def sourcemap_shipped(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for rel in _committed_maps(ctx):
        yield Hit(rel, 1, "", _MAP_MSG + " The map is committed in the Android assets folder.")
    for path in ctx.files(".pbxproj"):
        if scope_of(path) == "test":
            continue
        text = ctx.text(path) or ""
        if ".map in Resources" not in text:
            continue
        for m in _PBX_MAP.finditer(text):
            line = ctx.line_of(text, m.start())
            yield _hit(ctx, path, line, _MAP_MSG + f" `{m.group(1)}` is in the Copy Bundle Resources phase.")
            break
    for path in ctx.files("package.json", ".sh", ".gradle", ".kts", ".yml", ".yaml") + ctx.files(name="Fastfile"):
        if "/node_modules/" in path or scope_of(path) == "test":
            continue
        text = ctx.text(path) or ""
        if "--sourcemap-output" not in text:
            continue
        code = ctx.code(path) or text
        for m in _SOURCEMAP_OUT.finditer(code):
            target = m.group(1)
            if _ships_to_assets(target) and ("android" in target or "/src/main/" in target or target.startswith("$")
                                             or path.startswith("android/") or "/android/" in path):
                yield _hit(ctx, path, ctx.line_of(code, m.start()),
                           _MAP_MSG + f" The bundle command writes it to `{target}`, which is packaged.")
    for path in ctx.files(".gradle", ".gradle.kts"):
        if scope_of(path) == "test":
            continue
        raw = ctx.text(path) or ""
        if ".map" not in raw and "sourcemap" not in raw.lower():
            continue
        code = ctx.code(path) or ""
        asset_dirs = [s.strip() for m in _ASSET_DIRS.finditer(code)
                      for s in re.findall(r"['\"]([^'\"\n]{1,300})['\"]", m.group(1))]
        for m in _FROM_MAP.finditer(code):
            window = code[m.end(): m.end() + 1500]
            into = _INTO.search(window)
            if not into:
                continue
            target = into.group(1)
            if (re.search(r"(?:^|/)assets(?:/|$)", target) and "/debug" not in target) or target in asset_dirs:
                yield _hit(ctx, path, ctx.line_of(code, m.start()),
                           _MAP_MSG + f" A Gradle copy task puts it in `{target}`, which is packaged as app assets.")


# ---------------------------------------------------------------------------- RN-018 debug tooling in release

_TOOL_MODULES = {
    "reactotron-react-native": "Reactotron", "reactotron-redux": "Reactotron",
    "react-native-flipper": "Flipper", "redux-flipper": "Flipper",
    "remote-redux-devtools": "remote Redux DevTools", "@redux-devtools/remote": "remote Redux DevTools",
    "react-devtools-core": "React DevTools",
}
_TOOL_CALL = re.compile(r"\.\s*connect\s*\(|\baddPlugin\s*\(|\bcreateDebugger\s*\(|\bcomposeWithDevTools\s*\("
                        r"|\bdevToolsEnhancer\s*\(|\bconnectToDevTools\s*\(")
_REALTIME = re.compile(r"\brealtime\s*:\s*true\b")
_IMPORT_SPEC = re.compile(r"(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['\"]([^'\"\n]{1,200})['\"]")
_PROD_PROFILE = re.compile(r"(?i)^(?:prod|production|release|store|app-?store|play-?store|live)$")


def _tool_modules(code: str) -> Dict[str, str]:
    out = {}
    for m in _IMPORT_SPEC.finditer(code):
        tool = _TOOL_MODULES.get(m.group(1))
        if tool:
            out[m.group(1)] = tool
    return out


def _unguarded_call(ctx: Context, path: str, tools: Dict[str, str]) -> Optional[Tuple[int, str]]:
    blank = ctx.code(path, False) or ""
    code = ctx.code(path) or ""
    guard = dev_guard(ctx, path)
    for m in _TOOL_CALL.finditer(blank):
        name = m.group(0)
        if "connect" in name and "connectToDevTools" not in name:
            if not any(t == "Reactotron" for t in tools.values()):
                continue
            # `Reactotron.configure(...)...connect()`: the chain must start at Reactotron within the statement.
            before = blank[max(0, m.start() - 1500): m.start()]
            if "configure" not in before and "Reactotron" not in before:
                continue
            tool = "Reactotron"
        elif "addPlugin" in name or "createDebugger" in name:
            if "Flipper" not in tools.values():
                continue
            tool = "Flipper"
        elif "connectToDevTools" in name:
            if "React DevTools" not in tools.values():
                continue
            tool = "React DevTools"
        else:
            if "remote Redux DevTools" not in tools.values():
                continue
            close = min(bracket_match(blank, m.end() - 1, "(", ")"), len(blank), m.end() + 2000)
            if not _REALTIME.search(code[m.end(): close]):
                continue
            tool = "remote Redux DevTools"
        if m.start() in guard:
            continue
        return ctx.line_of(blank, m.start()), tool
    return None


def _strip_ext(path: str) -> str:
    for ext in JS:
        if path.endswith(ext):
            return path[: -len(ext)]
    return path


def _import_index(ctx: Context) -> Dict[str, List[Tuple[str, str, int]]]:
    """Module file name (last path segment, no extension) -> (importing file, spec, offset) for every import,
    require() and import() in the project's non-test JS. Built once, the first time a rule needs it."""
    def build() -> Dict[str, List[Tuple[str, str, int]]]:
        index: Dict[str, List[Tuple[str, str, int]]] = {}
        for path in js_files(ctx):
            if scope_of(path) == "test":
                continue
            raw = ctx.text(path) or ""
            if "import" not in raw and "require" not in raw:
                continue
            for m in _IMPORT_SPEC.finditer(ctx.code(path) or ""):
                spec = m.group(1)
                if spec.startswith(".") or "/" in spec:
                    key = spec.rsplit("/", 1)[-1].split(".")[0]
                    index.setdefault(key, []).append((path, spec, m.start()))
        return index
    return memo(ctx, "rn_build:imports", build)


def _loaded_only_in_dev(ctx: Context, target: str) -> Optional[bool]:
    """Whether every import or require of `target` (a JS file) sits under a __DEV__ guard. None when no file
    loads it by a relative path that resolves to it, or by an aliased path ending in its file name."""
    stem = _strip_ext(target)
    base = stem.rsplit("/", 1)[-1]
    key, candidates = base, {stem}
    if base == "index":
        key = _dir(stem).rsplit("/", 1)[-1]
        candidates.add(_dir(stem))
    found = False
    for path, spec, offset in _import_index(ctx).get(key, []):
        if path == target:
            continue
        if spec.startswith("."):
            resolved = _strip_ext(posixpath.normpath(posixpath.join(_dir(path) or ".", spec)))
            if resolved not in candidates:
                continue
        found = True
        if offset not in dev_guard(ctx, path):
            return False
    return True if found else None


@detector("rn_debug_tool_release")
def debug_tool_release(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in js_files(ctx):
        if scope_of(path) != "main" or _NOT_SHIPPED.search(path):
            continue
        raw = ctx.text(path) or ""
        if not any(k in raw for k in ("reactotron", "flipper", "redux-devtools", "react-devtools-core")):
            continue
        tools = _tool_modules(ctx.code(path) or "")
        if not tools:
            continue
        found = _unguarded_call(ctx, path, tools)
        if not found:
            continue
        line, tool = found
        loaded = _loaded_only_in_dev(ctx, path)
        if loaded is True:
            continue
        if loaded is None and not re.search(r"(?:^|/)(?:index|App|_layout)\.[jt]sx?$", path):
            ctx.note_unknown(f"{path} starts {tool} outside __DEV__, but masaudit found no file that loads it; "
                             "check by hand that it loads only in development builds.")
            continue
        yield _hit(ctx, path, line,
                   f"{tool} is started outside a `__DEV__` check, so release builds try to connect to it and stream "
                   "app state, network calls and storage to whatever host it points at.")
    for path in ctx.files(name="eas.json"):
        if scope_of(path) != "main":
            continue
        text = ctx.text(path) or ""
        data = _json(text)
        build = data.get("build") if isinstance(data, dict) else None
        if not isinstance(build, dict):
            continue
        for name, prof in build.items():
            if not isinstance(prof, dict):
                continue
            store = prof.get("distribution") == "store" or _PROD_PROFILE.match(str(name))
            if not store:
                continue
            dev, cur, hops = None, prof, 0
            while isinstance(cur, dict) and hops < 10:
                if "developmentClient" in cur:
                    dev = cur.get("developmentClient")
                    break
                cur = build.get(cur.get("extends")) if isinstance(cur.get("extends"), str) else None
                hops += 1
            if dev is True:
                line = _line_of_text(ctx, text, re.compile(r'"' + re.escape(str(name)) + r'"\s*:'))
                yield _hit(ctx, path, line,
                           f"The `{name}` build profile sets `developmentClient: true`, so store builds include "
                           "expo-dev-client's developer menu and can load JavaScript from a development server.")
