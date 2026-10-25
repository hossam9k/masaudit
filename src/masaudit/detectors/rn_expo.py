# SPDX-License-Identifier: Apache-2.0
"""React Native and Expo evidence for the native Android and iOS rules (android.py and ios.py use it).

No detector is registered here. Two kinds of help:

- JavaScript evidence: a pinning call (react-native-ssl-public-key-pinning, react-native-ssl-pinning), its pin
  sets, Keychain options (react-native-keychain, expo-secure-store), and `if (__DEV__)` guards. Absence rules
  (no pinning, no screenshot protection, no integrity check) must count what an RN app does in JavaScript.
- The Expo config adapter: a managed Expo app has no android/ or ios/ folder (prebuild generates them), so
  its manifest and Info.plist settings live in app.json (`expo.android`, `expo.ios.infoPlist`, config plugin
  options). ExpoApp gives the existing rules those values and the app.json line to report.

Only literal configuration is read: app.json, or app.config.json. A computed app.config.js/ts is read for
explicit `key: true` settings only, and a rule that needs a default notes it as unknown.
"""

from __future__ import annotations

import itertools
import json
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

from masaudit import safety
from masaudit.detect import depends_on, scope_of
from masaudit.detectors import reactnative as rn
from masaudit.engine import Context
from masaudit.textscan import bracket_match, holds_any

UNKNOWN = rn.UNKNOWN

has_dep = rn.has_dep


def is_rn_app(ctx: Context) -> bool:
    """A React Native app: the RN platform was detected and a package.json depends on react-native or expo."""
    return bool(rn.memo(ctx, "rnx:app", lambda: rn.is_react_native(ctx) and rn.has_dep(ctx, "react-native", "expo")))


def js_sources(ctx: Context, needles: Tuple[str, ...]) -> Iterator[Tuple[str, str, str]]:
    """(path, code, blank) for shipping JS/TS files whose raw text holds a needle. `code` keeps strings,
    `blank` blanks them; comments are blanked in both."""
    for path in rn.js_files(ctx):
        if scope_of(path) == "test" or not holds_any(ctx, path, needles):
            continue
        code, blank = ctx.code(path, True), ctx.code(path, False)
        if code is not None and blank is not None:
            yield path, code, blank


# Call sites read per file, and the longest argument list read: rn.call_args walks a call's whole span, so
# thousands of nested or unclosed calls in a crafted file must not each walk the rest of the file.
MAX_CALLS = 400
MAX_SPAN = 20_000


def args_of(blank: str, paren: int) -> List[Tuple[int, int]]:
    """rn.call_args for a call whose argument list closes within MAX_SPAN characters, else []."""
    close = bracket_match(blank, paren, "(", ")")
    if close >= len(blank) or close - paren > MAX_SPAN:
        return []
    return rn.call_args(blank, paren)


def dep_matching(ctx: Context, pattern: "re.Pattern[str]") -> Optional[str]:
    """The first package.json dependency whose name matches (search, not fullmatch)."""
    return next((name for name in sorted(rn.package_deps(ctx)) if pattern.search(name)), None)


def js_evidence(ctx: Context, key: str, pattern: "re.Pattern[str]", needles: Tuple[str, ...],
                keep_strings: bool = False) -> Optional[Tuple[str, int]]:
    """The first match of `pattern` in shipping JS/TS (comments blanked; strings too unless keep_strings).
    Every match must contain one of `needles`."""
    def find() -> Optional[Tuple[str, int]]:
        for path, code, blank in js_sources(ctx, needles):
            text = code if keep_strings else blank
            m = pattern.search(text)
            if m is not None:
                return path, ctx.line_of(text, m.start())
        return None
    return rn.memo(ctx, "rnx:ev:" + key, find)


# ---------------------------------------------------------------------------- pinning

PIN_LIBS = ("react-native-ssl-public-key-pinning", "react-native-ssl-pinning", "react-native-pinch")
_INIT_PINNING = re.compile(r"\binitializeSslPinning\s*\(")
_SSL_PINNING_OPT = re.compile(r"(?<![\w$])['\"]?sslPinning['\"]?\s*:")


def pinning_call(ctx: Context) -> Optional[Tuple[str, int]]:
    """Where shipping JS turns certificate pinning on: initializeSslPinning(...) of
    react-native-ssl-public-key-pinning, or an `sslPinning:` option of react-native-ssl-pinning /
    react-native-pinch. An installed library that is never called is not evidence."""
    def find() -> Optional[Tuple[str, int]]:
        for path, _code, blank in js_sources(ctx, ("initializeSslPinning", "sslPinning")):
            m = _INIT_PINNING.search(blank)
            if m is None and any(lib in (ctx.text(path) or "") for lib in PIN_LIBS):
                m = _SSL_PINNING_OPT.search(blank)
            if m is not None:
                return path, ctx.line_of(blank, m.start())
        return None
    return rn.memo(ctx, "rnx:pinning", find)


@dataclass
class JsPinSet:
    path: str
    line: int
    host: str
    pins: int
    expiration: bool


_HOST_KEY = re.compile(r"(?:['\"]([^'\"\n]{1,253})['\"]|(?<![\w$])([A-Za-z_$][\w$]{0,252}))\s*:\s*\{")


def js_pin_sets(ctx: Context) -> List[JsPinSet]:
    """Literal pin sets of initializeSslPinning({ 'host': { publicKeyHashes: [...], expirationDate } })."""
    def find() -> List[JsPinSet]:
        out: List[JsPinSet] = []
        for path, code, blank in js_sources(ctx, ("initializeSslPinning",)):
            for m in itertools.islice(_INIT_PINNING.finditer(blank), MAX_CALLS):
                args = args_of(blank, m.end() - 1)
                if not args:
                    continue
                lo, hi = args[0]
                brace = blank.find("{", lo, hi)
                if brace < 0 or blank[lo:brace].strip():
                    continue               # a variable, not a literal object
                end = min(bracket_match(blank, brace, "{", "}"), hi)
                i = brace + 1
                while i < end:
                    hm = _HOST_KEY.search(code, i, end)
                    if hm is None:
                        break
                    body_open = hm.end() - 1
                    body_end = min(bracket_match(blank, body_open, "{", "}"), end)
                    body = blank[body_open:body_end]
                    hashes = re.search(r"(?<![\w$])['\"]?publicKeyHashes['\"]?\s*:\s*\[", body)
                    if hashes:
                        arr = body_open + hashes.end() - 1
                        arr_end = bracket_match(blank, arr, "[", "]")
                        items = rn.literal(code[arr:arr_end + 1])
                        pins = len(items) if isinstance(items, list) else -1
                        exp = bool(re.search(r"(?<![\w$])['\"]?expirationDate['\"]?\s*:", body))
                        out.append(JsPinSet(path, ctx.line_of(code, hm.start()), hm.group(1) or hm.group(2), pins, exp))
                    i = body_end + 1
        return out
    return rn.memo(ctx, "rnx:pinsets", find)


# ---------------------------------------------------------------------------- Keychain options

# react-native-keychain: `accessible: ACCESSIBLE.WHEN_UNLOCKED`, `Keychain.ACCESSIBLE.ALWAYS` (also through a wrapper
# that re-exports ACCESSIBLE), or the string value 'AccessibleAfterFirstUnlock'. expo-secure-store:
# `keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK` or a named import of the constant.
# Each starts with its literal, then the boundary check (`ACCESSIBLE(?<!\wACCESSIBLE)` is `\bACCESSIBLE`):
# the regex engine finds a leading literal much faster.
_RNK_ACCESSIBLE = re.compile(r"ACCESSIBLE(?<!\wACCESSIBLE)\s*\.\s*([A-Z_]{6,40})\b")
_RNK_STRING = re.compile(r"accessible(?<![\w$]accessible)\s*:\s*['\"](Accessible[A-Za-z]{4,40})['\"]")
_EXPO_ACCESSIBLE = re.compile(r"keychainAccessible(?<![\w$]keychainAccessible)\s*:\s*"
                              r"(?:([A-Za-z_$][\w$]{0,60})\s*\.\s*)?([A-Z_]{6,40})\b")
_COMPARED = re.compile(r"(?:[=!]==?|\bcase)\s*(?:[\w$]+\s*\.\s*)*$")


@dataclass
class KeychainUse:
    path: str
    line: int
    value: str            # Apple's name of the class (kSecAttrAccessibleAfterFirstUnlock); "" for a default
    library: str
    debug: bool
    default: str = ""     # the library default that applies, when the call passes no class


_RNK_NAMES = {"WHEN_UNLOCKED": "kSecAttrAccessibleWhenUnlocked",
              "AFTER_FIRST_UNLOCK": "kSecAttrAccessibleAfterFirstUnlock",
              "ALWAYS": "kSecAttrAccessibleAlways",
              "WHEN_PASSCODE_SET_THIS_DEVICE_ONLY": "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
              "WHEN_UNLOCKED_THIS_DEVICE_ONLY": "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
              "AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
              "ALWAYS_THIS_DEVICE_ONLY": "kSecAttrAccessibleAlwaysThisDeviceOnly"}
# Write calls and the index of their options argument; the library default when the options don't set a class.
_KEYCHAIN_WRITES = {"setGenericPassword": 2, "setInternetCredentials": 3}
_SECURE_STORE_WRITES = {"setItemAsync": 2, "setItem": 2}
_WRITE_CALL = re.compile(r"(?<![\w$])(?:([A-Za-z_$][\w$]{0,60})\s*\.\s*)?(setGenericPassword|setInternetCredentials"
                         r"|setItemAsync|setItem)\s*\(")


def _default_write(blank: str, code: str, m: "re.Match[str]", index: int, key: str) -> bool:
    """Whether this write call leaves the accessibility class to the library default: no options argument,
    or a literal options object without `key` and without a spread."""
    args = args_of(blank, m.end() - 1)
    if len(args) < index:
        return False                      # fewer arguments than the call needs: not this API
    if len(args) == index:
        return True
    lo, hi = args[index]
    opts = blank[lo:hi].strip()
    if not (opts.startswith("{") and opts.endswith("}")):
        return False                      # a variable or a call: its keys aren't known here
    return "..." not in opts and not re.search(r"(?<![\w$])['\"]?" + key + r"['\"]?\s*[:,}]", code[lo:hi])


def keychain_uses(ctx: Context) -> List[KeychainUse]:
    """Keychain accessibility classes that shipping JS passes to react-native-keychain or expo-secure-store,
    and the first write per file that leaves the class to the library default."""
    def find() -> List[KeychainUse]:
        out: List[KeychainUse] = []
        rnk_dep = rn.has_dep(ctx, "react-native-keychain")
        for path, code, blank in js_sources(ctx, ("ACCESSIBLE", "ccessible", "setGenericPassword",
                                                  "setInternetCredentials", "setItemAsync", "setItem")):
            mods = rn.imports(code)
            keychain = {n for n, (mod, _i) in mods.items() if mod == "react-native-keychain"}
            secure = {n for n, (mod, _i) in mods.items() if mod == "expo-secure-store"}
            if keychain or rnk_dep:
                for m in _RNK_ACCESSIBLE.finditer(blank):
                    name = m.group(1)
                    head = blank[max(0, m.start() - 120):m.start()]
                    owner = re.search(r"([A-Za-z_$][\w$]{0,60})\s*\.\s*$", head)
                    if name not in _RNK_NAMES or _COMPARED.search(head):
                        continue
                    if not keychain and not owner:
                        continue          # a bare ACCESSIBLE that isn't react-native-keychain's
                    if owner is None and "ACCESSIBLE" not in keychain:
                        continue
                    out.append(KeychainUse(path, ctx.line_of(blank, m.start()), _RNK_NAMES[name],
                                           "react-native-keychain", rn.in_dev(code, blank, m.start())))
                if keychain:
                    for m in _RNK_STRING.finditer(code):
                        out.append(KeychainUse(path, ctx.line_of(code, m.start()), "kSecAttr" + m.group(1),
                                               "react-native-keychain", rn.in_dev(code, blank, m.start())))
            if secure:
                for m in _EXPO_ACCESSIBLE.finditer(blank):
                    owner, name = m.group(1), m.group(2)
                    if (owner and owner not in secure) or (not owner and name not in secure) \
                            or name not in _RNK_NAMES:
                        continue
                    out.append(KeychainUse(path, ctx.line_of(blank, m.start()), _RNK_NAMES[name],
                                           "expo-secure-store", rn.in_dev(code, blank, m.start())))
            # A write counts only through a name imported from one of the two modules.
            for m in itertools.islice(_WRITE_CALL.finditer(blank) if keychain or secure else (), MAX_CALLS):
                owner, fn = m.group(1), m.group(2)
                if owner:
                    module = mods.get(owner, ("", ""))
                    if module[1] not in ("*", "default"):
                        continue
                    module_name = module[0]
                else:
                    module_name = mods.get(fn, ("", ""))[0]
                if module_name == "react-native-keychain" and fn in _KEYCHAIN_WRITES:
                    if _default_write(blank, code, m, _KEYCHAIN_WRITES[fn], "accessible"):
                        out.append(KeychainUse(path, ctx.line_of(blank, m.start()), "", "react-native-keychain",
                                               rn.in_dev(code, blank, m.start()), "AFTER_FIRST_UNLOCK"))
                        break
                elif module_name == "expo-secure-store" and fn in _SECURE_STORE_WRITES:
                    if _default_write(blank, code, m, _SECURE_STORE_WRITES[fn], "keychainAccessible"):
                        out.append(KeychainUse(path, ctx.line_of(blank, m.start()), "", "expo-secure-store",
                                               rn.in_dev(code, blank, m.start()), "WHEN_UNLOCKED"))
                        break
        return out
    return rn.memo(ctx, "rnx:keychain", find)


# ---------------------------------------------------------------------------- Expo config

_CONFIG_NAMES = ("app.json", "app.config.json", "app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs")


@dataclass
class ExpoApp:
    path: str                         # the config file findings point at
    data: Dict[str, Any]              # the `expo` object ({} for a computed app.config.js/ts)
    literal: bool                     # data is the whole config (JSON), not a guess
    dynamic: Optional[str]            # an app.config.js/ts next to it, which can change any value
    folder: str                       # the app's folder ("" at the root)
    text: str

    def get(self, *keys: Any) -> Any:
        node: Any = self.data
        for k in keys:
            if isinstance(node, dict) and isinstance(k, str):
                node = node.get(k)
            elif isinstance(node, list) and isinstance(k, int) and 0 <= k < len(node):
                node = node[k]
            else:
                return None
        return node

    def line(self, *keys: Any) -> int:
        """The line of the last key of this path that the text holds (1 when none is found)."""
        pos, found = 0, -1
        for k in keys:
            if not isinstance(k, str):
                continue
            m = re.compile(r"[\"']?" + re.escape(k) + r"[\"']?\s*:|[\"']" + re.escape(k) + r"[\"']").search(self.text, pos)
            if m is None:
                break
            pos = found = m.start()
        return self.text.count("\n", 0, found) + 1 if found >= 0 else 1

    def plugin(self, name: str) -> Optional[Dict[str, Any]]:
        """The options object of a config plugin (`["expo-build-properties", {...}]`), {} with no options."""
        for p in rn.as_list(self.get("plugins")):
            if p == name:
                return {}
            if isinstance(p, list) and p and p[0] == name:
                return p[1] if len(p) > 1 and isinstance(p[1], dict) else {}
        return None

    def mentions(self, key: str) -> bool:
        """Whether a computed app.config.js/ts names this key (it may override the JSON value)."""
        return bool(self.dynamic) and key in self.dynamic

    def js_flag(self, key: str) -> Optional[Tuple[bool, int]]:
        """An explicit `key: true|false` in a computed app.config.js/ts: (value, line)."""
        if not self.dynamic:
            return None
        m = re.search(r"(?<![\w$])[\"']?" + re.escape(key) + r"[\"']?\s*:\s*(true|false)\b", self.dynamic)
        if m is None:
            return None
        return m.group(1) == "true", self.dynamic.count("\n", 0, m.start()) + 1


_LOCAL_PLUGIN = re.compile(r"['\"](\.{1,2}/[\w./-]{1,200})['\"]")


def config_mentions(ctx: Context, app: ExpoApp, pattern: "re.Pattern[str]") -> bool:
    """Whether the computed app config, or a local config plugin it names ('./plugins/withX.js'), matches."""
    texts: List[str] = []
    dyn_path = next((p for p in ctx.files(*(n for n in _CONFIG_NAMES if not n.endswith(".json")))
                     if posixpath.dirname(p) == app.folder), None)
    if dyn_path:
        texts.append(ctx.code(dyn_path, True) or "")
    refs = _LOCAL_PLUGIN.findall("\n".join(texts) + "\n" + app.text)
    files = set(ctx.project.files)
    for ref in refs[:50]:
        base = posixpath.normpath(posixpath.join(app.folder, ref))
        for cand in (base, base + ".js", base + ".ts", base + "/index.js", base + "/index.ts"):
            if cand in files:
                texts.append(ctx.code(cand, True) or "")
                break
    return any(pattern.search(t) for t in texts)


def _json(text: Optional[str]) -> Any:
    if not text or len(text) > safety.MAX_FILE_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def expo_app(ctx: Context) -> Optional[ExpoApp]:
    """The Expo app config: app.json's `expo` object (or a top-level object when the project depends on
    expo), else app.config.json, else a computed app.config.js/ts. Configs in a folder whose own package.json
    depends on expo come first (a monorepo's root app.json can be a stub), then the shallowest, outside tests."""
    def find() -> Optional[ExpoApp]:
        if not is_rn_app(ctx):
            return None

        def app_folder(path: str) -> int:
            pkg = posixpath.join(posixpath.dirname(path), "package.json")
            return 0 if depends_on(ctx.text(pkg), "expo") else 1
        configs = sorted((p for name in _CONFIG_NAMES for p in ctx.files(name=name) if scope_of(p) != "test"),
                         key=lambda p: (app_folder(p), p.count("/"), _CONFIG_NAMES.index(posixpath.basename(p))))
        expo_dep = rn.has_dep(ctx, "expo")
        for path in configs:
            folder = posixpath.dirname(path)
            dynamic_path = next((c for c in configs if posixpath.dirname(c) == folder
                                 and c.endswith((".js", ".ts", ".mjs", ".cjs"))), None)
            dynamic = ctx.code(dynamic_path, False) if dynamic_path else None
            if path.endswith(".json"):
                data = _json(ctx.text(path))
                if not isinstance(data, dict):
                    continue
                if isinstance(data.get("expo"), dict):
                    data = data["expo"]
                elif not (expo_dep and any(k in data for k in ("android", "ios", "plugins", "slug"))):
                    continue                 # a bare React Native app.json ({"name", "displayName"})
                return ExpoApp(path, data, dynamic is None, dynamic, folder, ctx.text(path) or "")
            if expo_dep:
                return ExpoApp(path, {}, False, dynamic, folder, ctx.code(path, True) or "")
        return None
    return rn.memo(ctx, "rnx:expo", find)


def _has_folder(ctx: Context, folder: str) -> bool:
    prefix = folder + "/" if folder else ""
    return any(f.startswith(prefix) for f in ctx.project.files)


def managed_android(ctx: Context) -> Optional[ExpoApp]:
    """The Expo config when the app has no android/ folder: prebuild generates the manifest from it."""
    app = expo_app(ctx)
    if app is None or _has_folder(ctx, posixpath.join(app.folder, "android")):
        return None
    return app


def managed_ios(ctx: Context) -> Optional[ExpoApp]:
    """The Expo config when the app has no ios/ folder: prebuild generates Info.plist from it."""
    app = expo_app(ctx)
    if app is None or _has_folder(ctx, posixpath.join(app.folder, "ios")):
        return None
    return app


def config_pins(app: ExpoApp) -> bool:
    """Whether the Expo config itself may pin: NSPinnedDomains in ios.infoPlist, a pinning config plugin, or a
    computed app.config.js/ts that mentions pinning (it can add either)."""
    if app.get("ios", "infoPlist", "NSAppTransportSecurity", "NSPinnedDomains"):
        return True
    names = [p if isinstance(p, str) else p[0] for p in rn.as_list(app.get("plugins"))
             if isinstance(p, str) or (isinstance(p, list) and p and isinstance(p[0], str))]
    if any(re.search(r"(?i)pinn|trustkit|network-security", n) for n in names):
        return True
    return bool(app.dynamic and re.search(r"(?i)pinn|trustkit|networkSecurityConfig", app.dynamic))


# ---------------------------------------------------------------------------- WebView props

_WEBVIEW_TAG = re.compile(r"<\s*([A-Z][\w$]{0,60}WebView)(?![\w$.])")


@dataclass
class WebViewProp:
    path: str
    line: int
    value: Any              # the literal value (True for a bare prop), or rn.UNKNOWN
    text: str               # the value's source text
    debug: bool             # under `if (__DEV__)`, or the value is `__DEV__`
    passthrough: bool = False   # `prop={props.prop}` or `prop={prop}`: a wrapper forwarding its caller's value
    inline_html: bool = False   # loads inline HTML with no https base URL: the page is about:blank, not HTTPS


# `html` and `baseUrl` as keys of the source object (`{ html }`, `{ html: page, baseUrl }`), not as values
# (`{ uri: html }`).
_HTML_KEY = re.compile(r"[{,]\s*html\s*(?=[,:}])")
_BASE_URL = re.compile(r"[{,]\s*baseUrl\s*(?=[,:}])")


def _inline_html(code: str, el: "rn.Element") -> bool:
    """`source={{ html }}` with no `baseUrl`, or a wrapper given `html=` and neither `source` nor `baseUrl`.
    react-native-webview then loads the HTML with an empty base URL, so the page isn't an https page.
    A spread (`{...props}`) may add a base URL, so it never counts."""
    if el.spread or "baseUrl" in el.props:
        return False
    source = el.props.get("source")
    if source is None:
        return "html" in el.props
    text = source.text(code).strip()
    return text.startswith("{") and bool(_HTML_KEY.search(text)) and not _BASE_URL.search(text)


def webview_prop(ctx: Context, prop: str) -> List[WebViewProp]:
    """A prop of react-native-webview's <WebView> (any local name it is imported as) and of wrappers named
    `...WebView` that pass props through, in shipping JS/TS."""
    def find() -> List[WebViewProp]:
        out: List[WebViewProp] = []
        for path, code, blank in js_sources(ctx, (prop,)):
            names = set(rn.names_from(code, "react-native-webview"))
            names.update(m.group(1) for m in _WEBVIEW_TAG.finditer(blank))
            for el in rn.jsx_elements(code, blank, sorted(names)):
                p = el.props.get(prop)
                if p is None:
                    continue
                text = "true" if p.kind == "true" else code[p.start:p.end]
                value = True if p.kind == "true" else (text if p.kind == "string" else rn.literal(text))
                debug = rn.in_dev(code, blank, el.start) or bool(re.fullmatch(r"\s*__DEV__\s*", text))
                forwarded = bool(re.fullmatch(r"\s*(?:props\s*\.\s*|this\s*\.\s*props\s*\.\s*)?" + prop + r"\s*", text))
                out.append(WebViewProp(path, ctx.line_of(code, p.start), value, text.strip(), debug, forwarded,
                                       _inline_html(code, el)))
        return out
    return rn.memo(ctx, "rnx:webview:" + prop, find)


# ---------------------------------------------------------------------------- files in Documents

# expo-file-system (FileSystem.documentDirectory, Paths.document), react-native-fs (DocumentDirectoryPath),
# react-native-blob-util (dirs.DocumentDir).
_DOCS_ANCHOR = re.compile(r"\b(?:documentDirectory|DocumentDirectoryPath|DocumentDir)\b|\bPaths\s*\.\s*document\b")
_DOCS_NAME = re.compile(r"\s*(?:\+\s*['\"`]|\}|,\s*['\"`])([^'\"`$\n]{1,80})")
_FILE_WRITE = re.compile(r"\b(?:writeAsStringAsync|writeFile|appendFile|copyAsync|moveAsync|downloadAsync|copyFile"
                         r"|moveFile|downloadFile|writeStream|createFile)\s*\(|\.\s*(?:write|create)\s*\(")


def documents_writes(ctx: Context, sensitive: "re.Pattern[str]") -> List[Tuple[str, int, str]]:
    """(path, line, file name) for sensitive file names that shipping JS puts in the Documents folder, in files
    that write files."""
    def find() -> List[Tuple[str, int, str]]:
        out: List[Tuple[str, int, str]] = []
        for path, code, blank in js_sources(ctx, ("ocumentDirectory", "DocumentDir", "Paths")):
            if not _FILE_WRITE.search(blank):
                continue
            for m in _DOCS_ANCHOR.finditer(blank):
                n = _DOCS_NAME.match(code, m.end(), min(len(code), m.end() + 200))
                if n is None:
                    continue
                name = n.group(1).strip().lstrip("/")
                if name and sensitive.search(name):
                    out.append((path, ctx.line_of(code, m.start()), name))
        return out
    return rn.memo(ctx, "rnx:docs", find)
