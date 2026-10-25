# SPDX-License-Identifier: Apache-2.0
"""React Native detectors: network: plain HTTP, TLS, and certificate pinning. Shared helpers are in reactnative.py.

RN-003: HTTP requests or responses logged in every build: an axios interceptor that prints headers, bodies,
or whole request objects, redux-logger, or react-native-network-logger, outside `__DEV__` (book §6.6).
RN-004: a JavaScript networking library told to accept any certificate: react-native-ssl-pinning
`disableAllSecurity: true`, rn-fetch-blob or react-native-blob-util `trusty: true` (book §7.1).
RN-019: npm dependencies that can be swapped at the source or in transit: git dependencies not pinned to a
commit, plain-HTTP sources, `*` or `latest`, and .npmrc or .yarnrc settings that turn off TLS checks, use
an HTTP registry, or commit a registry token (book §15.4).
"""

from __future__ import annotations

import json
import re
from typing import Dict, FrozenSet, Iterable, Iterator, Optional, Set, Tuple

from masaudit import safety
from masaudit.detect import scope_of
from masaudit.detectors import reactnative as rn
from masaudit.detectors.reactnative import call_args, imports, js_files, memo
from masaudit.detectors.rn_storage import dotfiles, looks_secret, package_dirs
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.textscan import bracket_match, text_memo

# ---------------------------------------------------------------------------- debug-only code

_IF = re.compile(r"\bif\s*\(")
def dev_only(code: str, blank: str, idx: int) -> bool:
    """Is offset idx in code that runs only in development builds? (reactnative.DevGuard)"""
    return rn.in_dev(code, blank, idx)


# ---------------------------------------------------------------------------- RN-003

def _console_stripping(ctx: Context) -> Tuple[bool, FrozenSet[str]]:
    """(release strips console calls, the console methods kept anyway) from babel-plugin-transform-remove-console
    in a Babel config. Several configs or `exclude` lists: a method counts as kept if any config keeps it."""
    def build() -> Tuple[bool, FrozenSet[str]]:
        stripped, kept = False, set()
        for path in ctx.files(".js", ".cjs", ".mjs", ".json", ".ts"):
            base = path.rsplit("/", 1)[-1]
            if not re.match(r"(?:babel\.config|\.babelrc)", base) or scope_of(path) == "test":
                continue
            code = ctx.code(path) or ""
            for m in re.finditer(r"transform-remove-console", code):
                stripped = True
                ex = re.match(r"['\"]\s*,\s*\{\s*['\"]?exclude['\"]?\s*:\s*\[([^\]]{0,400})\]", code[m.end():m.end() + 500])
                if ex:
                    kept |= set(re.findall(r"['\"](\w+)['\"]", ex.group(1)))
        return stripped, frozenset(kept)
    return memo(ctx, "rn003:console", build)


_CONSOLE = re.compile(r"(?<![\w$.])console\s*\.\s*(log|info|debug|warn|error|trace|dir)\s*\(")
_INTERCEPTOR = re.compile(r"\binterceptors\s*\.\s*(request|response)\s*\.\s*use\s*\(")
_SENSITIVE_PART = re.compile(r"\.\s*(?:headers|data|body|_bodyInit|params)\b|\bAuthorization\b|\bJSON\s*\.\s*stringify\s*\(")
_PARAMS = re.compile(r"^\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)")


def _function_body(code: str, blank: str, span: Tuple[int, int]) -> Optional[Tuple[int, int, str]]:
    """(start, end, first parameter) of an inline function in an argument span."""
    a, b = span
    text = blank[a:b]
    arrow = text.find("=>")
    func = re.match(r"\s*(?:async\s+)?function\b", text)
    if arrow < 0 and not func:
        return None
    pm = _PARAMS.match(text)
    param = pm.group(1) if pm else ""
    if param in ("async", "function"):
        param = ""
    return a, b, param


_FUNCTION_DEF = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)?"
                           r"|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(?\s*"
                           r"([A-Za-z_$][\w$]*)?")


def _named_function(blank: str, name: str) -> Optional[Tuple[int, int, str]]:
    """(body start, body end, first parameter) of a function declared in the file. The file's declarations
    are indexed once, so many interceptors that name a handler don't each search the whole file."""
    def build() -> dict:
        table: dict = {}
        for m in _FUNCTION_DEF.finditer(blank):
            table.setdefault(m.group(1) or m.group(3), (m.end(), m.group(2) or m.group(4) or ""))
        return table
    found = text_memo(blank, ("rn003:functions",), build).get(name)
    if not found:
        return None
    end, param = found
    brace = blank.find("{", end, end + 400)
    if brace < 0:
        return None
    close = bracket_match(blank, brace, "{", "}")
    return (brace, close, param) if close < len(blank) else None


def _logs_request(code: str, blank: str, body: Tuple[int, int, str], kept: Optional[FrozenSet[str]]) -> str:
    """The console call in a handler body that prints headers, bodies, or a whole request, response, or
    error object (an axios error carries its request's headers). '' if none, or if it is debug-only or the
    release build strips it. `kept` is None when the release build keeps every console call."""
    a, b, param = body
    for m in _CONSOLE.finditer(blank, a, b):
        if kept is not None and m.group(1) not in kept:
            continue
        args = call_args(blank, m.end() - 1)
        if not args:
            continue
        text = code[args[0][0]:args[-1][1]]
        risky = bool(_SENSITIVE_PART.search(text))
        if not risky and param:
            for x, y in args:
                arg = code[x:y].strip()
                if re.fullmatch(re.escape(param) + r"(?:\s*\??\.\s*(?:request|response|config))?", arg):
                    risky = True
        if not risky or dev_only(code, blank, m.start()):
            continue
        return code[m.start():m.end() - 1].replace(" ", "")
    return ""


def _axios_logger_names(code: str) -> Set[str]:
    return {local for local, (module, _imported) in imports(code).items() if module == "axios-logger"}


def _http_log_hits(ctx: Context, path: str, kept: Optional[FrozenSet[str]]) -> Iterator[Tuple[int, str]]:
    raw = ctx.text(path) or ""
    if "interceptors" not in raw and "redux-logger" not in raw and "react-native-network-logger" not in raw:
        return
    code = ctx.code(path) or ""
    blank = ctx.code(path, False) or ""
    if "interceptors" in raw:
        ax_logger = _axios_logger_names(code)
        for m in _INTERCEPTOR.finditer(blank):
            if dev_only(code, blank, m.start()):
                continue
            for span in call_args(blank, m.end() - 1)[:2]:
                arg = blank[span[0]:span[1]].strip()
                root = re.split(r"\s*\.\s*", arg, maxsplit=1)[0]
                if root in ax_logger:
                    yield m.start(), (f"The axios {m.group(1)} interceptor uses axios-logger, which prints each "
                                      "request with its body in every build.")
                    break
                body = _function_body(code, blank, span)
                if body is None and re.fullmatch(r"[A-Za-z_$][\w$]*", arg):
                    body = _named_function(blank, arg)
                if body is None:
                    continue
                call = _logs_request(code, blank, body, kept)
                if call:
                    yield m.start(), (f"The axios {m.group(1)} interceptor passes headers, bodies, or the whole "
                                      f"request to `{call}` in every build, so tokens and personal data reach the "
                                      "device log.")
                    break
    names = imports(code)
    if "redux-logger" in raw and (kept is None or "log" in kept):
        loggers = {local for local, (module, imported) in names.items()
                   if module == "redux-logger" and imported in ("default", "logger")}
        for local, (module, imported) in names.items():
            if module == "redux-logger" and imported == "createLogger":
                for c in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*" + re.escape(local) + r"\s*\(",
                                     blank):
                    loggers.add(c.group(1))
        if loggers:
            use = re.compile(r"[(\[,]\s*(?:\.\.\.\s*)?(" + "|".join(re.escape(x) for x in loggers) +
                             r")(?![\w$])(?!\s*[.(=:])")
            for m in use.finditer(blank):
                if dev_only(code, blank, m.start(1)):
                    continue
                yield m.start(1), ("redux-logger is added to the store in every build. It prints every action "
                                   "and state change, including API responses and tokens kept in the store.")
    if "react-native-network-logger" in raw:
        starts = [local for local, (module, imported) in names.items()
                  if module == "react-native-network-logger" and imported == "startNetworkLogging"]
        for local in starts:
            for m in re.finditer(r"(?<![\w$.])" + re.escape(local) + r"\s*\(", blank):
                if not dev_only(code, blank, m.start()):
                    yield m.start(), ("`startNetworkLogging()` runs in every build: react-native-network-logger "
                                      "records each request and response, headers and bodies included, and "
                                      "shows them in the app.")


@detector("rn_http_logging")
def http_logging(ctx: Context, rule: Rule) -> Iterable[Hit]:
    stripped, kept_methods = _console_stripping(ctx)
    kept = kept_methods if stripped else None
    for path in js_files(ctx):
        if scope_of(path) == "test":
            continue
        seen: Set[int] = set()
        for offset, message in _http_log_hits(ctx, path, kept):
            code = ctx.code(path) or ""
            line = ctx.line_of(code, offset)
            if line not in seen:
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), message)


# ---------------------------------------------------------------------------- RN-004

_SSL_PINNING = ("react-native-ssl-pinning",)
_BLOB = ("rn-fetch-blob", "react-native-blob-util", "react-native-fetch-blob")
_DISABLE_ALL = re.compile(r"(?<![\w$])['\"]?disableAllSecurity['\"]?\s*:\s*true\b")
_TRUSTY = re.compile(r"(?<![\w$])['\"]?trusty['\"]?\s*:\s*true\b")


@detector("rn_trust_any_cert")
def trust_any_cert(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in js_files(ctx):
        if scope_of(path) == "test":
            continue
        raw = ctx.text(path) or ""
        checks = []
        if "disableAllSecurity" in raw and any(m in raw for m in _SSL_PINNING):
            checks.append((_DISABLE_ALL, _SSL_PINNING,
                           "`disableAllSecurity: true` makes react-native-ssl-pinning accept any certificate, so "
                           "anyone on the network can read and change this traffic."))
        if "trusty" in raw and any(m in raw for m in _BLOB):
            checks.append((_TRUSTY, _BLOB,
                           "`trusty: true` makes the blob client accept any certificate, including a self-signed "
                           "one from whoever is on the network."))
        if not checks:
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, False) or ""
        modules = {module for module, _name in imports(code).values()}
        seen: Set[int] = set()
        for rx, libs, message in checks:
            if not modules & set(libs):
                continue
            for m in rx.finditer(code):
                if blank[m.end() - 4:m.end()] != "true":
                    continue                            # the text is inside a string
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), message,
                          scope="debug" if dev_only(code, blank, m.start()) else "")


# ---------------------------------------------------------------------------- RN-019

_GIT_SPEC = re.compile(r"^(?:git\+[a-z]+://|git://|git@|github:|gitlab:|bitbucket:|gist:)", re.IGNORECASE)
_SHORTHAND = re.compile(r"^[A-Za-z0-9][\w.\-]{0,100}/[\w.\-]{1,100}(?:#.*)?$")
_COMMIT = re.compile(r"^(?:commit=)?[0-9a-fA-F]{6,40}$")
_LOCAL_HOST = re.compile(r"^https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|10\.\d+\.\d+\.\d+|"
                         r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[\w.\-]+\.(?:local|localhost|"
                         r"internal|lan|test))(?::\d+)?(?:/|$)", re.IGNORECASE)
_UNBOUNDED = {"*", "latest", "", "x", "next"}


def _spec_problem(spec: str, shipped: bool) -> str:
    s = spec.strip()
    low = s.lower()
    if low.startswith(("npm:", "workspace:", "file:", "link:", "portal:", "patch:", "exec:", ".", "/", "~/")):
        return ""
    if low.startswith("http://") or low.startswith("git+http://"):
        return "is downloaded over plain HTTP, so anyone on the network can swap it"
    if _GIT_SPEC.match(s) or _SHORTHAND.match(s):
        ref = s.split("#", 1)[1] if "#" in s else ""
        if ref.startswith("semver:"):
            return "comes from a git repository by version range, not a commit"
        if not ref:
            return "comes from a git repository's default branch, which can change under you"
        if not _COMMIT.match(ref):
            return f"comes from git at `{ref[:60]}`, a branch or tag that can be moved to other code"
        return ""
    if shipped and low in _UNBOUNDED:
        return f"accepts any version (`{s or 'empty'}`), so a new release is installed without review"
    return ""


def _package_json_hits(ctx: Context, path: str) -> Iterator[Hit]:
    text = ctx.text(path) or ""
    if len(text) > safety.MAX_FILE_BYTES:
        return
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return
    if not isinstance(data, dict):
        return
    offsets: Dict[Tuple[str, str], int] = {}
    for m in re.finditer(r"\"((?:[^\"\\\n]|\\.){1,300})\"\s*:\s*\"((?:[^\"\\\n]|\\.){0,1000})\"", text):
        offsets.setdefault((m.group(1), m.group(2)), m.start())
    for section in ("dependencies", "optionalDependencies", "devDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in list(block.items())[:2000]:
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            problem = _spec_problem(spec, section != "devDependencies")
            if not problem:
                continue
            at = offsets.get((name, spec))
            line = ctx.line_of(text, at) if at is not None else 1
            yield Hit(path, line, ctx.snippet(path, line), f"`{name}` {problem}.")


_NPMRC = re.compile(r"^\.npmrc$|^\.yarnrc$")
_NPMRC_LINE = re.compile(r"^[ \t]*([^=\s#;][^=\n]{0,300}?)[ \t]*=[ \t]*([^\n]{0,1000})$", re.MULTILINE)
_YARNRC_V1_LINE = re.compile(r"^[ \t]*([\w\-@/:.\"]{1,300})[ \t]+([^\n]{1,1000})$", re.MULTILINE)
_YARNRC_YML_LINE = re.compile(r"^[ \t]*([A-Za-z]\w{0,60})[ \t]*:[ \t]*([^\n#]{0,1000})", re.MULTILINE)


def _clean(value: str) -> str:
    return value.strip().strip("'\"").strip()


def _registry_problem(key: str, value: str) -> str:
    k = key.strip().strip('"').lower()
    v = _clean(value)
    lv = v.lower()
    if k in ("strict-ssl", "enablestrictssl") and lv == "false":
        return "turns off TLS certificate checks for package downloads, so anyone on the network can swap packages"
    if (k == "registry" or k.endswith(":registry") or k == "npmregistryserver") and lv.startswith("http://") \
            and not _LOCAL_HOST.match(v):
        return "points the package registry at a plain-HTTP address, so anyone on the network can swap packages"
    if (k.endswith("_authtoken") or k.endswith(":_auth") or k in ("_auth", "_password") or k.endswith(":_password")
            or k == "npmauthtoken") and "${" not in v and looks_secret(v):
        return "commits a registry token to the repository; anyone who can read the repository can publish or " \
               "read packages as you"
    return ""


def _npmrc_hits(ctx: Context, path: str) -> Iterator[Hit]:
    text = ctx.text(path) or ""
    rx = _NPMRC_LINE if path.endswith(".npmrc") else _YARNRC_V1_LINE
    for m in rx.finditer(text[:safety.MAX_FILE_BYTES]):
        problem = _registry_problem(m.group(1), m.group(2))
        if problem:
            line = ctx.line_of(text, m.start())
            value = _clean(m.group(2))
            snippet = ctx.snippet(path, line)
            if "token" in problem and value in snippet:
                snippet = snippet.replace(value, value[:4] + "…[masked]")
            yield Hit(path, line, snippet, f"This setting {problem}.")


def _yarnrc_yml_hits(ctx: Context, path: str) -> Iterator[Hit]:
    text = ctx.text(path) or ""
    for m in _YARNRC_YML_LINE.finditer(text[:safety.MAX_FILE_BYTES]):
        key, value = m.group(1), m.group(2)
        problem = _registry_problem(key, value)
        if not problem and key == "unsafeHttpWhitelist":
            rest = value.strip() or re.split(r"\n(?=\S)", text[m.end():m.end() + 300], maxsplit=1)[0]
            if re.search(r"""(?:^|[\[\s,-])["']?\*["']?(?:[\],\s]|$)""", rest):
                problem = "allows plain HTTP for every host (`*`), so anyone on the network can swap packages"
        if not problem and key == "checksumBehavior" and _clean(value).lower() in ("ignore", "update"):
            problem = "tells Yarn to accept a package whose checksum doesn't match the lockfile"
        if problem:
            line = ctx.line_of(text, m.start())
            snippet = ctx.snippet(path, line)
            if "token" in problem:
                snippet = snippet.replace(_clean(value), _clean(value)[:4] + "…[masked]")
            yield Hit(path, line, snippet, f"This setting {problem}.")


@detector("rn_npm_sources")
def npm_sources(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(name="package.json"):
        if scope_of(path) != "test":
            yield from _package_json_hits(ctx, path)
    done: Set[str] = set()
    for dir_ in package_dirs(ctx):
        for path in dotfiles(ctx, dir_, _NPMRC):
            if path not in done:
                done.add(path)
                yield from _npmrc_hits(ctx, path)
    for path in ctx.files(name=".yarnrc.yml"):
        if scope_of(path) != "test":
            yield from _yarnrc_yml_hits(ctx, path)

