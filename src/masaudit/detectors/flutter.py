# SPDX-License-Identifier: Apache-2.0
"""Flutter (Dart) detectors: TLS bypass in `badCertificateCallback`, tokens in shared_preferences,
the Dart-side pinning evidence the Android and iOS pinning rules use, Dio logging, web view settings,
biometric checks, and release obfuscation. Book: §7.1, §6.4, §6.6, §8.10, §11.1, §14.3, §16.3-16.6.

Dart's `HttpClient` brings its own TLS stack, so `<pin-set>` and NSPinnedDomains don't cover it
(book §8.10, MASTG-KNOW-0015). Every detector runs on code with comments blanked.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.detect import scope_of as _scope_of
from masaudit.guards import dart_debug, guarded_by
from masaudit.textscan import bracket_match, found_in_span, name_index
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule


_SCOPES: Dict[str, str] = {}


def scope_of(path: str) -> str:
    """detect.scope_of, memoised: detectors ask it about the same paths many times per scan."""
    s = _SCOPES.get(path)
    if s is None:
        if len(_SCOPES) >= 200_000:
            _SCOPES.clear()
        s = _SCOPES[path] = _scope_of(path)
    return s


DART = (".dart",)


def is_flutter(ctx: Context) -> bool:
    return bool(ctx.files(name="pubspec.yaml"))


def _pubspec_deps(ctx: Context) -> str:
    """Every pubspec.yaml in the project, with YAML comments removed."""
    return "\n".join(re.sub(r"#[^\n]*", "", ctx.text(p) or "") for p in ctx.files(name="pubspec.yaml"))


# ---------------------------------------------------------------------------- pinning evidence

# Identifiers only (strings and comments blanked), so a TODO that mentions pinning doesn't count.
_DART_PIN_CODE = re.compile(
    r"\bsetTrustedCertificates(?:Bytes)?\s*\(|\bwithTrustedRoots\s*:\s*false\b|\bvalidateCertificate\s*:"
    r"|\bHttpCertificatePinning\b|\bSslPinningPlugin\b|\bCertificatePinningInterceptor\b|\b\w*Pinning\w*\b"
)
_DART_PIN_DEPS = re.compile(r"^[ \t]+[\w]*(?:pinning|pinner)[\w]*[ \t]*:", re.MULTILINE | re.IGNORECASE)
# HTTP clients that use the platform's networking, so native pinning configuration covers them.
_NATIVE_HTTP_DEPS = re.compile(r"^[ \t]+(?:cronet_http|cupertino_http|native_dio_adapter)[ \t]*:", re.MULTILINE)


def dart_pinning_evidence(ctx: Context) -> bool:
    if _DART_PIN_DEPS.search(_pubspec_deps(ctx)):
        return True
    for path in ctx.files(*DART):
        if scope_of(path) == "test":
            continue
        if _DART_PIN_CODE.search(ctx.code(path, keep_strings=False) or ""):
            return True
    return False


def uses_native_http(ctx: Context) -> bool:
    return bool(_NATIVE_HTTP_DEPS.search(_pubspec_deps(ctx)))


# ---------------------------------------------------------------------------- FLT-001

_RETURNS_TRUE = r"(?:=>\s*\(?\s*true\b(?!\s*[&|?=!<>])|\{\s*return\s+true\s*;\s*\})"
BAD_CERT_INLINE = re.compile(r"\bbadCertificateCallback\s*=\s*\(?\s*\([^()]*\)\s*" + _RETURNS_TRUE)
BAD_CERT_REF = re.compile(r"\bbadCertificateCallback\s*=\s*([A-Za-z_]\w*)\s*[;),]")


def _function_returns_true(code: str, name: str) -> bool:
    return name in name_index(code, r"\s*\([^()]*\)\s*" + _RETURNS_TRUE)


@detector("flutter_trust_all")
def trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = ("`badCertificateCallback` returns true, so Dart's HttpClient accepts any certificate, "
           "including a self-signed one from whoever is on the network.")
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "badCertificateCallback" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in BAD_CERT_INLINE.finditer(code):
            seen.add(ctx.line_of(code, m.start()))
        for m in BAD_CERT_REF.finditer(code):
            if m.group(1) not in ("null", "true", "false") and _function_returns_true(code, m.group(1)):
                seen.add(ctx.line_of(code, m.start()))
        for line in sorted(seen):
            yield Hit(path, line, ctx.snippet(path, line), msg)


# ---------------------------------------------------------------------------- FLT-002

_SENSITIVE = re.compile(r"(?i)token|password|passwd|secret|jwt|credential|api_?key")
_NOT_SECRET = re.compile(r"(?i)fcm|apns|push|device|expir")
_NOT_SECRET_KEY = re.compile(r"(?i)(?:type|version|policy|hint|length)$")   # token_type, password_policy_version
# A constant value (a plain string, number, boolean, or null) is a setting, not a token someone received.
_LITERAL_VALUE = re.compile(r"""^\s*(?:'[^'$\\\n]*'|"[^"$\\\n]*"|-?\d[\d.]*|true|false|null)\s*\)?\s*$""")
_SET_CALL = re.compile(
    r"\.\s*set(?:String|StringList)\s*\(\s*(?:[\"']([^\"'\n]*)[\"']|([A-Za-z_][\w.]*))\s*,\s*([^,;\n]*)"
)


def _key_text(code: str, literal: Optional[str], ident: Optional[str]) -> str:
    """The key's text: a literal, a constant resolved in the same file, or the constant's name."""
    if literal is not None:
        return literal
    name = (ident or "").rsplit(".", 1)[-1]
    m = name_index(code, r"\s*=\s*[\"']([^\"'\n]*)[\"']").get(name)
    return m.group(2) if m else name


@detector("flutter_prefs_token")
def prefs_token(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "SharedPreferences" not in raw and "shared_preferences" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        bare = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in _SET_CALL.finditer(code):
            key = _key_text(code, m.group(1), m.group(2))
            value = bare[m.start(3):m.end(3)]                 # the value expression, strings blanked
            names = [w for w in re.findall(r"[A-Za-z_]\w*", value) if _SENSITIVE.search(w)]
            what = key if _SENSITIVE.search(key) else names[0] if names else ""
            if not what or _NOT_SECRET.search(key) or _NOT_SECRET.search(value) \
                    or (what == key and _NOT_SECRET_KEY.search(key)):          # `token_type`, not `auth_type: token`
                continue
            if _LITERAL_VALUE.match(code[m.start(3):m.end(3)]):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"`{what}` looks like a token or secret and is written to shared_preferences.")


# ---------------------------------------------------------------------------- shared helpers

_ASSERT = re.compile(r"\bassert\s*\(")


def _release_off(blank: str, idx: int) -> bool:
    """Debug-only Dart code: `if (kDebugMode)`, `if (kProfileMode)`, `if (!kReleaseMode)`, or inside
    `assert(...)`, whose body is compiled out of release builds."""
    if guarded_by(blank, idx, dart_debug):            # guards.dart_debug_guarded
        return True
    if guarded_by(blank, idx, lambda c: "!kReleaseMode" in c and "&&" not in c):
        return True
    for m in _ASSERT.finditer(blank, max(0, idx - 4000), idx):
        if bracket_match(blank, m.end() - 1, "(", ")") > idx:
            return True
    return False


def _args_span(blank: str, open_paren: int) -> Tuple[int, int]:
    """Where the argument list opening at `open_paren` sits: `(` up to its `)`, or the end of the file."""
    return open_paren, min(len(blank), bracket_match(blank, open_paren, "(", ")") + 1)


def _hit_at(ctx: Context, path: str, blank: str, idx: int, message: str) -> Hit:
    line = ctx.line_of(blank, idx)
    scope = "debug" if _release_off(blank, idx) else ""
    return Hit(path, line, ctx.snippet(path, line), message, scope=scope)


def _pubspec_dir_of(ctx: Context, path: str) -> Optional[str]:
    """Directory (relative, '' for the root) of the nearest pubspec.yaml above `path`."""
    dirs = {p.rsplit("/", 1)[0] if "/" in p else "" for p in ctx.files(name="pubspec.yaml")}
    cur = path.rsplit("/", 1)[0] if "/" in path else ""
    while True:
        if cur in dirs:
            return cur
        if not cur:
            return None
        cur = cur.rsplit("/", 1)[0] if "/" in cur else ""


def _locked_version(ctx: Context, pubspec_dir: Optional[str], package: str) -> Tuple[int, ...]:
    """The version pubspec.lock resolves for `package`, or () when there is no lock or no entry.
    safety.walk skips .lock files, so the lock is read by name next to its pubspec.yaml."""
    if pubspec_dir is None:
        return ()
    rel = (pubspec_dir + "/" if pubspec_dir else "") + "pubspec.lock"
    text = safety.read_text(ctx.root, rel)
    if not text:
        return ()
    in_pkg = False
    for line in text.splitlines():
        if re.match(r"^  \S", line):
            in_pkg = line.strip() == package + ":"
        elif in_pkg:
            m = re.match(r'^    version:\s*"?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?!\d)', line)
            if m:
                return tuple(int(x) for x in m.groups())
    return ()


def _arg(blank: str, span: Tuple[int, int], name: str, value: str) -> bool:
    """Is `name: value` among the arguments in `span`? (A lookup, not a scan of the arguments: an unclosed
    call's arguments run to the end of the file, and a scan per call made such files quadratic.)"""
    return found_in_span(blank, re.compile(r"\b" + name + r"\s*:\s*" + value + r"\b"), *span)


# ---------------------------------------------------------------------------- FLT-003

_PRETTY = re.compile(r"\bPrettyDioLogger\s*\(")
_LOG_INTERCEPTOR = re.compile(r"\bLogInterceptor\s*\(")
_LOG_PRINT = re.compile(r"\blogPrint\s*:")


@detector("flutter_dio_logger")
def dio_logger(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "PrettyDioLogger" not in raw and "LogInterceptor" not in raw:
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in _PRETTY.finditer(blank):
            args = _args_span(blank, m.end() - 1)
            # Defaults: response bodies on; headers and request bodies off.
            if (_arg(blank, args, "responseBody", "false") and not _arg(blank, args, "requestHeader", "true")
                    and not _arg(blank, args, "requestBody", "true")
                    and not _arg(blank, args, "responseHeader", "true")):
                continue
            yield _hit_at(ctx, path, blank, m.start(),
                          "PrettyDioLogger prints requests and responses with `print`, which reaches the "
                          "device log in release builds.")
        version: Optional[Tuple[int, ...]] = None
        for m in _LOG_INTERCEPTOR.finditer(blank):
            args = _args_span(blank, m.end() - 1)
            # Defaults: request and response headers on; bodies off.
            if (_arg(blank, args, "requestHeader", "false") and _arg(blank, args, "responseHeader", "false")
                    and not _arg(blank, args, "requestBody", "true")
                    and not _arg(blank, args, "responseBody", "true")):
                continue
            if found_in_span(blank, _LOG_PRINT, *args):
                msg = ("LogInterceptor sends headers, including `Authorization`, to a custom `logPrint` "
                       "that also runs in release builds.")
            else:
                if version is None:
                    version = _locked_version(ctx, _pubspec_dir_of(ctx, path), "dio")
                if not version or version[0] >= 5:
                    continue                     # dio 5 prints only inside assert(), so not in release
                msg = (f"LogInterceptor on dio {'.'.join(map(str, version))} prints headers, including "
                       "`Authorization`, with `print` in release builds.")
            yield _hit_at(ctx, path, blank, m.start(), msg)


# ---------------------------------------------------------------------------- FLT-004

_INAPP_SETTINGS = re.compile(
    r"\b(?:InAppWebViewSettings|InAppWebViewOptions|AndroidInAppWebViewOptions|InAppWebViewGroupOptions|"
    r"InAppBrowserClassSettings)\s*\("
)
_FILE_ORIGIN = re.compile(r"\b(allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)\s*[:=]\s*true\b")
_FILE_ACCESS = re.compile(r"\ballowFileAccess\s*[:=]\s*true\b")
_MIXED = re.compile(r"\bmixedContentMode\s*[:=]\s*(?:Android)?MixedContentMode\s*\.\s*MIXED_CONTENT_ALWAYS_ALLOW\b")


def _enclosing_settings(blank: str, idx: int) -> Tuple[int, int]:
    """Span of the arguments of the flutter_inappwebview settings call around `idx`; empty when there is none."""
    best = (idx, idx)
    for m in _INAPP_SETTINGS.finditer(blank, max(0, idx - 6000), idx):
        args = _args_span(blank, m.end() - 1)
        if args[1] > idx:
            best = args
    return best


@detector("flutter_webview_file_access")
def webview_file_access(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if not any(k in raw for k in ("allowFileAccess", "allowUniversalAccess", "MIXED_CONTENT_ALWAYS_ALLOW")):
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        found = []
        for m in _FILE_ORIGIN.finditer(blank):
            found.append((m.start(), f"`{m.group(1)}` is on, so a page loaded from a file can read other "
                                     "local files and send them anywhere."))
        for m in _MIXED.finditer(blank):
            found.append((m.start(), "`MIXED_CONTENT_ALWAYS_ALLOW` lets an HTTPS page load scripts over plain "
                                     "HTTP, which anyone on the network can replace."))
        for m in _FILE_ACCESS.finditer(blank):
            if _arg(blank, _enclosing_settings(blank, m.start()), "javaScriptEnabled", "false"):
                continue                         # JavaScript is on by default in flutter_inappwebview
            found.append((m.start(), "`allowFileAccess` is on with JavaScript enabled, so page scripts can "
                                     "read local files through `file://` URLs."))
        seen: Set[int] = set()
        for idx, msg in sorted(found):
            line = ctx.line_of(blank, idx)
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, blank, idx, msg)


# ---------------------------------------------------------------------------- FLT-005

_TRUST_HANDLER = re.compile(
    r"\b(onReceivedServerTrustAuthRequest|androidOnReceivedServerTrustAuthRequest|onReceivedSslError|"
    r"onSslAuthError)\s*:\s*"
)
_PROCEEDS = re.compile(r"\bServerTrustAuthResponseAction\s*\.\s*PROCEED\b|\.\s*proceed\s*\(\s*\)")
_CONDITION = re.compile(r"\bif\s*\(|\bswitch\s*\(|\?\s*[^.?\s]|==|!=|&&|\|\||\bcase\b")
_BODY_START = re.compile(r"\s*(?:async\s*)?(\{|=>)")


def _closure_body(blank: str, start: int) -> Tuple[int, int]:
    """Span of the body of the closure, or of the named function, passed as a handler at `start`."""
    ref = re.compile(r"([A-Za-z_]\w*)\s*[,)]").match(blank, start)
    if ref:                                      # a function reference: find its declaration
        decl = name_index(blank, r"\s*\([^()]*\)\s*(?:async\s*)?(\{|=>)").get(ref.group(1))
        if not decl:
            return start, start
        at = decl.start(2)
    else:
        if not blank.startswith("(", start):
            return start, start
        m = _BODY_START.match(blank, bracket_match(blank, start, "(", ")") + 1)
        if not m:
            return start, start
        at = m.start(1)
    if blank.startswith("{", at):
        return at, min(len(blank), bracket_match(blank, at, "{", "}") + 1)
    depth = 0                                    # arrow body: up to the `,` or `)` that ends it
    for j in range(at + 2, min(len(blank), at + 3000)):
        c = blank[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return at, j
            depth -= 1
        elif c in ",;" and depth == 0:
            return at, j
    return at, min(len(blank), at + 3000)


def _body_has(blank: str, rx: "re.Pattern[str]", span: Tuple[int, int]) -> bool:
    if span[1] - span[0] <= 3000:                # arrow bodies and short blocks: search the slice
        return rx.search(blank[span[0]:span[1]]) is not None
    return found_in_span(blank, rx, *span)       # a long `{...}` block, which may hold many other handlers


@detector("flutter_webview_trust_all")
def webview_trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "PROCEED" not in raw and "proceed" not in raw:
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in _TRUST_HANDLER.finditer(blank):
            body = _closure_body(blank, m.end())
            if not _body_has(blank, _PROCEEDS, body) or _body_has(blank, _CONDITION, body):
                continue
            yield _hit_at(ctx, path, blank, m.start(),
                          f"`{m.group(1)}` proceeds without checking the certificate, so the web view "
                          "trusts any server, including an attacker's.")


# ---------------------------------------------------------------------------- FLT-006

_WEB_DEBUG = re.compile(
    r"\b(?:Android)?InAppWebViewController\s*\.\s*setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"
    r"|\bisInspectable\s*[:=]\s*true\b"
    r"|\bAndroidWebViewController\s*\.\s*enableDebugging\s*\(\s*true\s*\)"
    r"|\.\s*setInspectable\s*\(\s*true\s*\)"
)


@detector("flutter_webview_debugging")
def webview_debugging(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if not any(k in raw for k in ("DebuggingEnabled", "isInspectable", "enableDebugging", "setInspectable")):
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in _WEB_DEBUG.finditer(blank):
            yield _hit_at(ctx, path, blank, m.start(),
                          "Web view debugging is on, so anyone holding the device can attach DevTools or "
                          "Safari and read or change the page, including its tokens.")


# ---------------------------------------------------------------------------- FLT-007

_LOCAL_AUTH_CALL = re.compile(
    r"\bLocalAuthentication\s*\(\s*\)\s*\.\s*authenticate\s*\(|\.\s*authenticate\s*\(\s*localizedReason\s*:"
)
_DART_BOUND = re.compile(
    r"\bBiometricStorage\b|\bauthenticationRequired\s*:\s*true\b|\baccessControlFlags\s*:"
    r"|\bAndroidOptions\s*\.\s*biometric\b|\benforceBiometrics\s*:\s*true\b"
)
_NATIVE_BOUND = re.compile(r"\bCryptoObject\b|\bSecAccessControlCreateWithFlags\b|\bkSecAttrAccessControl\b")


def _bound_evidence(ctx: Context) -> bool:
    if re.search(r"^[ \t]+biometric_storage[ \t]*:", _pubspec_deps(ctx), re.MULTILINE):
        return True
    for path in ctx.files(".dart", ".kt", ".java", ".swift", ".m", ".mm"):
        regex = _DART_BOUND if path.endswith(".dart") else _NATIVE_BOUND
        if scope_of(path) == "test" or not regex.search(ctx.text(path) or ""):
            continue
        if regex.search(ctx.code(path, keep_strings=False) or ""):
            return True
    return False


@detector("flutter_biometric_boolean")
def biometric_boolean(ctx: Context, rule: Rule) -> Iterable[Hit]:
    hits = []
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "authenticate" not in raw or ("local_auth" not in raw and "LocalAuthentication" not in raw):
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in _LOCAL_AUTH_CALL.finditer(blank):
            line = ctx.line_of(blank, m.start())
            hits.append(Hit(path, line, ctx.snippet(path, line),
                            "local_auth's `authenticate()` only returns true or false. A hooked app returns "
                            "true and nothing needs decrypting, so the check protects nothing."))
    if hits and not _bound_evidence(ctx):
        yield from hits


# ---------------------------------------------------------------------------- FLT-008

_FLUTTER_BUILD = re.compile(r"\bflutter\s+build\s+(apk|appbundle|ipa|ios)\b([^\n]*)")
_BUILD_CMD = re.compile(r"\bflutter\s+build\b")
_YAML_COMMENT = re.compile(r"(^|[ \t])#[^\n]*", re.MULTILINE)


_FOLDED_HEADER = re.compile(r"(?:^|[\s:-])>[-+]?[0-9]?\s*$")
_FOLD_LINES = 50                                 # lines a folded command may span, at most


def _folded_lines(text: str) -> Dict[int, int]:
    """{line start offset: content indent} for the lines of YAML folded blocks (`run: >`), in one pass."""
    out: Dict[int, int] = {}
    header, content = -1, -1                     # the open block's header indent and content indent
    pos = 0
    for line in text.split("\n"):
        indent = len(line) - len(line.lstrip(" "))
        if line.strip():
            if header >= 0 and indent > header:
                if content < 0:
                    content = indent
                out[pos] = content
            else:
                header, content = (indent, -1) if _FOLDED_HEADER.search(line) else (-1, -1)
        pos += len(line) + 1
    return out


def _folded_rest(text: str, folded: Dict[int, int], start: int, end: int) -> str:
    """The lines a folded block joins onto the command at `start`: in a `>` block, line breaks between lines
    of the block's indent become spaces, so `--obfuscate` on the next line belongs to the same command. A
    blank line, a more-indented line, or another `flutter build` ends it."""
    line_start = text.rfind("\n", 0, start) + 1
    indent = folded.get(line_start)
    if indent is None or len(text[line_start:start]) - len(text[line_start:start].lstrip(" ")) != indent:
        return ""
    rest: List[str] = []
    pos = end + 1
    while pos < len(text) and len(rest) < _FOLD_LINES:
        nxt = text.find("\n", pos)
        nxt = len(text) if nxt < 0 else nxt
        line = text[pos:nxt]
        if folded.get(pos) != indent or len(line) - len(line.lstrip(" ")) != indent or _BUILD_CMD.search(line):
            break
        rest.append(line.strip())
        pos = nxt + 1
    return " " + " ".join(rest) if rest else ""


@detector("flutter_obfuscation")
def obfuscation(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if not is_flutter(ctx):
        return
    scripted = False
    for path in ctx.files(".yml", ".yaml"):
        raw = ctx.text(path) or ""
        if "flutter" not in raw or not _BUILD_CMD.search(raw):
            continue
        text = _YAML_COMMENT.sub(lambda m: m.group(1) + " " * (len(m.group(0)) - len(m.group(1))), raw)
        if not _BUILD_CMD.search(text):
            continue
        scripted = True
        missing = []
        folded = _folded_lines(text)
        for m in _FLUTTER_BUILD.finditer(text):
            args = m.group(2)
            end = m.end()
            while args.rstrip().endswith("\\") and end < len(text):    # shell line continuations
                nxt = text.find("\n", end + 1)
                nxt = len(text) if nxt < 0 else nxt
                args = args.rstrip()[:-1] + " " + text[end + 1:nxt]
                end = nxt
            args += _folded_rest(text, folded, m.start(), end)
            # `--debug` builds, and `${{ ... }}` standing alone where it may hold the flags (an expression
            # inside one flag, `--build-number=${{ github.run_number }}`, can't).
            if re.search(r"--(?:debug|profile|config-only)\b|(?:^|\s)\"?\$\{\{", args):
                continue
            if re.search(r"(?:^|\s)\"?\$\{?[A-Za-z_]", args):
                continue                         # flags passed through a variable can't be read
            if "--obfuscate" in args and "--split-debug-info" in args:
                continue
            missing.append(m)
        if missing:
            line = ctx.line_of(text, missing[0].start())
            more = f" ({len(missing)} build commands in this file)" if len(missing) > 1 else ""
            yield Hit(path, line, ctx.snippet(path, line),
                      f"`flutter build {missing[0].group(1)}` runs without `--obfuscate "
                      f"--split-debug-info`{more}, so class and function names ship readable.")
    if not scripted:
        ctx.note_unknown("No `flutter build` command was found in the scanned workflow files; check that "
                         "release builds pass `--obfuscate --split-debug-info`.")
