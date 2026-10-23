# SPDX-License-Identifier: Apache-2.0
"""iOS detectors: Info.plist / ATS, project.pbxproj and .xcconfig build settings, and Swift or
Objective-C code that needs more than a single regex (function bodies, #if DEBUG blocks)."""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.detectors import flutter
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.parsers import pbxproj, plist, xcconfig

CODE_SUFFIXES = (".swift", ".m", ".mm", ".h")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

# ============================================================================ shared helpers


def _cache(ctx: Context) -> Dict[str, Any]:
    c = getattr(ctx, "_ios_cache", None)
    if c is None:
        c = {}
        ctx._ios_cache = c  # type: ignore[attr-defined]
    return c


# ---------------------------------------------------------------------------- plists


@dataclass
class PlistDoc:
    path: str
    data: Any
    lines: Dict[tuple, int]

    def line(self, *path: Any) -> int:
        return plist.line_of(self.lines, *path)


def _plists(ctx: Context) -> List[PlistDoc]:
    cache = _cache(ctx)
    if "plists" not in cache:
        docs: List[PlistDoc] = []
        for path in ctx.files(".plist"):
            raw = safety.read_bytes(ctx.root, path)
            if not raw:
                continue
            data = plist.loads(raw)
            if data is None:
                ctx.note_unknown(f"Couldn't parse {path} (invalid plist, or it declares entities).")
                continue
            lines = {} if plist.is_binary(raw) else plist.key_lines(ctx.text(path) or "")
            docs.append(PlistDoc(path, data, lines))
        cache["plists"] = docs
    return cache["plists"]


def _shipping_plists(ctx: Context) -> List[PlistDoc]:
    """Plists that can end up in a release build (not referenced only by Debug configurations)."""
    debug_only = _debug_only_plists(ctx)
    return [d for d in _plists(ctx) if d.path not in debug_only]


def _ats_docs(ctx: Context) -> Iterator[Tuple[PlistDoc, Dict[str, Any]]]:
    for doc in _shipping_plists(ctx):
        ats = plist.get(doc.data, "NSAppTransportSecurity")
        if isinstance(ats, dict):
            yield doc, ats


def _plist_hit(ctx: Context, doc: PlistDoc, path: tuple, message: str) -> Hit:
    line = doc.line(*path)
    return Hit(doc.path, line, ctx.snippet(doc.path, line) if line else "", message)


# ---------------------------------------------------------------------------- Xcode projects


def _projects(ctx: Context) -> List[pbxproj.Project]:
    cache = _cache(ctx)
    if "projects" not in cache:
        out = []
        for path in ctx.files(name="project.pbxproj"):
            data = pbxproj.parse(ctx.text(path))
            if data is None:
                ctx.note_unknown(f"Couldn't parse {path} (not a valid project file).")
                continue
            out.append(pbxproj.Project(data, path))
        cache["projects"] = out
    return cache["projects"]


Value = Tuple[Optional[str], str, int]       # (value or None if not a string, file, line)


def _xc_layer(ctx: Context, rel: str) -> Dict[str, Value]:
    cache = _cache(ctx).setdefault("xc", {})
    if rel not in cache:
        unknowns: List[str] = []
        settings = xcconfig.resolve(ctx.root, rel, read=lambda r, p: ctx.text(p), unknowns=unknowns)
        for u in unknowns:
            ctx.note_unknown(u)
        cache[rel] = {k: (s.value, s.path, s.line) for k, s in settings.items()}
    return cache[rel]


def _pbx_layer(proj: pbxproj.Project, cfg: pbxproj.BuildConfig) -> Dict[str, Value]:
    out: Dict[str, Value] = {}
    for k, v in cfg.settings.items():
        if isinstance(v, list):
            v = " ".join(x for x in v if isinstance(x, str))
        out[k] = (v if isinstance(v, str) else None, proj.path, cfg.lines.get(k, cfg.line))
    return out


def _effective(ctx: Context, proj: pbxproj.Project, target: pbxproj.Target,
               cfg_name: str) -> Dict[str, Value]:
    """Build settings of one target in one configuration, lowest precedence first."""
    layers: List[Dict[str, Value]] = []
    pcfg = proj.project_configs().get(cfg_name)
    tcfg = target.configs.get(cfg_name)
    for cfg in (pcfg, tcfg):
        if cfg is None:
            continue
        if cfg.base_xcconfig:
            layers.append(_xc_layer(ctx, cfg.base_xcconfig))
        layers.append(_pbx_layer(proj, cfg))
    merged: Dict[str, Value] = {}
    for layer in layers:
        for k, v in layer.items():
            if v[0] is not None and v[0].strip() == "$(inherited)" and k in merged:
                continue
            merged[k] = v
    return merged


def _release_setting_sets(ctx: Context) -> Iterator[Tuple[str, Dict[str, Value]]]:
    """(label, settings) for every shipping configuration we can see.

    From each project: every non-test target in every configuration that isn't Debug-like.
    Plus root .xcconfig files no project references (XcodeGen/Tuist repos), unless their
    name says Debug.
    """
    referenced: Set[str] = set()
    for proj in _projects(ctx):
        configs = proj.project_configs()
        for cfg in configs.values():
            if cfg.base_xcconfig:
                referenced.add(cfg.base_xcconfig)
        for target in proj.targets():
            for cfg in target.configs.values():
                if cfg.base_xcconfig:
                    referenced.add(cfg.base_xcconfig)
            if target.is_test:
                continue
            for name in sorted(set(target.configs) | set(configs)):
                if pbxproj.is_debug_config(name):
                    continue
                yield f"{target.name} ({name})", _effective(ctx, proj, target, name)
    included: Set[str] = set()
    all_xc = ctx.files(".xcconfig")
    for path in all_xc:
        for inc, _opt, _line in xcconfig.parse(ctx.text(path) or "").includes:
            target_path = xcconfig.include_path(path, inc)
            if target_path:
                included.add(target_path)
    for path in all_xc:
        if path in referenced or path in included:
            continue
        stem = posixpath.splitext(posixpath.basename(path))[0]
        if pbxproj.is_debug_config(stem):
            continue
        yield path, _xc_layer(ctx, path)


def _setting_hits(ctx: Context, check: Callable[[str, str, Dict[str, Value]], Optional[str]],
                  keys: Callable[[str], bool]) -> Iterator[Hit]:
    seen: Set[Tuple[str, int]] = set()
    for label, settings in _release_setting_sets(ctx):
        for key, (value, path, line) in settings.items():
            if value is None or not keys(key):
                continue
            if xcconfig.is_unresolved(value):
                ctx.note_unknown(f"{key} in {label} is set from a variable ({value}); couldn't decide.")
                continue
            message = check(key, value, settings)
            if message and (path, line) not in seen:
                seen.add((path, line))
                yield Hit(path, line, ctx.snippet(path, line), f"{message} [{label}]")


def _debug_only_plists(ctx: Context) -> Set[str]:
    cache = _cache(ctx)
    if "debug_plists" not in cache:
        kinds: Dict[str, Set[bool]] = {}
        for proj in _projects(ctx):
            configs = proj.project_configs()
            for target in proj.targets():
                for name in set(target.configs) | set(configs):
                    value = _effective(ctx, proj, target, name).get("INFOPLIST_FILE", (None, "", 0))[0]
                    if not value:
                        continue
                    path = proj.settings_path(value)
                    if path is not None:
                        kinds.setdefault(path, set()).add(pbxproj.is_debug_config(name))
        cache["debug_plists"] = {p for p, k in kinds.items() if k == {True}}
    return cache["debug_plists"]


# ---------------------------------------------------------------------------- code


_PP = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elseif|elif|else|endif)\b([^\n]*)", re.MULTILINE)
_DEBUG_CONDS = {"DEBUG", "DEBUG==1", "definedDEBUG", "DEBUG!=0"}
_RELEASE_CONDS = {"!DEBUG", "!definedDEBUG", "DEBUG==0"}


def _cond_kind(directive: str, rest: str) -> Tuple[str, bool]:
    """('debug' | 'release' | 'other', pure) for a conditional-compilation line."""
    c = rest.split("//", 1)[0].strip()
    if directive == "ifdef":
        return ("debug" if c == "DEBUG" else "other"), True
    if directive == "ifndef":
        return ("release" if c == "DEBUG" else "other"), True
    norm = re.sub(r"[()\s]", "", c)
    if norm in _DEBUG_CONDS:
        return "debug", True
    if norm in _RELEASE_CONDS:
        return "release", True
    if "||" not in norm and any(part in _DEBUG_CONDS for part in norm.split("&&")):
        return "debug", False
    return "other", False


def _blank_debug(code: str) -> str:
    """Blank every line compiled only in DEBUG builds (#if DEBUG / #ifdef DEBUG / #else of !DEBUG)."""
    if "#" not in code:
        return code
    lines = code.split("\n")
    stack: List[List[Any]] = []          # [current_kind, if_kind, pure]
    out = []
    for line in lines:
        m = _PP.match(line)
        if m:
            d, rest = m.group(1), m.group(2)
            if d in ("if", "ifdef", "ifndef"):
                kind, pure = _cond_kind(d, rest)
                stack.append([kind, kind, pure])
            elif d in ("elseif", "elif") and stack:
                kind, _ = _cond_kind("if", rest)
                if stack[-1][1] == "release" and stack[-1][2]:
                    kind = "debug"
                stack[-1][0] = kind
                stack[-1][2] = False
            elif d == "else" and stack:
                top = stack[-1]
                if top[2] and top[1] == "debug":
                    top[0] = "release"
                elif top[2] and top[1] == "release":
                    top[0] = "debug"
                else:
                    top[0] = "other"
            elif d == "endif" and stack:
                stack.pop()
            out.append(line)
            continue
        if any(f[0] == "debug" for f in stack):
            out.append(" " * len(line))
        else:
            out.append(line)
    return "\n".join(out)


def _release_code(ctx: Context, path: str, keep_strings: bool = True) -> Optional[str]:
    """Code with comments blanked and DEBUG-only blocks blanked. Offsets match the raw file."""
    cache = _cache(ctx).setdefault("release_code", {})
    key = (path, keep_strings)
    if key not in cache:
        code = ctx.code(path, keep_strings=keep_strings)
        cache[key] = _blank_debug(code) if code is not None else None
    return cache[key]


def _body(code: str, start: int, max_gap: int = 800) -> Optional[Tuple[int, int]]:
    """Span of the brace-balanced block that starts after `start` (code must have strings blanked)."""
    i = code.find("{", start)
    if i == -1 or i - start > max_gap:
        return None
    depth = 0
    for j in range(i, len(code)):
        ch = code[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i, j + 1
    return None


def _functions(ctx: Context, signature: "re.Pattern[str]") -> Iterator[Tuple[str, int, str, str]]:
    """(path, line, body, whole_file) for each function whose signature matches, in shipping code."""
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or not signature.search(raw):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if code is None:
            continue
        for m in signature.finditer(code):
            span = _body(code, m.end())
            if span is None:
                continue
            yield path, ctx.line_of(code, m.start()), code[span[0]:span[1]], code


def _code_hits(ctx: Context, regex: "re.Pattern[str]", prefilter: str, message: str,
               keep_strings: bool = False) -> Iterator[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or prefilter not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=keep_strings)
        if code is None:
            continue
        for m in regex.finditer(code):
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line), message)


# ============================================================================ network


def _is_local(domain: str) -> bool:
    d = domain.strip().lower()
    return d in LOCAL_HOSTS or d.endswith((".local", ".localhost", ".test"))


_ATS_KEY = re.compile(
    r"^INFOPLIST_KEY_(?:NSAppTransportSecurity_)?(NSAllowsArbitraryLoads|NSAllowsArbitraryLoadsInWebContent)$"
)


@detector("ios_ats_arbitrary_loads")
def ats_arbitrary_loads(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        web = plist.truthy(ats.get("NSAllowsArbitraryLoadsInWebContent"))
        # On iOS 10+, NSAllowsArbitraryLoads is ignored when any of the narrower keys is present.
        overridden = any(k in ats for k in ("NSAllowsArbitraryLoadsInWebContent",
                                            "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"))
        if plist.truthy(ats.get("NSAllowsArbitraryLoads")) and not overridden:
            yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSAllowsArbitraryLoads"),
                             "NSAllowsArbitraryLoads turns off App Transport Security for every host.")
        if web:
            yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSAllowsArbitraryLoadsInWebContent"),
                             "NSAllowsArbitraryLoadsInWebContent lets every web view load plain HTTP.")

    def check(key: str, value: str, settings: Dict[str, Value]) -> Optional[str]:
        generated = settings.get("GENERATE_INFOPLIST_FILE", (None, "", 0))[0]
        if not xcconfig.is_yes(value) or not xcconfig.is_yes(generated):
            return None
        return f"Build setting {key} = YES adds an ATS exception to the generated Info.plist."

    yield from _setting_hits(ctx, check, lambda k: bool(_ATS_KEY.match(k)))


@detector("ios_ats_exception_http")
def ats_exception_http(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        domains = ats.get("NSExceptionDomains")
        if not isinstance(domains, dict):
            continue
        for domain, conf in domains.items():
            if not isinstance(conf, dict) or _is_local(domain):
                continue
            for key in ("NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads"):
                if plist.truthy(conf.get(key)):
                    sub = " and its subdomains" if plist.truthy(conf.get("NSIncludesSubdomains")) else ""
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSExceptionDomains", domain, key),
                                     f"Plain HTTP is allowed for {domain}{sub}.")


_WEAK_TLS = {"TLSV1.0", "TLSV1.1"}
_WEAK_TLS_CODE = re.compile(
    r"\b(?:tlsMinimumSupportedProtocolVersion|TLSMinimumSupportedProtocol)\s*=\s*[\w.]*?"
    r"(?:TLSv10|TLSv11|tlsProtocol1|tlsProtocol11|kTLSProtocol1|kTLSProtocol11)\b"
)


@detector("ios_weak_tls")
def weak_tls(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        domains = ats.get("NSExceptionDomains")
        if not isinstance(domains, dict):
            continue
        for domain, conf in domains.items():
            if not isinstance(conf, dict):
                continue
            for key in ("NSExceptionMinimumTLSVersion", "NSTemporaryExceptionMinimumTLSVersion"):
                value = conf.get(key)
                if isinstance(value, str) and value.strip().upper() in _WEAK_TLS:
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSExceptionDomains", domain, key),
                                     f"{domain} accepts {value.strip()}, below the TLS 1.2 floor ATS enforces.")
    yield from _code_hits(ctx, _WEAK_TLS_CODE, "TLS",
                          "The session accepts TLS 1.0 or 1.1, below the TLS 1.2 floor ATS enforces.")


# ---------------------------------------------------------------------------- trust and pinning

_CHALLENGE = re.compile(
    r"didReceive\s+challenge\s*:\s*URLAuthenticationChallenge"
    r"|didReceive(?:Authentication)?Challenge\s*:\s*\(\s*NSURLAuthenticationChallenge"
)
_TRUST_CREDENTIAL = re.compile(r"URLCredential\s*(?:\.init)?\s*\(\s*trust\s*:|credentialForTrust\s*:|initWithTrust\s*:")
_USE_CREDENTIAL = re.compile(r"\.useCredential\b|NSURLSessionAuthChallengeUseCredential")
_EVALUATES = re.compile(r"SecTrustEvaluate\w*|TSKPinningValidator|\bevaluate\s*\(")
_REJECTS = re.compile(r"[cC]ancelAuthenticationChallenge|[rR]ejectProtectionSpace")
_PIN_MARKERS = re.compile(
    r"SecTrustCopyCertificateChain|SecTrustGetCertificateAtIndex|SecCertificateCopyKey|SecTrustCopyPublicKey"
    r"|SecTrustCopyKey|SecCertificateCopyData|\bpin(?:s|ned\w*|Set)?\b|\bspki\w*|SPKI\w*"
)
_DEFAULT_HANDLING = re.compile(r"\.performDefaultHandling\b|NSURLSessionAuthChallengePerformDefaultHandling")


@detector("ios_trust_all")
def trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, line, body, _code in _functions(ctx, _CHALLENGE):
        if not (_TRUST_CREDENTIAL.search(body) and _USE_CREDENTIAL.search(body)):
            continue
        if _EVALUATES.search(body) or _REJECTS.search(body):
            continue
        if _PIN_MARKERS.search(body):
            msg = ("This handler compares pins but never validates the chain (no SecTrustEvaluateWithError), "
                   "so an expired or self-signed certificate carrying a pinned key is accepted.")
        else:
            msg = "This handler returns .useCredential for any server trust without evaluating it."
        yield Hit(path, line, ctx.snippet(path, line), msg)


@detector("ios_pin_fallback")
def pin_fallback(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, line, body, _code in _functions(ctx, _CHALLENGE):
        if not (_PIN_MARKERS.search(body) and _DEFAULT_HANDLING.search(body)):
            continue
        if _REJECTS.search(body):
            continue
        yield Hit(path, line, ctx.snippet(path, line),
                  "This pinning handler never cancels the challenge: when no pin matches it falls back to "
                  ".performDefaultHandling, which accepts any publicly trusted certificate.")


@detector("ios_pins_no_backup")
def pins_no_backup(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        pinned = ats.get("NSPinnedDomains")
        if not isinstance(pinned, dict):
            continue
        for domain, conf in pinned.items():
            if not isinstance(conf, dict):
                continue
            for key in ("NSPinnedCAIdentities", "NSPinnedLeafIdentities"):
                ids = conf.get(key)
                if isinstance(ids, list) and len(ids) < 2:
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSPinnedDomains", domain, key),
                                     f"{domain} has {len(ids)} pin under {key}: no backup pin.")


_PIN_EVIDENCE_CODE = re.compile(
    r"\bTrustKit\b|TSKPinningValidator|kTSKPinnedDomains|PinnedCertificatesTrustEvaluator"
    r"|PublicKeysTrustEvaluator|\bCertificatePinner\b|SecTrustCopyCertificateChain|SecCertificateCopyKey"
    r"|SecTrustCopyKey|SecTrustCopyPublicKey|SecTrustGetCertificateAtIndex|WultraSSLPinning"
)
_PIN_EVIDENCE_DEPS = re.compile(r"TrustKit|ssl-pinning-ios|WultraSSLPinning", re.IGNORECASE)


def _native_pinning_evidence(ctx: Context, code_files: List[str]) -> bool:
    for _doc, ats in _ats_docs(ctx):
        if isinstance(ats.get("NSPinnedDomains"), dict) and ats["NSPinnedDomains"]:
            return True
    for path in code_files + [p for p in ctx.files(".kt") if re.search(r"/(ios|apple|darwin)Main/", "/" + p)]:
        code = ctx.code(path, keep_strings=False)
        if code and _PIN_EVIDENCE_CODE.search(code):
            return True
    for name in ("Podfile", "Package.swift", "Cartfile"):
        for path in ctx.files(name=name):
            text = ctx.code(path) or ""
            if name != "Package.swift":        # Ruby-style comments in Podfile and Cartfile
                text = re.sub(r"#[^\n]*", "", text)
            if _PIN_EVIDENCE_DEPS.search(text):
                return True
    return False


@detector("ios_pinning_missing")
def pinning_missing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    is_flutter = flutter.is_flutter(ctx)
    if not is_flutter and ctx.files(name="package.json"):
        ctx.note_unknown("React Native project: iOS pinning may live in JavaScript; IOS pinning check skipped.")
        return
    code_files = ctx.files(*CODE_SUFFIXES)
    if not code_files:
        return
    if is_flutter and flutter.dart_pinning_evidence(ctx):
        return
    if _native_pinning_evidence(ctx, code_files):
        if is_flutter and not flutter.uses_native_http(ctx):
            ctx.note_unknown("iOS pinning is configured natively, but Flutter's Dart HttpClient has its own "
                             "TLS stack and ignores it; confirm the Dart side pins too.")
        return
    missing = "no NSPinnedDomains, TrustKit, or pin-checking URLSession delegate"
    if is_flutter:
        missing = "no NSPinnedDomains, TrustKit, pin-checking URLSession delegate, or Dart-side pinning"
    for proj in _projects(ctx):
        for target in proj.targets():
            if target.is_app:
                yield Hit(proj.path, target.line, ctx.snippet(proj.path, target.line),
                          f"No certificate pinning found for app target {target.name}: {missing}.")
                return
    for doc in _shipping_plists(ctx):
        if plist.get(doc.data, "CFBundleIdentifier") is not None:
            yield Hit(doc.path, 0, "", f"No certificate pinning found: {missing}.")
            return


# ============================================================================ WebViews


_INSPECTABLE = re.compile(r"\bisInspectable\s*=\s*true\b|\binspectable\s*=\s*YES\b|\bsetInspectable\s*:\s*YES\b")


@detector("ios_webview_inspectable")
def webview_inspectable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _code_hits(ctx, _INSPECTABLE, "nspectable",
                          "Web inspection is switched on in code that also compiles into release builds.")


_MESSAGE_HANDLER = re.compile(
    r"didReceive\s+message\s*:\s*WKScriptMessage\b|didReceiveScriptMessage\s*:\s*\(\s*WKScriptMessage"
)


@detector("ios_message_handler_origin")
def message_handler_origin(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, line, body, code in _functions(ctx, _MESSAGE_HANDLER):
        if "frameInfo" in body or "frameInfo" in code:
            continue
        yield Hit(path, line, ctx.snippet(path, line),
                  "This script message handler never checks message.frameInfo (main frame and securityOrigin), "
                  "so any page or iframe in the web view can call it.")


# ============================================================================ deep links


_SDK_SCHEMES = re.compile(r"^(?:com\.googleusercontent\.apps\.|fb\d|msauth\.)", re.IGNORECASE)
_AUTH_WORDS = re.compile(r"oauth|callback|redirect|auth|login|signin|sign-in|sso", re.IGNORECASE)
_SCHEME_LITERAL = re.compile(r'"([A-Za-z][A-Za-z0-9+.\-]*)://([^"\s]*)"')
_ASWEB = re.compile(r"ASWebAuthenticationSession\s*\(")
_CALLBACK_SCHEME = re.compile(r"callbackURLScheme\s*:\s*(?!nil\b)\S|callback\s*:\s*\.customScheme\s*\(")


def _url_schemes(ctx: Context) -> Set[str]:
    schemes: Set[str] = set()
    for doc in _shipping_plists(ctx):
        types = plist.get(doc.data, "CFBundleURLTypes")
        if not isinstance(types, list):
            continue
        for t in types:
            for s in (plist.get(t, "CFBundleURLSchemes") or []):
                if not isinstance(s, str):
                    continue
                if xcconfig.is_unresolved(s):
                    ctx.note_unknown(f"URL scheme {s} in {doc.path} comes from a build variable.")
                    continue
                schemes.add(s.lower())
    return schemes


@detector("ios_custom_scheme_auth")
def custom_scheme_auth(ctx: Context, rule: Rule) -> Iterable[Hit]:
    schemes = {s for s in _url_schemes(ctx) if not _SDK_SCHEMES.match(s)}
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or ("://" not in raw and "ASWebAuthenticationSession" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        seen_lines: Set[int] = set()
        for m in _ASWEB.finditer(code):
            window = code[m.end():m.end() + 600]
            c = _CALLBACK_SCHEME.search(window)
            if c:
                line = ctx.line_of(code, m.end() + c.start())
                seen_lines.add(line)
                yield Hit(path, line, ctx.snippet(path, line),
                          "The sign-in session returns through a custom URL scheme, which isn't tied to your app.")
        for m in _SCHEME_LITERAL.finditer(code):
            scheme, rest = m.group(1).lower(), m.group(2)
            if scheme not in schemes or not _AUTH_WORDS.search(rest):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen_lines:
                continue
            seen_lines.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"Auth redirect {scheme}://{rest} uses a custom URL scheme registered in CFBundleURLTypes.")


# ============================================================================ privacy and build


PRIVACY_MANIFEST = "PrivacyInfo.xcprivacy"


def _exists_under(ctx: Context, folder: str, name: str) -> bool:
    prefix = folder.rstrip("/") + "/" if folder else ""
    if any(f.startswith(prefix) and f.rsplit("/", 1)[-1] == name for f in ctx.project.files):
        return True
    base = os.path.join(ctx.root, folder)
    if not safety.is_within(ctx.root, base) or not os.path.isdir(base):
        return False
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in safety.SKIP_DIRS
                       and not os.path.islink(os.path.join(dirpath, d))]
        if name in filenames:
            return True
    return False


@detector("ios_privacy_manifest")
def privacy_manifest(ctx: Context, rule: Rule) -> Iterable[Hit]:
    projects = list(_projects(ctx))
    if not projects:
        ctx.note_unknown(f"No Xcode project was found, so app targets couldn't be checked for {PRIVACY_MANIFEST}.")
        return
    for proj in projects:
        in_project = any(isinstance(o, dict) and o.get("isa") == "PBXFileReference"
                         and proj.file_name(oid) == PRIVACY_MANIFEST for oid, o in proj.objects.items())
        for target in proj.targets():
            if not target.is_app:
                continue
            refs = proj.phase_files(target, "PBXResourcesBuildPhase")
            if any(proj.file_name(r) == PRIVACY_MANIFEST for r in refs):
                continue
            if any(_exists_under(ctx, g, PRIVACY_MANIFEST) for g in target.synchronized_groups):
                continue
            if in_project:
                msg = (f"{PRIVACY_MANIFEST} is in the project but not in app target {target.name}'s "
                       "Copy Bundle Resources, so it doesn't ship.")
            else:
                msg = f"App target {target.name} has no {PRIVACY_MANIFEST}."
            yield Hit(proj.path, target.line, ctx.snippet(proj.path, target.line), msg)


@detector("ios_release_testability")
def release_testability(ctx: Context, rule: Rule) -> Iterable[Hit]:
    def check(key: str, value: str, _settings: Dict[str, Value]) -> Optional[str]:
        if key == "ENABLE_TESTABILITY" and xcconfig.is_yes(value):
            return "ENABLE_TESTABILITY = YES exports internal symbols and skips stripping."
        if key == "STRIP_INSTALLED_PRODUCT" and xcconfig.is_no(value):
            return "STRIP_INSTALLED_PRODUCT = NO ships the binary with its symbols."
        return None

    yield from _setting_hits(ctx, check, lambda k: k in ("ENABLE_TESTABILITY", "STRIP_INSTALLED_PRODUCT"))
