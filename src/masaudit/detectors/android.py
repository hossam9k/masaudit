# SPDX-License-Identifier: Apache-2.0
"""Android detectors: manifest, network security config, Gradle, and Android-specific code."""

from __future__ import annotations

import datetime
import posixpath
import re
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit.detect import scope_of
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.parsers import gradle, manifest, xmlsafe
from masaudit.parsers.xmlsafe import Element

CODE_SUFFIXES = (".kt", ".java")
BUILD_FILES = ("build.gradle", "build.gradle.kts")


# ---------------------------------------------------------------------------- helpers


def _xml(ctx: Context, path: str):
    text = ctx.text(path)
    if text is None:
        return None
    root = xmlsafe.parse(text)
    if root is None:
        ctx.note_unknown(f"Couldn't parse {path} (invalid XML or it declares entities).")
    return root


def _hit(ctx: Context, path: str, line: int, message: str) -> Hit:
    return Hit(path, line, ctx.snippet(path, line), message)


def _manifests(ctx: Context) -> Iterator[Tuple[str, Element]]:
    for path in ctx.files(name="AndroidManifest.xml"):
        root = _xml(ctx, path)
        if root is not None and root.tag == "manifest":
            yield path, root


def _res_xml(ctx: Context, root_tag: str) -> Iterator[Tuple[str, Element]]:
    for path in ctx.files(".xml"):
        if "/res/xml/" not in "/" + path:
            continue
        text = ctx.text(path) or ""
        if f"<{root_tag}" not in text:
            continue
        root = _xml(ctx, path)
        if root is not None and root.tag == root_tag:
            yield path, root


def _code_files(ctx: Context, *needles: str) -> Iterator[Tuple[str, str, str]]:
    """(path, code, blank) for Kotlin/Java files whose raw text contains every needle.

    `code` has comments blanked; `blank` also blanks string contents. Offsets are identical.
    """
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or not all(n in raw for n in needles):
            continue
        code = ctx.code(path, keep_strings=True)
        blank = ctx.code(path, keep_strings=False)
        if code is not None and blank is not None:
            yield path, code, blank


def _match(text: str, i: int, opener: str, closer: str) -> int:
    """Index of the bracket closing the one at `i` (text must have strings blanked)."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == opener:
            depth += 1
        elif text[j] == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def _args(blank: str, open_paren: int) -> List[Tuple[int, int]]:
    """Top-level argument spans of the call whose "(" is at open_paren."""
    close = _match(blank, open_paren, "(", ")")
    spans, depth, start = [], 0, open_paren + 1
    for j in range(open_paren + 1, close):
        c = blank[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, j))
            start = j + 1
    if blank[start:close].strip() or spans:
        spans.append((start, close))
    return spans


_IF = re.compile(r"\bif\s*\(")


def _debug_guarded(blank: str, idx: int) -> bool:
    """True if idx sits under `if (BuildConfig.DEBUG)` or an `if (... FLAG_DEBUGGABLE ...)` check."""
    for m in _IF.finditer(blank, max(0, idx - 2000), idx):
        open_paren = m.end() - 1
        close = _match(blank, open_paren, "(", ")")
        if close >= idx:
            continue
        cond = re.sub(r"\s+", "", blank[open_paren + 1:close])
        debug = (re.search(r"(?<!!)BuildConfig\.DEBUG\b", cond) and "!BuildConfig.DEBUG" not in cond) or (
            "FLAG_DEBUGGABLE" in cond and "==0" not in cond)
        if not debug:
            continue
        j = close + 1
        while j < len(blank) and blank[j] in " \t\r\n":
            j += 1
        if j < len(blank) and blank[j] == "{":
            if j < idx < _match(blank, j, "{", "}"):
                return True
        else:
            between = blank[close + 1:idx]
            if ";" not in between and between.count("\n") <= 1:
                return True
    return False


def _module_of(path: str) -> str:
    p = "/" + path
    if "/src/" in p:
        return p[: p.index("/src/")].lstrip("/")
    return posixpath.dirname(path)


_APP_PLUGIN = re.compile(r"com\.android\.application|android[.-]application")
_LIB_PLUGIN = re.compile(r"com\.android\.library|android[.-]library|com\.android\.test\b|java-library"
                         r"|kotlin\(\s*\"jvm\"\s*\)|kotlin\(\s*\"multiplatform\"\s*\)")


def _module_kinds(ctx: Context) -> Dict[str, str]:
    """module dir -> "app" | "lib" | "unknown", from each build.gradle(.kts)."""
    out: Dict[str, str] = {}
    for path in ctx.files(*BUILD_FILES):
        if path.rsplit("/", 1)[-1] not in BUILD_FILES:
            continue
        code = ctx.code(path) or ""
        if _APP_PLUGIN.search(code):
            kind = "app"
        elif _LIB_PLUGIN.search(code):
            kind = "lib"
        else:
            kind = "unknown"
        out[posixpath.dirname(path)] = kind
    return out


def _build_files(ctx: Context, kinds: Tuple[str, ...] = ("app", "unknown")) -> Iterator[Tuple[str, str, str]]:
    modules = _module_kinds(ctx)
    for path in ctx.files(*BUILD_FILES):
        if path.rsplit("/", 1)[-1] not in BUILD_FILES:
            continue
        if modules.get(posixpath.dirname(path), "unknown") not in kinds:
            continue
        code = ctx.code(path, keep_strings=True)
        blank = ctx.code(path, keep_strings=False)
        if code is not None and blank is not None:
            yield path, code, blank


def _under(el: Element, tag: str) -> bool:
    p = el.parent
    while p is not None:
        if p.tag == tag:
            return True
        p = p.parent
    return False


# ---------------------------------------------------------------------------- network


@detector("android_cleartext")
def cleartext(ctx: Context, rule: Rule) -> Iterable[Hit]:
    # Network security config: cleartext allowed in the base config.
    for path in ctx.files(".xml"):
        if "/res/xml/" not in "/" + path:
            continue
        root = _xml(ctx, path)
        if root is None or root.tag != "network-security-config":
            continue
        for base in root.iter("base-config"):
            if xmlsafe.is_true(base.get("cleartextTrafficPermitted")):
                yield Hit(path, base.line, ctx.snippet(path, base.line),
                          "The base config allows plain HTTP for every host.")
    # Manifest: usesCleartextTraffic="true" on <application>.
    for path in ctx.files(name="AndroidManifest.xml"):
        root = _xml(ctx, path)
        if root is None:
            continue
        for app in root.iter("application"):
            if xmlsafe.is_true(app.get("android:usesCleartextTraffic")):
                yield Hit(path, app.line, ctx.snippet(path, app.line),
                          "The manifest allows plain HTTP for the whole app.")


@detector("android_user_certs")
def user_certs(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _res_xml(ctx, "network-security-config"):
        for cert in root.iter("certificates"):
            if (cert.get("src") or "").strip() != "user" or _under(cert, "debug-overrides"):
                continue
            where = "the base config" if _under(cert, "base-config") else "a domain config"
            yield _hit(ctx, path, cert.line,
                       f"User-installed CAs are trusted in {where}, so a proxy CA can read release traffic.")


_SSL_ERROR = re.compile(r"\bonReceivedSslError\s*\(")
_PROCEED = re.compile(r"\??\.proceed\s*\(\s*\)")


@detector("android_webview_ssl_proceed")
def webview_ssl_proceed(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "onReceivedSslError", "proceed"):
        for m in _SSL_ERROR.finditer(blank):
            close = _match(blank, m.end() - 1, "(", ")")
            brace = blank.find("{", close)
            if brace == -1 or not re.fullmatch(r"\s*(?::\s*Unit\s*)?", blank[close + 1:brace]):
                continue
            end = _match(blank, brace, "{", "}")
            for p in _PROCEED.finditer(blank, brace, end):
                line = ctx.line_of(blank, p.start())
                yield _hit(ctx, path, line,
                           "The WebView continues past a TLS certificate error, so any certificate is accepted.")


_TRUST_EMPTY = re.compile(r"\bcheckServerTrusted\s*\(")
_VERIFY = re.compile(r"\bverify\s*\(")
_LAMBDA_TRUE = re.compile(
    r"(?:\bHostnameVerifier|\bhostnameVerifier|\bsetDefaultHostnameVerifier)\s*(?:\(\s*)?"
    r"(?:\{\s*\w+\s*(?::\s*\w+\??\s*)?,\s*\w+\s*(?::\s*\w+\??\s*)?->|\(\s*\w+\s*,\s*\w+\s*\)\s*->)\s*true\b"
)
_ALLOW_ALL = re.compile(r"\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bAllowAllHostnameVerifier\b|\bNoopHostnameVerifier\b")


@detector("android_trust_all")
def trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx):
        if not re.search(r"checkServerTrusted|HostnameVerifier|hostnameVerifier|SSLSession", blank):
            continue
        for m in _TRUST_EMPTY.finditer(blank):
            close = _match(blank, m.end() - 1, "(", ")")
            rest = blank[close + 1:close + 400]
            if re.match(r"\s*(?::\s*Unit\s*)?(?:throws\s+[\w.\s,]+?)?\s*(?:\{\s*(?:return\s*;?\s*)?\}|=\s*Unit\b)", rest):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "checkServerTrusted() is empty, so this TrustManager accepts every certificate.")
        for m in _VERIFY.finditer(blank):
            close = _match(blank, m.end() - 1, "(", ")")
            if "SSLSession" not in blank[m.end():close]:
                continue
            rest = blank[close + 1:close + 200]
            if re.match(r"\s*(?::\s*Boolean\s*)?(?:=\s*true\b|\{\s*return\s+true\s*;?\s*\})", rest):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line, "This HostnameVerifier returns true for every host name.")
        for m in _LAMBDA_TRUE.finditer(blank):
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line, "This HostnameVerifier returns true for every host name.")
        for m in _ALLOW_ALL.finditer(blank):
            line_start = blank.rfind("\n", 0, m.start()) + 1
            if blank[line_start:m.start()].lstrip().startswith("import"):
                continue
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line, "An allow-all HostnameVerifier accepts certificates for any host name.")


_PIN_MARKERS = re.compile(r"<pin-set|CertificatePinner|TrustKit|[Pp]inning|sha256/[A-Za-z0-9+/=]{20,}")


@detector("android_pinning_missing")
def pinning_missing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    apps: List[Tuple[str, Element]] = []
    internet = False
    for path, root in _manifests(ctx):
        if any(p.get("android:name") == "android.permission.INTERNET" for p in manifest.uses_permissions(root)):
            internet = True
        if scope_of(path) == "main":
            apps.extend((path, a) for a in manifest.applications(root))
    if not apps or not internet:
        return
    files = ctx.project.files
    if any(f.endswith(".dart") or f.rsplit("/", 1)[-1] in ("pubspec.yaml", "package.json") for f in files):
        ctx.note_unknown("Pinning check skipped: Flutter or React Native code may pin outside the Android sources.")
        return
    for path in ctx.files(".xml", ".kt", ".java", ".kts", ".gradle", ".toml", ".json"):
        text = ctx.text(path) or ""
        if _PIN_MARKERS.search(text):
            return
    for path, _code, blank in _code_files(ctx, "checkServerTrusted"):
        if "checkServerTrusted" in blank:
            ctx.note_unknown(f"Pinning check skipped: {path} has a custom TrustManager that may pin.")
            return
    path, app = apps[0]
    yield _hit(ctx, path, app.line,
               "No certificate pinning found: no <pin-set>, no OkHttp CertificatePinner, and no pinning library.")


@detector("android_pin_set")
def pin_set(ctx: Context, rule: Rule) -> Iterable[Hit]:
    today = datetime.date.today()
    for path, root in _res_xml(ctx, "network-security-config"):
        for ps in root.iter("pin-set"):
            problems = []
            pins = [c for c in ps.children if c.tag == "pin"]
            if len(pins) < 2:
                problems.append("it has only one pin and no backup pin")
            exp = (ps.get("expiration") or "").strip()
            if not exp:
                problems.append("it has no expiration date")
            else:
                try:
                    when = datetime.date.fromisoformat(exp)
                except ValueError:
                    when = None
                if when is not None and when < today:
                    problems.append(f"its pins expired on {exp}, so Android no longer enforces them")
            if problems:
                yield _hit(ctx, path, ps.line, "This pin-set is risky: " + "; ".join(problems) + ".")


_GATED_TRUST = re.compile(r"certificatePinner\s*\(|CertificatePinner|sslSocketFactory\s*\(|hostnameVerifier\s*\("
                          r"|TrustManager|\btrustAll\w*")
_BUILDCONFIG_IF = re.compile(r"\bif\s*\(\s*!?\s*BuildConfig\.\w+")


@detector("android_buildconfig_trust")
def buildconfig_trust(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "BuildConfig."):
        for m in _BUILDCONFIG_IF.finditer(blank):
            open_paren = blank.index("(", m.start())
            close = _match(blank, open_paren, "(", ")")
            j = close + 1
            while j < len(blank) and blank[j] in " \t\r\n":
                j += 1
            if j < len(blank) and blank[j] == "{":
                end = _match(blank, j, "{", "}")
                region = blank[j:end]
                em = re.compile(r"\s*else\s*\{").match(blank, end + 1)
                if em:
                    region += blank[em.end() - 1:_match(blank, em.end() - 1, "{", "}")]
            else:
                nl = blank.find("\n", j)
                region = blank[j: nl if nl != -1 else len(blank)]
            if _GATED_TRUST.search(region):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "Certificate pinning or trust checks depend on a BuildConfig flag that can be flipped.")


# ---------------------------------------------------------------------------- WebView


_WV_DEBUG = re.compile(r"\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)")


@detector("android_webview_debugging")
def webview_debugging(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "setWebContentsDebuggingEnabled"):
        for m in _WV_DEBUG.finditer(blank):
            if _debug_guarded(blank, m.start()):
                continue
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line,
                       "WebView debugging is turned on for every build, including release.")


_URL_SOURCE = re.compile(
    r"getStringExtra\s*\(|getQueryParameter\s*\(|\bintent\??\.data(?:String)?\b"
    r"|getIntent\(\)\s*\.\s*getData(?:String)?\s*\(|\bintent\??\.extras\??\.getString\s*\("
    r"|getExtras\(\)\s*\.\s*getString\s*\("
)
_LOAD_URL = re.compile(r"\.loadUrl\s*\(")
_STRING_ASSIGN = re.compile(r"(?:\bval|\bvar|\bString)\s+(\w+)\s*(?::\s*String\??\s*)?=\s*([^;\n]*)")


@detector("android_webview_untrusted_url")
def webview_untrusted_url(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "loadUrl"):
        if re.search(r"\.host\b|getHost\s*\(", blank):
            continue          # the file inspects the host: assume an allowlist check
        tainted = {m.group(1) for m in _STRING_ASSIGN.finditer(blank) if _URL_SOURCE.search(m.group(2))}
        for m in _LOAD_URL.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            first = blank[spans[0][0]:spans[0][1]]
            name = re.fullmatch(r"\s*(\w+)\s*(?:!!|\.toString\(\))?\s*", first)
            if _URL_SOURCE.search(first) or (name and name.group(1) in tainted):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "The WebView loads a URL that came from an intent or deep link, with no host check.")


# ---------------------------------------------------------------------------- components and IPC

_SYSTEM_PERMISSION = re.compile(r"^(?:android\.permission\.|com\.google\.android\.c2dm\.permission\.SEND$"
                                r"|com\.google\.android\.gms\.)")


def _permission_strength(perm: str, declared: Dict[str, str]) -> str:
    """"strong" (system or signature), "weak" (normal/dangerous, any app can get it), or "unknown"."""
    if _SYSTEM_PERMISSION.match(perm):
        return "strong"
    if perm in declared:
        return "strong" if "signature" in declared[perm] else "weak"
    return "unknown"


@detector("android_exported")
def exported_components(ctx: Context, rule: Rule) -> Iterable[Hit]:
    parsed = list(_manifests(ctx))
    declared: Dict[str, str] = {}
    for _path, root in parsed:
        declared.update(manifest.declared_permissions(root))
    for path, root in parsed:
        for c in manifest.components(root):
            name = c.get("android:name") or c.tag
            exported = c.get("android:exported")
            if manifest.is_placeholder(exported):
                ctx.note_unknown(f"{path}: {name} sets android:exported from a placeholder.")
                continue
            if c.tag == "provider":
                if not xmlsafe.is_true(exported):
                    continue
                perm_attrs = [c.get(a) for a in ("android:permission", "android:readPermission",
                                                 "android:writePermission") if c.get(a)]
                if any(ch.tag == "path-permission" for ch in c.children):
                    continue
            else:
                filters = manifest.intent_filters(c)
                is_exported = xmlsafe.is_true(exported) if exported is not None else bool(filters)
                if not is_exported:
                    continue
                if c.tag in ("activity", "activity-alias") and (
                        manifest.is_launcher(c) or manifest.is_browsable_only(c)):
                    continue
                perm_attrs = [c.get("android:permission")] if c.get("android:permission") else []
            if perm_attrs:
                strengths = set()
                for perm in perm_attrs:
                    if manifest.is_placeholder(perm):
                        strengths.add("unknown")
                    else:
                        strengths.add(_permission_strength(perm.strip(), declared))
                if strengths != {"weak"}:
                    continue
                msg = f"{name} is exported and protected only by a permission any app can request."
            else:
                how = "exported" if exported is not None else "exported (it has an intent filter)"
                msg = f"The {c.tag} {name} is {how} with no permission, so any app can call it."
            yield _hit(ctx, path, c.line, msg)


@detector("android_file_provider_paths")
def file_provider_paths(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _res_xml(ctx, "paths"):
        for el in root.children:
            if el.tag == "root-path":
                yield _hit(ctx, path, el.line, "<root-path> shares the whole device filesystem.")
            elif (el.get("path") or "").strip() in (".", "/"):
                yield _hit(ctx, path, el.line, f"<{el.tag} path=\"{el.get('path')}\"> shares an entire directory tree.")


_START = re.compile(r"\b(?:startActivit(?:y|yForResult|ies)|startService|startForegroundService|sendBroadcast"
                    r"|bindService)\s*\(")
_PARCEL = re.compile(r"getParcelableExtra|getParcelable\s*\(")
_INTENT_ASSIGN = re.compile(
    r"(?P<decl>(?:\bval|\bvar|\bfinal\s+Intent|\bIntent)\s+(?P<name>\w+)\s*(?::\s*Intent\??)?)\s*=\s*(?P<rhs>[^;\n]*)")


@detector("android_intent_redirect")
def intent_redirect(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "getParcelable"):
        if "IntentSanitizer" in blank:
            continue
        nested: Set[str] = set()
        for m in _INTENT_ASSIGN.finditer(blank):
            rhs = code[m.start("rhs"):m.end("rhs")]
            typed = "Intent" in m.group("decl") or re.search(r"Intent::class|<Intent>|\(Intent\)|as\??\s+Intent", rhs)
            if _PARCEL.search(rhs) and typed:
                nested.add(m.group("name"))
        for m in _START.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            first = blank[spans[0][0]:spans[0][1]]
            name = re.fullmatch(r"\s*(\w+)\s*(?:!!)?\s*", first)
            if _PARCEL.search(first) or (name and name.group(1) in nested):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "An Intent taken from another Intent's extras is started as this app.")


_WEB_SCHEMES = {"http", "https"}


@detector("android_app_links")
def app_links(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        for c in manifest.components(root, ("activity", "activity-alias")):
            for f in manifest.intent_filters(c):
                if ("android.intent.action.VIEW" not in manifest.names(f, "action")
                        or "android.intent.category.BROWSABLE" not in manifest.names(f, "category")):
                    continue
                data = manifest.data_attrs(f)
                values = [d.get(k) for d in data for k in ("android:scheme", "android:host")]
                auto = f.get("android:autoVerify")
                if any(manifest.is_placeholder(v) for v in values + [auto]):
                    ctx.note_unknown(f"{path}: an App Link intent filter uses a placeholder.")
                    continue
                schemes = {(d.get("android:scheme") or "").lower() for d in data}
                hosts = [d.get("android:host") for d in data if d.get("android:host")]
                if schemes & _WEB_SCHEMES and hosts and not xmlsafe.is_true(auto):
                    yield _hit(ctx, path, f.line,
                               f"Web links for {', '.join(hosts)} open {c.get('android:name')} without "
                               "android:autoVerify, so another app can claim them.")


_SQL_CALL = re.compile(r"\b(?:rawQuery|execSQL)\s*\(")
_STR_LIT = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_TEMPLATE = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*)")
_CONCAT = re.compile(r"\+\s*([A-Za-z_][\w.]*)|([A-Za-z_][\w.]*)\s*\+")


def _is_constant(name: str) -> bool:
    last = re.split(r"[.\s]", name.strip())[-1]
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", last))


@detector("android_sql_concat")
def sql_concat(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx):
        if "rawQuery" not in blank and "execSQL" not in blank:
            continue
        for m in _SQL_CALL.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            a, b = spans[0]
            first_code, first_blank = code[a:b], blank[a:b]
            bad = bool(re.search(r"\bformat\s*\(", first_blank))
            for lit in _STR_LIT.finditer(first_code):
                for t in _TEMPLATE.finditer(lit.group(0)):
                    if not _is_constant(t.group(1) or t.group(2)):
                        bad = True
            for c in _CONCAT.finditer(first_blank):
                ident = c.group(1) or c.group(2)
                if not _is_constant(ident):
                    bad = True
            if bad:
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line, "This SQL is built by joining strings, so input can change the query.")


# ---------------------------------------------------------------------------- storage


@detector("android_backup")
def backup(ctx: Context, rule: Rule) -> Iterable[Hit]:
    kinds = _module_kinds(ctx)
    parsed = list(_manifests(ctx))
    handled: Set[str] = set()      # modules where some manifest disables backup or sets rules
    for path, root in parsed:
        for app in manifest.applications(root):
            ab = app.get("android:allowBackup")
            if (ab is not None and not manifest.is_placeholder(ab) and not xmlsafe.is_true(ab)) or (
                    app.get("android:dataExtractionRules") or app.get("android:fullBackupContent")):
                handled.add(_module_of(path))
    for path, root in parsed:
        module = _module_of(path)
        if module in handled:
            continue
        for app in manifest.applications(root):
            ab = app.get("android:allowBackup")
            if manifest.is_placeholder(ab):
                ctx.note_unknown(f"{path}: android:allowBackup comes from a placeholder.")
                continue
            if ab is None:
                if scope_of(path) != "main" or kinds.get(module) != "app":
                    continue
                msg = ("allowBackup isn't set, so Android backs up the app's files by default, "
                       "and there are no rules excluding sensitive files.")
            elif xmlsafe.is_true(ab):
                msg = "allowBackup is true and there are no rules excluding sensitive files."
            else:
                continue
            yield _hit(ctx, path, app.line, msg)


def _deprecated_dependency(ctx: Context, coords: "re.Pattern[str]", imports: "re.Pattern[str]",
                           what: str) -> Iterator[Hit]:
    for path in ctx.files(".gradle", ".kts", ".toml"):
        if path.endswith(".toml"):
            for lineno, line in gradle.toml_lines(ctx.text(path) or ""):
                if coords.search(line):
                    yield _hit(ctx, path, lineno, f"The version catalog declares {what}.")
            continue
        if path.rsplit("/", 1)[-1] not in BUILD_FILES:
            continue
        code = ctx.code(path) or ""
        for m in coords.finditer(code):
            yield _hit(ctx, path, ctx.line_of(code, m.start()), f"The build depends on {what}.")
    for path, _code, blank in _code_files(ctx):
        m = imports.search(blank)
        if m:
            yield _hit(ctx, path, ctx.line_of(blank, m.start()), f"This file uses {what}.")


@detector("android_security_crypto")
def security_crypto(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _deprecated_dependency(
        ctx,
        re.compile(r"androidx\.security:security-crypto|group\s*=\s*[\"']androidx\.security[\"'][^\n]*"
                   r"name\s*=\s*[\"']security-crypto"),
        re.compile(r"^\s*import\s+androidx\.security\.crypto\.", re.MULTILINE),
        "the deprecated Jetpack Security library (androidx.security:security-crypto)",
    )


@detector("android_sqlcipher_legacy")
def sqlcipher_legacy(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _deprecated_dependency(
        ctx,
        re.compile(r"net\.zetetic:android-database-sqlcipher|group\s*=\s*[\"']net\.zetetic[\"'][^\n]*"
                   r"name\s*=\s*[\"']android-database-sqlcipher"),
        re.compile(r"^\s*import\s+net\.sqlcipher\.", re.MULTILINE),
        "the end-of-life SQLCipher package (net.zetetic:android-database-sqlcipher)",
    )


@detector("android_tink_keystore")
def tink_keystore(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "AndroidKeysetManager", "withMasterKeyUri"):
        if "AndroidKeysetManager" not in blank or "isUsingKeystore" in blank:
            continue
        m = re.search(r"\bwithMasterKeyUri\s*\(", blank)
        if m:
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line,
                       "The keyset uses a Keystore master key, but nothing checks isUsingKeystore() "
                       "for Tink's silent cleartext fallback.")


# ---------------------------------------------------------------------------- biometrics

_AUTHENTICATE = re.compile(r"\.authenticate\s*\(")


@detector("android_biometric_no_crypto")
def biometric_no_crypto(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "BiometricPrompt"):
        framework_only = "android.hardware.biometrics" in blank and "androidx.biometric" not in blank
        for m in _AUTHENTICATE.finditer(blank):
            n = len(_args(blank, m.end() - 1))
            if (framework_only and n == 3) or (not framework_only and n == 1):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "BiometricPrompt.authenticate() is called without a CryptoObject, "
                           "so the result is a boolean a hook can fake.")


_INVALIDATED_FALSE = re.compile(r"\bsetInvalidatedByBiometricEnrollment\s*\(\s*false\s*\)")
_AUTH_PARAMS = re.compile(r"\bsetUserAuthenticationParameters\s*\(")
_VALIDITY = re.compile(r"\bsetUserAuthenticationValidityDurationSeconds\s*\(\s*(\d+)\s*\)")


@detector("android_biometric_enrollment")
def biometric_enrollment(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "KeyGenParameterSpec"):
        for m in _INVALIDATED_FALSE.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "setInvalidatedByBiometricEnrollment(false): the key keeps working after "
                       "someone adds a new fingerprint or face.")
        if not re.search(r"setUserAuthenticationRequired\s*\(\s*true\s*\)", blank):
            continue
        for m in _AUTH_PARAMS.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if len(spans) != 2:
                continue
            timeout = blank[spans[0][0]:spans[0][1]].strip()
            kinds = blank[spans[1][0]:spans[1][1]]
            if "AUTH_DEVICE_CREDENTIAL" in kinds and "AUTH_BIOMETRIC_STRONG" in kinds:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "The key also accepts the device PIN, so Android doesn't invalidate it when "
                           "biometrics change.")
            elif timeout.isdigit() and int(timeout) > 0:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"The key stays unlocked for {timeout} seconds after authentication, so it isn't "
                           "tied to each use or invalidated on new enrollment.")
        for m in _VALIDITY.finditer(blank):
            if int(m.group(1)) > 0:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"The key stays unlocked for {m.group(1)} seconds after authentication, so it isn't "
                           "tied to each use or invalidated on new enrollment.")


# ---------------------------------------------------------------------------- build


_DEBUGGABLE = gradle.setting(r"isDebuggable|debuggable|setDebuggable")
_MINIFY = gradle.setting(r"isMinifyEnabled|minifyEnabled|setMinifyEnabled")
_ENABLE = gradle.setting(r"enable|isEnable")


@detector("android_debuggable")
def debuggable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        if scope_of(path) in ("debug", "test"):
            continue        # a debug-only manifest is where debuggable belongs
        for app in manifest.applications(root):
            value = app.get("android:debuggable")
            if manifest.is_placeholder(value):
                ctx.note_unknown(f"{path}: android:debuggable comes from a placeholder.")
            elif xmlsafe.is_true(value):
                yield _hit(ctx, path, app.line,
                           "android:debuggable=\"true\" in the main manifest makes every build debuggable.")
    for path, code, blank in _build_files(ctx):
        for block in gradle.build_type_blocks(code, blank, "release"):
            for idx, val in gradle.find_settings(code, _DEBUGGABLE, block.body_start, block.body_end):
                if val == "true":
                    yield _hit(ctx, path, ctx.line_of(code, idx), "The release build type is debuggable.")
                elif val != "false":
                    ctx.note_unknown(f"{path}: release debuggable is set from '{val}'.")


@detector("android_r8_off")
def r8_off(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _build_files(ctx):
        for block in gradle.build_type_blocks(code, blank, "release"):
            for idx, val in gradle.find_settings(code, _MINIFY, block.body_start, block.body_end):
                if val == "false":
                    yield _hit(ctx, path, ctx.line_of(code, idx),
                               "R8 minification is off in the release build type.")
                elif val != "true":
                    ctx.note_unknown(f"{path}: release minification is set from '{val}'.")
            for opt in gradle.child_blocks(code, blank, block, "optimization"):
                for idx, val in gradle.find_settings(code, _ENABLE, opt.body_start, opt.body_end):
                    if val == "false":
                        yield _hit(ctx, path, ctx.line_of(code, idx),
                                   "App optimization (R8) is off in the release build type.")


def _sdk_levels(ctx: Context, rule_key: str, threshold: int, label: str) -> Iterator[Hit]:
    """Shared logic for targetSdk / minSdk: Gradle (both DSLs), version catalogs, and the manifest."""
    key_re = re.compile(r"(?<![\w])(" + rule_key + r"Version|" + rule_key + r")[ \t]*(?:=\s*|\(\s*|[ \t]+)"
                        r"(?P<val>[^\s,}]+)")
    catalog_key_re = re.compile(r"(?i)(?:^|[-_.])" + re.sub(r"Sdk", r"[-_.]?sdk", rule_key) + r"(?:version)?$")
    versions: Dict[str, Tuple[str, int, str]] = {}
    seen: Set[Tuple[str, int]] = set()

    def report(path: str, line: int, value: int, where: str) -> Iterator[Hit]:
        if (path, line) in seen or value >= threshold:
            return
        seen.add((path, line))
        yield _hit(ctx, path, line, f"{label} is {value} {where}; it should be at least {threshold}.")

    for path in ctx.files(".toml"):
        for key, (val, line) in gradle.toml_versions(ctx.text(path) or "").items():
            versions[key] = (val, line, path)
            if catalog_key_re.search(key) and val.isdigit():
                yield from report(path, line, int(val), "in the version catalog")

    found_in_gradle = False
    build_like = list(_build_files(ctx))
    known = {p for p, _c, _b in build_like}
    for path in ctx.files(".kt", ".kts"):
        if path not in known and ("/build-logic/" in "/" + path or "/buildSrc/" in "/" + path):
            code, blank = ctx.code(path, True), ctx.code(path, False)
            if code is not None and blank is not None:
                build_like.append((path, code, blank))
    for path, code, blank in build_like:
        skip = [b for name in ("lint", "lintOptions", "testOptions")
                for b in gradle.named_blocks(code, blank, name)]
        for m in key_re.finditer(code):
            prefix = code[max(0, m.start() - 12):m.start()]
            if gradle.inside(m.start(), skip) or re.search(r"(?:lint|testOptions|lintOptions)\.$", prefix):
                continue
            val = m.group("val")
            while val.endswith(")") and val.count("(") < val.count(")"):
                val = val[:-1]
            found_in_gradle = True
            n = gradle.int_literal(val)
            if n is not None:
                yield from report(path, ctx.line_of(code, m.start()), n, f"in {path.rsplit('/', 1)[-1]}")
                continue
            accessor = gradle.catalog_key(val)
            quoted = re.search(r"\b(?:findVersion|\w*[vV]ersion)\(\s*[\"']([\w.-]+)[\"']", val)
            if accessor is None and quoted:      # libs.findVersion("targetSdk"), convention helpers
                accessor = re.sub(r"[-_]", ".", quoted.group(1))
            entry = None
            if accessor:
                for key, (v, line, src) in versions.items():
                    if re.sub(r"[-_]", ".", key).lower() == accessor.lower():
                        entry = (v, line, src)
            if entry is not None and entry[0].isdigit():
                yield from report(entry[2], entry[1], int(entry[0]), "in the version catalog")
            else:
                ctx.note_unknown(f"{path}: {m.group(1)} is set from '{val}', which masaudit can't resolve.")
    if found_in_gradle or any(catalog_key_re.search(k) for k in versions):
        return
    attr = "android:" + rule_key + "Version"
    for path, root in _manifests(ctx):
        for el in root.children:
            if el.tag != "uses-sdk":
                continue
            val = el.get(attr)
            if manifest.is_placeholder(val):
                ctx.note_unknown(f"{path}: {attr} comes from a placeholder.")
            elif val and val.strip().isdigit():
                yield from report(path, el.line, int(val), "in the manifest")


@detector("android_target_sdk")
def target_sdk(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _sdk_levels(ctx, "targetSdk", 36, "targetSdk")


@detector("android_min_sdk")
def min_sdk(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _sdk_levels(ctx, "minSdk", 24, "minSdk")


_LEVEL_BODY = re.compile(r"\bLevel\.BODY\b")


@detector("android_http_logging_body")
def http_logging_body(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "HttpLoggingInterceptor"):
        for m in _LEVEL_BODY.finditer(blank):
            line_start = blank.rfind("\n", 0, m.start()) + 1
            if blank[line_start:m.start()].lstrip().startswith("import"):
                continue
            if _debug_guarded(blank, m.start()):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "HttpLoggingInterceptor logs full request and response bodies, including tokens, "
                       "in every build.")


# ---------------------------------------------------------------------------- privacy

DANGEROUS_PERMISSIONS = {
    "ACCESS_FINE_LOCATION": "precise location",
    "ACCESS_BACKGROUND_LOCATION": "location in the background",
    "READ_EXTERNAL_STORAGE": "all shared files",
    "WRITE_EXTERNAL_STORAGE": "all shared files",
    "MANAGE_EXTERNAL_STORAGE": "every file on shared storage",
    "READ_MEDIA_IMAGES": "the whole photo library",
    "READ_MEDIA_VIDEO": "every video",
    "READ_MEDIA_AUDIO": "every audio file",
    "QUERY_ALL_PACKAGES": "the list of every installed app",
    "SYSTEM_ALERT_WINDOW": "drawing over other apps",
    "READ_CONTACTS": "the contact list",
    "READ_SMS": "text messages",
    "RECEIVE_SMS": "incoming text messages",
    "SEND_SMS": "sending text messages",
    "READ_CALL_LOG": "the call log",
    "READ_PHONE_STATE": "phone identity and call state",
    "READ_PHONE_NUMBERS": "the phone number",
    "RECORD_AUDIO": "the microphone",
    "CAMERA": "the camera",
    "BODY_SENSORS": "body sensors",
}


@detector("android_dangerous_permissions")
def dangerous_permissions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        for p in manifest.uses_permissions(root):
            name = (p.get("android:name") or "").strip()
            short = name.rsplit(".", 1)[-1]
            if name.startswith("android.permission.") and short in DANGEROUS_PERMISSIONS:
                yield _hit(ctx, path, p.line,
                           f"The app asks for {short} ({DANGEROUS_PERMISSIONS[short]}). "
                           "Check that a feature needs it and that a narrower option won't do.")
