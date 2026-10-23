# SPDX-License-Identifier: Apache-2.0
"""Flutter (Dart) detectors: TLS bypass in `badCertificateCallback`, tokens in shared_preferences,
and the Dart-side pinning evidence the Android and iOS pinning rules use. Book: §7.1, §6.4, §8.10.

Dart's `HttpClient` brings its own TLS stack, so `<pin-set>` and NSPinnedDomains don't cover it
(book §8.10, MASTG-KNOW-0015). Every detector runs on code with comments blanked.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Set

from masaudit.detect import scope_of
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule

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
    return bool(re.search(r"\b" + re.escape(name) + r"\s*\([^()]*\)\s*" + _RETURNS_TRUE, code))


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
_SET_CALL = re.compile(
    r"\.\s*set(?:String|StringList)\s*\(\s*(?:[\"']([^\"'\n]*)[\"']|([A-Za-z_][\w.]*))\s*,\s*([^,;\n]*)"
)


def _key_text(code: str, literal: Optional[str], ident: Optional[str]) -> str:
    """The key's text: a literal, a constant resolved in the same file, or the constant's name."""
    if literal is not None:
        return literal
    name = (ident or "").rsplit(".", 1)[-1]
    m = re.search(r"\b" + re.escape(name) + r"\s*=\s*[\"']([^\"'\n]*)[\"']", code)
    return m.group(1) if m else name


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
            if not what or _NOT_SECRET.search(key) or _NOT_SECRET.search(value):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"`{what}` looks like a token or secret and is written to shared_preferences.")
