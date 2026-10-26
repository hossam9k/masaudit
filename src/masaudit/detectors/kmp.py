# SPDX-License-Identifier: Apache-2.0
"""Kotlin Multiplatform detectors: what belongs in commonMain and what must stay native.

Book: §21.1 (keep platform trust primitives native), §21.2 (design around intent, not
mechanism), §8.10 (Ktor's common API doesn't pin; each engine must), §6.6 (no secrets in logs).
"""

from __future__ import annotations

import re
from typing import Iterable, List, Set

from masaudit.guards import guarded_by
from masaudit.textscan import bracket_match, first_in_span, found_in_span, name_index
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule

APPLE_SET = re.compile(r"/(?:ios\w*|apple|darwin|macos\w*|native)Main/")


def _in_common(path: str) -> bool:
    return "/commonMain/" in "/" + path


def _common_kotlin(ctx: Context) -> List[str]:
    return [p for p in ctx.files(".kt") if _in_common(p)]


# ---------------------------------------------------------------------------- KMP-001

MECHANISM = re.compile(r"(?i)key_?store|keychain|secure_?enclave|strong_?box|seckey")
EXPECT_DECL = re.compile(
    r"\bexpect\s+(?:(?:suspend|inline|internal|public|abstract|open|sealed|data|fun)\s+)*"
    r"(?:fun|class|object|interface|val|var)\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)"
)
SHARED_TYPE = re.compile(r"(?<!expect )\b(?:interface|abstract\s+class)\s+(\w+)")


@detector("kmp_mechanism_expect")
def mechanism_expect(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in _common_kotlin(ctx):
        raw = ctx.text(path) or ""
        if not MECHANISM.search(raw):
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for regex in (EXPECT_DECL, SHARED_TYPE):
            for m in regex.finditer(code):
                name = m.group(1)
                if not MECHANISM.search(name):
                    continue
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line),
                          f"`{name}` names one platform's mechanism in shared code; name it after what "
                          "the caller needs instead.")


# ---------------------------------------------------------------------------- KMP-002

NATIVE_PKG = (
    r"javax\.crypto|java\.security|android\.security|android\.hardware\.biometrics|androidx\.biometric|"
    r"androidx\.security|com\.google\.android\.play\.core\.integrity|com\.google\.android\.play\.integrity|"
    r"platform\.Security|platform\.LocalAuthentication|platform\.CryptoKit|platform\.DeviceCheck"
)
NATIVE_IMPORT = re.compile(r"^[ \t]*import\s+((?:" + NATIVE_PKG + r")\b[\w.*]*)", re.MULTILINE)
NATIVE_FQN = re.compile(r"(?<![\w.])((?:javax\.crypto|java\.security|android\.security)\.[A-Z]\w*)")


@detector("kmp_native_in_common")
def native_in_common(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in _common_kotlin(ctx):
        raw = ctx.text(path) or ""
        if not re.search(r"javax\.|java\.security|android\.|androidx\.|platform\.|play\.", raw):
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for regex in (NATIVE_IMPORT, NATIVE_FQN):
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start(1))
                if line in seen:
                    continue
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line),
                          f"`{m.group(1)}` is a platform trust API used from commonMain.")


# ---------------------------------------------------------------------------- KMP-003

PIN = re.compile(r"\"sha256/[A-Za-z0-9+/]{43}=\"")


@detector("kmp_ktor_pinning")
def ktor_pinning(ctx: Context, rule: Rule) -> Iterable[Hit]:
    kotlin = ctx.files(".kt", ".kts")
    if not any("io.ktor" in (ctx.text(p) or "") for p in kotlin):
        return
    first = None
    for path in _common_kotlin(ctx):
        code = ctx.code(path, keep_strings=True) or ""
        m = PIN.search(code)
        if m:
            first = (path, ctx.line_of(code, m.start()))
            break
    if first is None:
        return
    android = [p for p in kotlin if "/androidMain/" in "/" + p]
    apple = [p for p in kotlin if APPLE_SET.search("/" + p)]
    if not android and not apple:
        ctx.note_unknown(f"{first[0]}: Ktor pins are defined in commonMain, but no androidMain or iosMain "
                         "source set was found to check.")
        return

    def code_of(p: str) -> str:
        return ctx.code(p, keep_strings=False) or ""

    missing: List[str] = []
    if android and not any("CertificatePinner" in code_of(p) for p in android):
        missing.append("Android (OkHttp)")
    if apple:
        enforced = [p for p in apple if "CertificatePinner" in code_of(p) or "handleChallenge" in code_of(p)]
        if not enforced:
            missing.append("iOS (Darwin)")
        elif all("usePreconfiguredSession" in code_of(p) for p in enforced):
            missing.append("iOS (Darwin, where `usePreconfiguredSession` makes Ktor ignore `handleChallenge`)")
    if missing:
        path, line = first
        yield Hit(path, line, ctx.snippet(path, line),
                  "Pins are shared in commonMain, but nothing enforces them on " + " or ".join(missing) + ".")


# ---------------------------------------------------------------------------- KMP-004

KTOR_LOGGING = re.compile(r"\binstall\s*\(\s*Logging\s*\)\s*\{")
KTOR_LEVEL = re.compile(r"\blevel\s*=\s*LogLevel\s*\.\s*(ALL|BODY|HEADERS)\b")
_SANITIZE = re.compile(r"\bsanitizeHeader\s*[({]")


def _kmp_debug(cond: str) -> bool:
    if "!" in cond.replace("!=", ""):
        return False
    return bool(re.search(r"BuildConfig\.DEBUG\b|BuildKonfig\.DEBUG\b|\bisDebug\w*\b|isDebugBinary\b|\bDEBUG\b"
                          r"|\bdebug\b", cond))


@detector("kmp_ktor_logging")
def ktor_logging(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".kt"):
        raw = ctx.text(path) or ""
        if "Logging" not in raw or "LogLevel" not in raw:
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in KTOR_LOGGING.finditer(blank):
            # The block's span, looked up rather than sliced: nested blocks made a slice per block quadratic.
            body = (m.end() - 1, min(len(blank), bracket_match(blank, m.end() - 1, "{", "}") + 1))
            lv = first_in_span(blank, KTOR_LEVEL, *body)
            if lv is None:
                continue                         # INFO, NONE, or a level chosen at runtime
            level = lv.group(1)
            if level != "BODY" and found_in_span(blank, _SANITIZE, *body):
                continue
            idx = lv.start()
            line = ctx.line_of(blank, idx)
            scope = "debug" if guarded_by(blank, m.start(), _kmp_debug) else ""
            what = "request and response bodies" if level == "BODY" else "headers, including `Authorization`,"
            yield Hit(path, line, ctx.snippet(path, line),
                      f"Ktor's Logging plugin at `LogLevel.{level}` writes {what} to the log in every build.",
                      scope=scope)


# ---------------------------------------------------------------------------- KMP-005

TRUST_CREDENTIAL = re.compile(
    r"\bNSURLCredential\s*\.\s*(?:credentialForTrust|create\s*\(\s*trust\s*=|credentialWithTrust)"
)


@detector("kmp_darwin_trust_all")
def darwin_trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".kt"):
        if not APPLE_SET.search("/" + path):
            continue
        raw = ctx.text(path) or ""
        if "NSURLCredential" not in raw or "UseCredential" not in raw:
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        if (re.search(r"\bSecTrustEvaluate(?:WithError|AsyncWithError)?\s*\(", blank)
                or "CertificatePinner" in blank or "UseCredential" not in blank):
            continue
        for m in TRUST_CREDENTIAL.finditer(blank):
            line = ctx.line_of(blank, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      "The server-trust challenge is answered with a credential for whatever trust it "
                      "carries, without `SecTrustEvaluateWithError`, so any certificate is accepted.")


# ---------------------------------------------------------------------------- KMP-006

_SETTINGS_KEY = r"(\"[^\"\n]*\"|[A-Za-z_][\w.]*)"
SETTINGS_WRITE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*(?:putString|putStringOrNull|set)\s*\(\s*" + _SETTINGS_KEY + r"\s*,([^\n]*)"
    r"|\b([A-Za-z_]\w*)\s*\[\s*" + _SETTINGS_KEY + r"\s*\]\s*=(?!=)([^\n]*)"
)
_SECRET_KEY = re.compile(r"(?i)token|password|passwd|secret|jwt|credential|api_?key|private_?key")
_PUBLIC_KEY = re.compile(r"(?i)fcm|push|apns|firebase|notification|messaging|device_?token|csrf")
_PLAIN_IMPL = re.compile(
    r"\b(?:SharedPreferencesSettings|NSUserDefaultsSettings|PreferencesSettings|StorageSettings|"
    r"PropertiesSettings|DataStoreSettings|MapSettings)\b|\bSettings\s*\(\s*\)"
)
_SECURE_IMPL = re.compile(r"\bKeychainSettings\b|\bKVault\b")


def _settings_receiver(code: str, name: str) -> bool:
    if re.search(r"(?i)editor|^edit$|bundle|intent|map$", name):
        return False
    if re.search(r"(?i)settings$|^settings", name):
        return True
    return name in name_index(code, r"\s*(?::\s*\w*Settings\b|=\s*\w*Settings\s*\()")


def _settings_key(code: str, arg: str) -> str:
    if arg.startswith('"'):
        return arg.strip('"')
    name = arg.rsplit(".", 1)[-1]
    m = name_index(code, r"\s*(?::\s*String)?\s*=\s*\"([^\"\n]*)\"").get(name)
    return name + " " + (m.group(2) if m else "")


@detector("kmp_settings_token")
def settings_token(ctx: Context, rule: Rule) -> Iterable[Hit]:
    kotlin = [p for p in ctx.files(".kt") if "com.russhwolf.settings" in (ctx.text(p) or "")]
    if not kotlin:
        return
    all_code = [ctx.code(p, keep_strings=False) or "" for p in ctx.files(".kt")
                if "Settings" in (ctx.text(p) or "") or "KVault" in (ctx.text(p) or "")]
    plain = any(_PLAIN_IMPL.search(c) for c in all_code)
    secure = any(_SECURE_IMPL.search(c) for c in all_code)
    if secure and not plain:
        return                                   # every store the project builds is Keychain-backed
    for path in kotlin:
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        if re.search(r"(?i)encrypt|\bcipher\b|\baead\b|tink", blank):
            continue                             # values are assumed to be ciphertext
        seen: Set[int] = set()
        for m in SETTINGS_WRITE.finditer(code):
            recv, arg = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(5))
            if not _settings_receiver(blank, recv):
                continue
            if recv in name_index(blank, r"\s*(?::|=)\s*KeychainSettings\b"):
                continue
            key = _settings_key(code, arg)
            if not _SECRET_KEY.search(key) or _PUBLIC_KEY.search(key):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"multiplatform-settings stores `{arg.strip(chr(34))}` in SharedPreferences or "
                      "NSUserDefaults, which are plain files.")
