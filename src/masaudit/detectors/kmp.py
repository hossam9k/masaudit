# SPDX-License-Identifier: Apache-2.0
"""Kotlin Multiplatform detectors: what belongs in commonMain and what must stay native.

Book: §21.1 (keep platform trust primitives native), §21.2 (design around intent, not
mechanism), §8.10 (Ktor's common API doesn't pin; each engine must).
"""

from __future__ import annotations

import re
from typing import Iterable, List, Set

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
