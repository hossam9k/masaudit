# SPDX-License-Identifier: Apache-2.0
"""Cross-platform code detectors (Kotlin, Java, Swift, Objective-C, Dart): secrets, crypto misuse,
cleartext URLs, and sensitive logging. Book: §15.2, Chapter 0.2, §6.5, §7.1.

Every detector runs on code with comments blanked, so commented-out code and prose never match.
A hit in debug-only code (`if (BuildConfig.DEBUG)`, `#if DEBUG`, `if (kDebugMode)`) or in a file that
imports a test framework is reported with that scope, so it is lowered rather than dropped.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, List, Optional, Pattern, Sequence, Set, Tuple

from masaudit import guards
from masaudit.detect import scope_of
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule

CODE = (".kt", ".java", ".swift", ".m", ".mm", ".h", ".dart")
JVM = (".kt", ".java")
APPLE = (".swift", ".m", ".mm", ".h")
DART = (".dart",)


def _mask_in(snippet: str, value: str) -> str:
    """Mask `value` in a snippet even when it is too short for the generic masker."""
    if value and value in snippet:
        return snippet.replace(value, (value[:4] if len(value) > 8 else "") + "…[masked]")
    return snippet


# ---------------------------------------------------------------------------- scope and structure

# A file that imports a test framework is test code, wherever it lives (FooTests.swift next to the
# code it tests, a JVM test helper in a main source set).
_TEST_IMPORT = re.compile(
    r"^[ \t]*(?:@testable[ \t]+import\b|import[ \t]+(?:XCTest|Quick|Nimble|Testing)\b"
    r"|import[ \t]+(?:static[ \t]+)?(?:org\.junit|junit\.framework|kotlin\.test|io\.mockk|org\.mockito|"
    r"io\.kotest|androidx\.test)\b|import[ \t]+['\"]package:(?:flutter_test|test|mockito|mocktail)/)",
    re.MULTILINE,
)


# Gradle source sets of internal, QA, or staging flavors don't ship to users.
_NON_RELEASE_SOURCE_SET = re.compile(r"/src/(?:internal|qa|staging|dev|develop|uat)(?:Debug|Release)?/")


def _hit_scope(ctx: Context, path: str, idx: int, blank: Optional[str] = None) -> str:
    """'test' for a test-framework file, 'debug' under a debug-only guard, else '' (path decides)."""
    raw = ctx.text(path) or ""
    if _TEST_IMPORT.search(raw):
        return "test"
    if blank is None:
        blank = ctx.code(path, keep_strings=False) or ""
    if guards.debug_guarded(path, blank, idx) or _NON_RELEASE_SOURCE_SET.search("/" + path):
        return "debug"
    return ""


_NOT_FUNCTIONS = {
    "if", "for", "while", "switch", "catch", "synchronized", "when", "try", "guard", "else", "do", "return",
    "foreach", "with", "using", "lock", "autoreleasepool", "super", "this", "new", "throw", "in", "is", "as",
}
# Java `throws X, Y` or Dart `async`/`sync*` between the parameter list and the body.
_TRAILER = re.compile(r"\s(?:throws\s+[\w.]+(?:\s*,\s*[\w.]+)*|async\*?|sync\*)\s*$")


def _is_function_head(head: str, path: str) -> bool:
    h = head.rstrip()
    if path.endswith((".kt", ".kts")):
        return bool(re.search(r"\bfun\b[^=]*\)|\binit\s*$|\bconstructor\s*\(|\b(?:get|set)\s*\([^)]*\)", h))
    if path.endswith(".swift"):
        return bool(re.search(r"\b(?:func|init|deinit|subscript)\b|\b(?:get|set|willSet|didSet)\s*$", h))
    if path.endswith((".m", ".mm", ".h")) and re.match(r"\s*[-+]\s*\(", h):
        return True
    m = _TRAILER.search(h)
    h = h[:m.start()] if m else h
    if not h.endswith(")"):
        return path.endswith(".dart") and bool(re.search(r"\b(?:get|set)\s+\w+\s*$", h))
    depth = 0
    for i in range(len(h) - 1, -1, -1):
        if h[i] == ")":
            depth += 1
        elif h[i] == "(":
            depth -= 1
            if depth == 0:
                before = h[:i].rstrip()
                name = re.search(r"([A-Za-z_]\w*)\s*(?:<[^<>]*>)?$", before)
                if not name or name.group(1) in _NOT_FUNCTIONS:
                    return False
                prev = before[:name.start()].rstrip()
                if prev.endswith((".", "new", "?", "!")):
                    return False
                return path.endswith(".dart") or bool(re.search(r"[\w>\]?*]$", prev))
    return False


def _enclosing_function(blank: str, idx: int, path: str) -> Tuple[int, int, str]:
    """(body start, body end, head text) of the innermost function around `idx`, or the whole file."""
    depth = 0
    i = idx
    while i > 0:
        i -= 1
        c = blank[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth:
                depth -= 1
                continue
            head = blank[max(0, i - 400):i]
            cut = max(head.rfind(";"), head.rfind("}"), head.rfind("{"))
            head = head[cut + 1:]
            if _is_function_head(head, path):
                return i, guards.match(blank, i, "{", "}"), head
    return 0, len(blank), ""


def _function_name(head: str) -> str:
    m = re.search(r"([A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\([^{]*$", head)
    return m.group(1) if m else ""


def _declaration(head: str, keep_params: bool = False) -> str:
    """The function's own declaration from a head: its annotations, modifiers, and name, without the
    parameter list or the unrelated declarations that came before it."""
    lines = [ln for ln in head.split("\n") if ln.strip()]
    out: List[str] = []
    while lines:
        line = lines.pop()
        out.append(line)
        if re.search(r"\b(?:fun|func|init|void|static|public|private|protected|internal|override)\b"
                     r"|^\s*[-+]\s*\(|\w[\w<>\[\]?]*\s+\w+\s*\(", line):
            break
    while lines and lines[-1].lstrip().startswith("@"):
        out.append(lines.pop())
    text = " ".join(reversed(out))
    for _ in range(0 if keep_params else 3):
        text = re.sub(r"\([^()]*\)", "()", text)
    return text


def _enclosing_call(blank: str, idx: int) -> str:
    """Name of the call whose argument list holds `idx`, e.g. `getActivity` for a request code."""
    depth = 0
    for i in range(idx - 1, max(0, idx - 400) - 1, -1):
        c = blank[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth:
                depth -= 1
                continue
            m = re.search(r"([A-Za-z_]\w*)\s*$", blank[max(0, i - 80):i])
            return m.group(1) if m else ""
        elif c in "{};" and depth == 0:
            return ""
    return ""


def _identifier_words(code: str) -> Set[str]:
    words: Set[str] = set()
    for ident in set(re.findall(r"[A-Za-z_]\w*", code)):
        for part in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", ident):
            words.add(part.lower())
    return words


def _line_span(code: str, idx: int) -> Tuple[int, int]:
    start = code.rfind("\n", 0, idx) + 1
    end = code.find("\n", idx)
    return start, (len(code) if end < 0 else end)


def _scan(ctx: Context, rule_patterns: Sequence[Tuple[Pattern[str], str]], suffixes: Tuple[str, ...] = CODE,
          keep_strings: bool = True, prefilter: Sequence[str] = (),
          mask_group: Optional[int] = None) -> Iterable[Hit]:
    """Run (regex, message) pairs over code; at most one hit per line."""
    for path in ctx.files(*suffixes):
        raw = ctx.text(path)
        if raw is None or (prefilter and not any(p in raw for p in prefilter)):
            continue
        code = ctx.code(path, keep_strings=keep_strings)
        if code is None:
            continue
        seen: Set[int] = set()
        for regex, message in rule_patterns:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                snippet = ctx.snippet(path, line)
                if mask_group is not None:
                    snippet = _mask_in(snippet, m.group(mask_group) or "")
                yield Hit(path, line, snippet, message, _hit_scope(ctx, path, m.start()))


def _placeholder(value: str) -> bool:
    v = value.upper()
    return "EXAMPLE" in v or bool(re.search(r"(.)\1{7,}", value))


# ---------------------------------------------------------------------------- XPL-001

# A PEM header alone is how code strips or assembles a PEM; a key needs base64 body after it, in the
# same literal or a concatenated one.
PEM_WITH_BODY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    r"(?:\\[nr]|[ \t\r\n]|\"[ \t\r\n]*\+[ \t\r\n]*@?\"|\"\"\")*[A-Za-z0-9+/]{32}"
)
RESTRICTED: List[Tuple[Pattern[str], str]] = [
    (PEM_WITH_BODY, "A private key is embedded in the code."),
    (re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
     "An AWS access key ID; its secret key is usually stored next to it."),
    (re.compile(r"(?<![\w-])sk-[A-Za-z0-9_\-]{20,}"),
     "This looks like a model-provider API key (`sk-…`), which is billed to you per use."),
    (re.compile(r"(?<![\w])[sr]k_live_[0-9A-Za-z]{20,}"),
     "A live Stripe secret or restricted key; it can move money on your account."),
    (re.compile(r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
     "A GitHub token; it can read or change your repositories."),
    (re.compile(r"(?<![\w])xox[baprs]-[A-Za-z0-9-]{10,}"),
     "A Slack token; it can read or post to your workspace."),
]


@detector("xpl_restricted_secret")
def restricted_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        raw = ctx.text(path)
        if raw is None or not any(p in raw for p in ("PRIVATE KEY", "AKIA", "ASIA", "sk-", "k_live_", "ghp_", "gho_",
                                                      "ghu_", "ghs_", "ghr_", "github_pat_", "xox")):
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen: Set[int] = set()
        for regex, message in RESTRICTED:
            for m in regex.finditer(code):
                if _placeholder(m.group(0)[-32:] if m.group(0).startswith("-----") else m.group(0)):
                    continue
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                snippet = ctx.snippet(path, line)
                if not m.group(0).startswith("-----"):      # a PEM header line is not itself secret
                    snippet = _mask_in(snippet, m.group(0))
                yield Hit(path, line, snippet, message, _hit_scope(ctx, path, m.start()))


# ---------------------------------------------------------------------------- XPL-002

GOOGLE_KEY = re.compile(r"(?<![\w-])AIza[0-9A-Za-z_\-]{35}(?![\w-])")


@detector("xpl_google_api_key")
def google_api_key(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = ("A Google API key. Maps and Firebase keys ship by design; if this one calls a paid API "
           "such as Gemini, it's a restricted key and belongs behind your backend.")
    for hit in _scan(ctx, [(GOOGLE_KEY, msg)], prefilter=("AIza",), mask_group=0):
        yield hit


# ---------------------------------------------------------------------------- XPL-003

SECRET_ASSIGN = re.compile(
    r"\b(k?(?:client|api|app|consumer)[_\-]?secret)\b[\"']?"
    r"(?:\s*:\s*[A-Za-z_][\w.]*[?!]?)?"            # optional type annotation (Swift/Kotlin)
    r"\s*(?:=|:|\bto\b)\s*@?(?:\"([^\"\n]{8,})\"|'([^'\n]{8,})')",    # Dart also quotes with '...'
    re.IGNORECASE,
)
_FAKE_VALUE = re.compile(r"(?i)^(?:fake|dummy|test|mock|sample|example|changeme|secret$|your|replace|change|"
                         r"placeholder|todo|insert|xxx|none|null|redacted)")


def _real_secret_value(value: str, key: str = "") -> bool:
    v = value.strip()
    if any(s in v for s in ("${", "$(", "{{", "%", "<", "\\(")) or re.search(r"\$[A-Za-z_]", v):
        return False                                # an interpolated or formatted value
    if _FAKE_VALUE.match(v):
        return False
    if re.fullmatch(r"[a-z]+(?:[_.\-][a-z]+)*", v) or re.fullmatch(r"[A-Z]+(?:_[A-Z]+)*", v):
        return False                                # a key name such as "client_secret", not a value
    if re.fullmatch(r"[a-z]+(?:[A-Z][a-z0-9]*)+", v):
        return False                                # a camelCase key name such as "clientSecret"
    norm = re.sub(r"[_\-]", "", v).lower()
    if key and norm == re.sub(r"[_\-]", "", key).lower().lstrip("k"):
        return False
    return not _placeholder(v)


def _inside_json_literal(code: str, blank: str, key_start: int) -> bool:
    """`"{\"clientSecret\": …}"` written inside a string literal: test data or a request body. The quote
    before the key is then itself string content, which the blanked copy hides."""
    i = key_start - 1
    return i >= 0 and code[i] in "\"'" and blank[i] not in "\"'"


@detector("xpl_secret_assignment")
def secret_assignment(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        raw = ctx.text(path)
        if raw is None or "secret" not in raw.lower():
            continue
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in SECRET_ASSIGN.finditer(code):
            value = m.group(2) or m.group(3)
            if not _real_secret_value(value, m.group(1)) or _inside_json_literal(code, blank, m.start(1)):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, _mask_in(ctx.snippet(path, line), value),
                      f"`{m.group(1)}` is set to a literal value, so it ships inside the app.",
                      _hit_scope(ctx, path, m.start()))


# ---------------------------------------------------------------------------- XPL-004

ECB: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"Cipher\.getInstance\(\s*\"AES\"\s*[,)]"),
     "`Cipher.getInstance(\"AES\")` names no mode, and Android can silently pick ECB."),
    (re.compile(r"[\"']AES/ECB[^\"'\n]*[\"']"), "AES in ECB mode: identical blocks give identical ciphertext."),
    (re.compile(r"\bkCC(?:OptionECBMode|ModeECB)\b"), "CommonCrypto in ECB mode."),
    (re.compile(r"\bECB\(\)"), "A block cipher in ECB mode."),
]
ECB_DART: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bAESMode\.ecb\b"), "package:encrypt AES in ECB mode."),
    (re.compile(r"\bECBBlockCipher\s*\("), "PointyCastle's ECB block cipher."),
]
# `static let ecbMode = Options(rawValue: kCCOptionECBMode)` defines an option; its uses are what matter.
_OPTION_DEFINITION = re.compile(r"\b(?:static\s+)?(?:let|var)\s+\w+\s*=\s*\w*\(\s*rawValue:\s*(?:CCOptions\()?\s*$")


_LEGACY_NAME = re.compile(r"(?i)legacy|migrat")
_NSAE_CATCH = re.compile(r"\bcatch\s*\(\s*(?:\w+\s*:\s*)?(?:[\w.]*\.)?(?:NoSuchAlgorithmException|"
                         r"NoSuchPaddingException|GeneralSecurityException)(?:\s+\w+)?\s*\)\s*\{[^{}]*$")


def _line_offset(code: str, line: int) -> int:
    idx = 0
    for _ in range(line - 1):
        idx = code.find("\n", idx) + 1
        if idx == 0:
            return len(code)
    return idx


def _legacy_reason(ctx: Context, path: str, line: int) -> str:
    """Why this crypto looks like it only reads old data: legacy or migration code, or the fallback in a
    `catch (NoSuchAlgorithmException)` when the modern mode is missing. '' if neither."""
    blank = ctx.code(path, keep_strings=False) or ""
    idx = _line_offset(blank, line)
    owner = [m.group(1) for m in re.finditer(r"\b(?:class|object|struct|interface|enum)\s+(\w+)", blank[:idx])]
    fn = _function_name(_enclosing_function(blank, idx, path)[2]) if path.endswith(CODE) else ""
    if _LEGACY_NAME.search(path) or (owner and _LEGACY_NAME.search(owner[-1])) or _LEGACY_NAME.search(fn):
        return " This looks like legacy or migration code kept for data from older versions; remove it once migrated."
    line_end = blank.find("\n", idx)
    if _NSAE_CATCH.search(blank[max(0, idx - 300):line_end if line_end >= 0 else len(blank)]):
        return " It's only the fallback when the modern mode is missing on the device."
    return ""


def _lower_if_legacy(ctx: Context, hit: Hit) -> Hit:
    reason = _legacy_reason(ctx, hit.path, hit.line)
    if reason:
        hit.severity = "low"
        hit.message += reason
    return hit


@detector("xpl_ecb")
def ecb(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for hit in _scan(ctx, ECB, prefilter=("AES", "ECB")):
        before = hit.snippet.split("kCCOptionECBMode")[0] if "kCCOptionECBMode" in hit.snippet else ""
        if before and _OPTION_DEFINITION.search(before):
            continue
        yield _lower_if_legacy(ctx, hit)
    for hit in _scan(ctx, ECB_DART, suffixes=DART, keep_strings=False, prefilter=("AESMode", "ECBBlockCipher")):
        yield _lower_if_legacy(ctx, hit)
    # Keystore: ECB is a misnomer that RSA keys legitimately use, so flag it only for AES keys.
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "BLOCK_MODE_ECB" not in raw or "KEY_ALGORITHM_AES" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        if re.search(r"KEY_ALGORITHM_(?:RSA|EC)\b", code) or "KEY_ALGORITHM_AES" not in code:
            continue
        for m in re.finditer(r"\bBLOCK_MODE_ECB\b", code):
            line = ctx.line_of(code, m.start())
            yield _lower_if_legacy(ctx, Hit(path, line, ctx.snippet(path, line),
                                            "A Keystore AES key that allows ECB mode.",
                                            _hit_scope(ctx, path, m.start(), code)))


# ---------------------------------------------------------------------------- XPL-005

CBC: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"[\"']AES/CBC[^\"'\n]*[\"']"), "AES-CBC encrypts but doesn't detect tampering."),
    (re.compile(r"\bBLOCK_MODE_CBC\b"), "A Keystore key that uses CBC mode."),
    (re.compile(r"\bkCCModeCBC\b"), "CommonCrypto in CBC mode."),
    (re.compile(r"\bCBC\(\s*iv:"), "A block cipher in CBC mode."),
]
CBC_DART: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bAESMode\.cbc\b"), "package:encrypt AES in CBC mode."),
    (re.compile(r"\bCBCBlockCipher\s*\("), "PointyCastle's CBC block cipher."),
]
# A file that also computes an HMAC is following the rule's own fix (encrypt-then-MAC).
_MAC_IN_FILE = re.compile(r"\bMac\.getInstance\s*\(|\bHMAC\s*<|\bCCHmac\w*\s*\(|\bHMac\s*\(|\bHmac\s*\(|"
                          r"\bHMAC\s*\(|\bKEY_ALGORITHM_HMAC_SHA\d+\b|\bHmacSHA\d+\b|"
                          r"\bMAC_SIZE\b|\bMacInputStream\b|\bverifyMac\w*\s*\(")
# A Keystore key that needs user authentication for every use never leaves the Keystore; CBC there only
# binds a biometric or credential prompt, so tampering with its output gains an attacker nothing.
_KEYSPEC_CHAIN = re.compile(r"\bKeyGenParameterSpec\s*\.\s*Builder\s*\(")


def _auth_bound_cbc_keys(blank: str) -> List[Tuple[int, int]]:
    """Spans of `KeyGenParameterSpec.Builder(...)...build()` chains that use CBC and require user auth."""
    out = []
    for m in _KEYSPEC_CHAIN.finditer(blank):
        b = re.compile(r"\.\s*build\s*\(\s*\)").search(blank, m.end(), m.end() + 1500)
        if not b:
            continue
        chain = blank[m.start():b.end()]
        if "BLOCK_MODE_CBC" in chain and re.search(r"setUserAuthenticationRequired\s*\(\s*true\s*\)", chain):
            out.append((m.start(), b.end()))
    return out


@detector("xpl_cbc")
def cbc(ctx: Context, rule: Rule) -> Iterable[Hit]:
    seen_files: Set[str] = set()
    for suffixes, pats, keep, pre in ((CODE, CBC, True, ("CBC",)),
                                      (DART, CBC_DART, False, ("AESMode", "CBCBlockCipher"))):
        for hit in _scan(ctx, pats, suffixes=suffixes, keep_strings=keep, prefilter=pre):
            if hit.path in seen_files:
                continue                     # one report per file: the key spec and the transformation
            if _MAC_IN_FILE.search(ctx.code(hit.path, keep_strings=True) or ""):
                continue
            seen_files.add(hit.path)
            blank = (ctx.code(hit.path, keep_strings=False) or "") if hit.path.endswith(JVM) else ""
            spans = _auth_bound_cbc_keys(blank)
            in_chain = any(ctx.line_of(blank, s) <= hit.line <= ctx.line_of(blank, e) for s, e in spans)
            # A transformation string pairs with the auth-bound key unless the file also builds a software key.
            if in_chain or (spans and not re.search(r"\bSecretKeySpec\s*\(|\bKeyGenerator\s*\.\s*getInstance\s*\("
                                                    r"\s*[\"']AES[\"']\s*\)", ctx.code(hit.path) or "")):
                hit.severity = "low"
                hit.message += (" The Keystore key requires user authentication for every use, so it only "
                                "binds the biometric or credential prompt; prefer GCM anyway.")
            yield hit


# ---------------------------------------------------------------------------- XPL-006

_LITERAL_BYTES = (
    r"(?:ByteArray\(\s*\d+\s*\)"                       # Kotlin zero-filled array
    r"|byteArrayOf\([^)]*\)"
    r"|new\s+byte\s*\[\s*\d+\s*\]"                     # Java zero-filled array
    r"|new\s+byte\s*\[\s*\]\s*\{"
    r"|\"[^\"\n]*\"\s*\.\s*(?:toByteArray|getBytes|encodeToByteArray)\s*\()"
)
IV_INLINE = re.compile(
    r"\b(?:IvParameterSpec\(\s*|GCMParameterSpec\(\s*[^,()]+,\s*)" + _LITERAL_BYTES
)
IV_CALL_VAR = re.compile(r"\b(?:IvParameterSpec\(\s*|GCMParameterSpec\(\s*[^,()]+,\s*)([A-Za-z_]\w*)\s*[,)]")
SWIFT_NONCE = re.compile(
    r"\b(?:AES\.GCM|ChaChaPoly)\.Nonce\(\s*data:\s*(?:Data\(\s*\[|Data\(\s*\"|Data\(\s*repeating:"
    r"|\"[^\"\n]*\"\s*\.data\(|\[)"
    r"|\biv:\s*(?:\"[^\"\n]*\"|Array\(\s*\"|Array\(\s*repeating:|\[\s*(?:0x)?[0-9])"
)
# package:encrypt and PointyCastle. IV.fromLength is random in current package:encrypt, so it's not here.
_DART_LITERAL_BYTES = r"Uint8List\s*(?:\(\s*\d|\.fromList\s*\(\s*(?:const\s*)?\[)"
DART_IV = re.compile(
    r"\bIV\s*\.\s*(?:allZerosOfLength\s*\(|from(?:Utf8|Base64|Base16)\s*\(\s*r?[\"'])"
    r"|\bIV\s*\(\s*" + _DART_LITERAL_BYTES
    + r"|\bParametersWithIV\s*(?:<[^>]*>)?\s*\((?:[^,()]|\((?:[^()]|\([^()]*\))*\))+,\s*" + _DART_LITERAL_BYTES
)


def _filled(text: str, name: str) -> bool:
    """Does `text` write into the buffer `name` (random bytes, a copy, a read, or element stores)?"""
    n = re.escape(name)
    return bool(re.search(
        r"nextBytes\(\s*" + n + r"\s*\)|arraycopy\([^;]*?,\s*" + n + r"\s*,|\b" + n + r"\s*\.\s*copyInto\b"
        r"|\.copyInto\(\s*(?:destination\s*=\s*)?" + n + r"\b|\bread(?:Fully|NBytes)?\(\s*" + n + r"\b"
        r"|\breadFully\([^;\n]*\b" + n + r"\b|\bdoFinal\([^;\n]*\b" + n + r"\b|\b" + n + r"\s*\[[^\]]+\]\s*="
        r"|\bget\(\s*" + n + r"\s*[,)]|\b" + n + r"\s*=(?!=)\s*(?!ByteArray\(|new\s+byte)",
        text))


def _var_is_literal(code: str, name: str, idx: int = -1, path: str = ".kt", blank: Optional[str] = None) -> bool:
    """Is `name`, used at `idx`, a literal byte array or string in its function (or a class constant)?

    A sized zero buffer counts only when nothing in the function fills it."""
    blank = blank if blank is not None else code
    start, end, _head = _enclosing_function(blank, idx, path) if idx >= 0 else (0, len(code), "")
    pats = (
        r"\b" + re.escape(name) + r"\b(?:\s*:\s*ByteArray)?\s*=\s*(" + _LITERAL_BYTES + r"|\{)",
        r"byte\s*\[\s*\]\s*" + re.escape(name) + r"\s*=\s*(\{|" + _LITERAL_BYTES + ")",
    )
    for pat in pats:
        for decl in re.finditer(pat, code):
            in_function = start <= decl.start() < end
            if not in_function:
                if idx < 0:
                    in_function = True
                elif _enclosing_function(blank, decl.start(), path)[2]:
                    continue                 # declared inside another function
            scope_text = code[start:end] if in_function and idx >= 0 else code
            init = decl.group(1)
            if re.match(r"ByteArray\(|new\s+byte\s*\[\s*\d", init):
                stmt_end = code.find("\n", decl.end())
                stmt = code[decl.end():stmt_end if stmt_end >= 0 else len(code)]
                if re.match(r"\s*\)?\s*\.\s*(?:also|apply)\s*\{[^}]*nextBytes", stmt):
                    return False
                rest = scope_text.replace(code[decl.start():decl.end()], "", 1)
                if _filled(rest, name) or re.search(r"getSecretBytes|SecureRandom", scope_text):
                    return False
            return True
    return False


_FRESH_KEY = re.compile(r"doFinal\s*\(|hkdf|Hkdf|HKDF|derive\w*\s*\(|computeCipherKey|calculateAgreement|"
                        r"getSecretBytes|generateKey\s*\(")


def _per_message_key(code: str, blank: str, idx: int, path: str) -> bool:
    """The IV is fixed, but the key in the same `init` is derived fresh in this function (SIV-style,
    a key per file), or the function is itself a key-derivation step."""
    start, end, head = _enclosing_function(blank, idx, path)
    if re.search(r"(?i)derive|kdf", _function_name(head)):
        return True
    window = code[max(0, idx - 300):idx]
    at = window.rfind("init(")
    segment = window[at:] if at >= 0 else window[window.rfind("\n") + 1:]
    m = re.search(r"SecretKeySpec\(\s*([A-Za-z_]\w*)\s*[,)]|\binit\(\s*[^,()]+,\s*([A-Za-z_]\w*)\s*,", segment)
    if not m:
        return False
    key = m.group(1) or m.group(2)
    assign = re.search(r"\b" + re.escape(key) + r"\b(?:\s*:\s*[\w<>?]+)?\s*=\s*([^;\n]*)", code[start:idx])
    return bool(assign and _FRESH_KEY.search(assign.group(1)))


@detector("xpl_static_iv")
def static_iv(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = "The IV or nonce is a fixed value, so it repeats for every message encrypted with this key."
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "ParameterSpec" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in IV_INLINE.finditer(code):
            line = ctx.line_of(code, m.start())
            seen.add(line)
            if _per_message_key(code, blank, m.start(), path):
                continue
            yield Hit(path, line, ctx.snippet(path, line), msg, _hit_scope(ctx, path, m.start(), blank))
        for m in IV_CALL_VAR.finditer(code):
            line = ctx.line_of(code, m.start())
            if line in seen or not _var_is_literal(code, m.group(1), m.start(), path, blank):
                continue
            seen.add(line)
            if _per_message_key(code, blank, m.start(), path):
                continue
            yield Hit(path, line, ctx.snippet(path, line), msg, _hit_scope(ctx, path, m.start(), blank))
    for hit in _scan(ctx, [(SWIFT_NONCE, msg)], suffixes=(".swift",), prefilter=("Nonce(", "iv:")):
        yield hit
    for hit in _scan(ctx, [(DART_IV, msg)], suffixes=DART, prefilter=("IV",)):
        yield hit


# ---------------------------------------------------------------------------- XPL-007

WEAK_HASH: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\""), "MD5 or SHA-1 through MessageDigest"),
    (re.compile(r"(?<!HMAC<)\bInsecure\.(?:MD5|SHA1)\b(?!\s*>)"), "CryptoKit's `Insecure` MD5 or SHA-1"),
    (re.compile(r"\bCC_(?:MD5|SHA1)\s*\("), "CommonCrypto MD5 or SHA-1"),
    (re.compile(r"\bDigestUtils\.(?:md5|sha1)\w*\s*\("), "MD5 or SHA-1 through DigestUtils"),
    (re.compile(r"\bHashing\.(?:md5|sha1)\s*\("), "MD5 or SHA-1 through Guava"),
]
WEAK_HASH_DART: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"(?<![\w.])(?:md5|sha1)\s*\.\s*(?:convert|startChunkedConversion|bind)\s*\("),
     "MD5 or SHA-1 from package:crypto"),
    (re.compile(r"\b(?:MD5|SHA1)Digest\s*\(|\bDigest\s*\(\s*[\"'](?:MD5|SHA-1)[\"']"),
     "MD5 or SHA-1 through PointyCastle"),
]
# The hash only matters when it protects something: a password, a signature, a token.
_HASH_SECURITY = {"password", "passwd", "passcode", "signature", "sign", "signed", "verify", "verification",
                  "integrity", "certificate", "cert", "pin", "pinning", "token", "auth", "authenticate",
                  "credential", "credentials", "otp", "license", "receipt", "secret", "tamper"}
# Protocols that mandate MD5 or SHA-1 (CRAM-MD5, APOP, HIBP's k-anonymity range API, Commons paths).
_HASH_PROTOCOL = {"cram", "apop", "pwned", "hibp", "breach", "breaches", "podcastindex", "etag", "commons",
                  "gravatar", "hmac", "totp", "hotp"}


def _hash_context(blank: str, idx: int, path: str) -> Set[str]:
    s, e = _line_span(blank, idx)
    _start, _end, head = _enclosing_function(blank, idx, path)
    return _identifier_words(blank[s:e]) | _identifier_words(_declaration(head, keep_params=True))


@detector("xpl_weak_hash")
def weak_hash(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for suffixes, pats in ((JVM + APPLE, WEAK_HASH), (DART, WEAK_HASH_DART)):
        for path in ctx.files(*suffixes):
            raw = ctx.text(path) or ""
            if not any(p in raw for p in ("MD5", "SHA1", "SHA-1", "md5", "sha1")):
                continue
            code = ctx.code(path, keep_strings=True) or ""
            blank = ctx.code(path, keep_strings=False) or ""
            seen: Set[int] = set()
            for regex, what in pats:
                for m in regex.finditer(code):
                    line = ctx.line_of(code, m.start())
                    if line in seen:
                        continue
                    words = _hash_context(blank, m.start(), path)
                    hits = sorted(words & _HASH_SECURITY)
                    if not hits or words & _HASH_PROTOCOL:
                        continue
                    seen.add(line)
                    yield Hit(path, line, ctx.snippet(path, line),
                              f"{what}, in code that handles `{hits[0]}`.", _hit_scope(ctx, path, m.start(), blank))


# ---------------------------------------------------------------------------- XPL-008

RNG_JVM: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bjava\.util\.Random\s*[.(]"), "`java.util.Random` is predictable from a few outputs."),
    (re.compile(r"\bkotlin\.random\.Random\s*[.(]"), "`kotlin.random.Random` is not a secure generator."),
    (re.compile(r"\bMath\.random\s*\("), "`Math.random()` is predictable."),
    (re.compile(r"\bsetSeed\s*\("), "A generator seeded by the caller."),
]
# SecureRandom seeded by the caller is wrong whatever the value is used for.
RNG_SEEDED_SECURE = re.compile(r"\bSecureRandom\s*\(\s*[A-Za-z_\"]")
# Uses of an imported `Random` (an unused import is not a finding).
RNG_IMPORTED_USE = re.compile(r"(?<![\w.])Random\s*(?:\.\s*(?:next\w*|Default)\b|\()|\bnew\s+Random\s*\(")
RNG_IMPORTS = (
    (re.compile(r"^[ \t]*import\s+java\.util\.(?:Random|\*)\b", re.MULTILINE),
     "`java.util.Random` is predictable from a few outputs."),
    (re.compile(r"^[ \t]*import\s+kotlin\.random\.(?:Random|\*)\b", re.MULTILINE),
     "`kotlin.random.Random` is not a secure generator."),
)
RNG_APPLE: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"(?<![\w.])(?:rand|random|drand48|lrand48)\s*\(\s*\)"),
     "`rand()`/`random()` are predictable C generators."),
    (re.compile(r"(?<![\w.])(?:srand|srandom|srand48)\s*\("), "A C generator seeded by the caller."),
]
# dart:math `Random()`; `Random.secure()` is the safe one.
DART_RANDOM = re.compile(r"(?<![\w.])Random\s*\(")
# Words that say the value protects something. Strong words count on their own; weak words count only
# when nothing in the context says the value is an ID, a delay, or decoration.
RNG_STRONG = {"token", "nonce", "salt", "secret", "password", "passcode", "passphrase", "otp", "totp", "hotp",
              "iv", "cipher", "encrypt", "encryption", "csrf", "xsrf", "verifier", "jwt", "credential",
              "credentials", "mnemonic", "sessiontoken", "sessionkey", "oauthstate", "apikey"}
RNG_WEAK = {"key", "auth", "oauth", "pin", "uuid", "recovery", "entropy", "secure", "crypto",
            "sessionid"}
RNG_NON_SECURITY = {"request", "notification", "notify", "jitter", "delay", "backoff", "color", "colour",
                    "animation", "animate", "particle", "confetti", "shuffle", "shuffled", "sample", "sampling",
                    "cohort", "preview", "previews", "position", "badge", "index", "download", "snackbar",
                    "selection", "item", "items", "list", "remember", "saveable", "vm", "cache", "lazy",
                    "compose", "composable", "view", "schedule", "backup", "placeholder", "fake", "mock",
                    "demo", "game", "move", "file", "filename", "temp", "tmp", "pixel", "experiment",
                    "group", "campaign", "survey", "bucket", "retry", "interval", "spoiler", "bubble",
                    "pending", "intent", "activity", "broadcast", "alarm", "analytics", "metrics", "telemetry",
                    "event", "events", "url", "urls", "host", "server", "migration", "hour", "minute"}
# Calls whose argument is an ID, a delay, or a pick, whatever the surrounding code handles.
_RNG_ID_SINKS = {"getActivity", "getActivities", "getBroadcast", "getService", "getForegroundService", "notify",
                 "delay", "sleep", "postDelayed", "sendEmptyMessageDelayed", "startActivityForResult",
                 "requestPermissions", "shuffle", "shuffled", "setRequestCode", "Notification"}
# Module or package folders whose randomness is about measurement, not protection.
_RNG_NON_SECURITY_PATH = re.compile(r"(?i)/(?:analytics|metrics|telemetry|tracking|experiments?|abtest\w*)/")


def _rng_security_words(blank: str, idx: int, path: str) -> List[str]:
    """Security words in the statement, its assignment target, and the enclosing function's name and
    annotations. Checked per use, never per file."""
    s, e = _line_span(blank, idx)
    call = _enclosing_call(blank, idx)
    if call in _RNG_ID_SINKS:
        return []
    _start, _end, head = _enclosing_function(blank, idx, path)
    text = blank[s:e] + " " + _declaration(head) + " " + call
    words = _identifier_words(text)
    if _RNG_NON_SECURITY_PATH.search("/" + path):
        words.add("analytics")
    idents = {i.lower() for i in re.findall(r"[A-Za-z_]\w*", text)}
    for ident in idents:
        for compound in ("sessionid", "sessiontoken", "sessionkey", "oauthstate", "apikey"):
            if compound in ident:
                words.add(compound)
    if "preview" in words or "previews" in words:
        return []
    strong = words & RNG_STRONG
    if strong:
        return sorted(strong)
    weak = words & RNG_WEAK
    if weak and not words & RNG_NON_SECURITY:
        return sorted(weak)
    return []


@detector("xpl_insecure_random")
def insecure_random(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "Random" not in raw and "random" not in raw and "setSeed" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in RNG_SEEDED_SECURE.finditer(code):
            line = ctx.line_of(code, m.start())
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), "A SecureRandom seeded by the caller.",
                      _hit_scope(ctx, path, m.start(), code))
        pats = list(RNG_JVM)
        for imp, message in RNG_IMPORTS:
            if imp.search(code):
                pats.append((RNG_IMPORTED_USE, message))
                break
        for regex, message in pats:
            for m in regex.finditer(code):
                if regex.pattern.startswith(r"\bsetSeed") and "Random" not in code:
                    continue
                s, _e = _line_span(code, m.start())
                if re.match(r"\s*import\b", code[s:m.start()]):
                    continue                   # `import kotlin.random.Random.Default.nextInt`
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                words = _rng_security_words(code, m.start(), path)
                if not words:
                    continue
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), f"{message[:-1]}, and it produces a `{words[0]}`.",
                          _hit_scope(ctx, path, m.start(), code))
    for path in ctx.files(*APPLE):
        raw = ctx.text(path) or ""
        if "rand" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen = set()
        for regex, message in RNG_APPLE:
            for m in regex.finditer(code):
                s, _e = _line_span(code, m.start())
                if re.search(r"\bfunc\s+$", code[s:m.start()]):
                    continue                   # `static func random() -> UInt32` declares a function
                line = ctx.line_of(code, m.start())
                words = _rng_security_words(code, m.start(), path)
                if line in seen or not words:
                    continue
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), f"{message[:-1]}, and it produces a `{words[0]}`.",
                          _hit_scope(ctx, path, m.start(), code))
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "Random" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen = set()
        for m in DART_RANDOM.finditer(code):
            line = ctx.line_of(code, m.start())
            words = _rng_security_words(code, m.start(), path)
            if line in seen or not words:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"dart:math `Random()` is predictable, and it produces a `{words[0]}`.",
                      _hit_scope(ctx, path, m.start(), code))


# ---------------------------------------------------------------------------- XPL-009

HTTP_URL = re.compile(r"[\"']http://([^\"'\s/?#]*)")
DART_URI_HTTP = re.compile(r"\bUri\s*\.\s*http\s*\(\s*[\"']([^\"'\s/?#]*)")
_PORT = r"(?::(?:\d+|\$\{[^}]*\}|\$\w+|\\\([^)]*\)|%\w))?"
SAFE_HOSTS = re.compile(
    r"^(?:localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\[::1\]|"
    r"(?:[\w-]+\.)*example\.(?:com|org|net)|schemas\.android\.com|schemas\.xmlsoap\.org|"
    r"schemas\.microsoft\.com|www\.w3\.org|w3\.org|ns\.adobe\.com|ns\.apple\.com|www\.apple\.com|purl\.org|"
    r"xmlpull\.org|(?:www\.)?itunes\.com|search\.yahoo\.com|podlove\.org|"
    r"(?:[\w-]+\.)*(?:localhost|test|invalid|local))" + _PORT + "$",
    re.IGNORECASE,
)
PLACEHOLDER_HOST = re.compile(
    r"^(?:www\.)?(?:domain|mydomain|myserver|yourserver|your-server|server|host|hostname|foo|bar|local-ip|"
    r"ip-address|ip|address|example)(?:\.(?:com|org|net|tld))?" + _PORT + "$", re.IGNORECASE)
# Private address ranges are XPL-036's job (non-production endpoints).
PRIVATE_IP = re.compile(r"^(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)" + _PORT + "$")
_NOT_A_FETCH = {"ns", "nsuri", "namespace", "namespaces", "xmlns", "dtd", "license", "licenses", "placeholder",
                "hint", "prefix", "prefixes", "schema", "referer", "referrer", "library", "libraries", "homepage"}


# The URL is opened in the user's browser (a help link), not fetched by the app.
_BROWSER_OPEN = re.compile(r"\b(?:launchUri|launchUrl|launchUrlString|launchBrowser|openInBrowser|openBrowser|"
                           r"openExternal\w*|openUri|openURL|openUrl)\s*\(|\bIntent\s*\.\s*ACTION_VIEW\b|"
                           r"\bACTION_VIEW\b|\bCustomTabsIntent\b|\bUIApplication\s*\.\s*shared\s*\.\s*open\s*\(|"
                           r"\bSFSafariViewController\s*\(|\buriHandler\s*\.\s*openUri\b")


@detector("xpl_http_url")
def http_url(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        if scope_of(path) in ("test", "build-script"):
            continue                         # tests and build tooling never ship
        raw = ctx.text(path)
        is_dart = path.endswith(".dart")
        if raw is None or not ("http://" in raw or (is_dart and "Uri.http" in raw)) or _TEST_IMPORT.search(raw):
            continue
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        matches = list(HTTP_URL.finditer(code))
        if is_dart:
            matches += list(DART_URI_HTTP.finditer(code))     # Uri.http('host', '/path') is plain HTTP
        for m in sorted(matches, key=lambda m: m.start()):
            host = m.group(1)
            if (not host or host.startswith(("%", "$", "\\(", "[")) or host.endswith(".")
                    or SAFE_HOSTS.match(host) or PLACEHOLDER_HOST.match(host) or PRIVATE_IP.match(host)):
                continue                     # a scheme prefix, a URL builder, a placeholder, or a safe host
            after = code[m.end():m.end() + 6]
            if re.match(r"[\"']\s*\+", after) and m.group(0)[-1:] != "/":
                continue                     # "http://" + host: a builder
            line_start, line_end = _line_span(code, m.start())
            if re.search(r"xmlns|DOCTYPE", code[line_start:m.start()]):
                continue
            if _identifier_words(blank[line_start:line_end]) & _NOT_A_FETCH:
                continue
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                hit = Hit(path, line, ctx.snippet(path, line), f"A plain-HTTP URL to `{host}`.",
                          _hit_scope(ctx, path, m.start(), blank))
                prev_start = code.rfind("\n", 0, max(0, line_start - 1)) + 1
                if _BROWSER_OPEN.search(blank[prev_start:line_end]):
                    hit.severity = "low"
                    hit.message += " It's opened in the browser rather than fetched by the app; still link to https."
                yield hit


# ---------------------------------------------------------------------------- XPL-010

LOG_CALL = re.compile(
    r"(?<![\w.])(?:Log\.(?:v|d|i|w|e|wtf)|Timber\.(?:v|d|i|w|e|wtf)|System\.(?:out|err)\.print(?:ln|f)?|"
    r"println|print|debugPrint|NSLog|os_log)\s*\("
)
DART_LOG_CALL = re.compile(r"(?<![\w.])(?:print|debugPrint|debugPrintSynchronously|log|developer\.log)\s*\(")
SENSITIVE_WORD = re.compile(r"(?i)token|passw(?:or)?d|passwd|secret|authorization|bearer")
SENSITIVE_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
INTERP = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*)|\\\(([^)]*)\)")
# Derived values that reveal nothing: a length, a null check, a masked tail, an expiry date.
_SAFE_SUFFIX = re.compile(
    r"\.(?:length|size|count|isEmpty|isNotEmpty|isBlank|isNotBlank|isNullOrEmpty|isNullOrBlank|hashCode|"
    r"expirationDate|expiresAt|expiry|expiration|type|id|ID)\b\s*(?:\(\s*\))?|\.takeLast\(\s*[1-4]\s*\)"
    r"|\.suffix\(\s*[1-4]\s*\)|[!=]==?\s*(?:null|nil)\b|\.get\(\)\.length\(\)|\bis\s+\w+"
)
_BOOL_PREFIX = re.compile(r"^(?:is|has|should|can|supports|use|uses|needs|did|was|show|enable|enabled)[A-Z_]")
# A name containing one of these words is about the token, not the token itself.
_NON_SECRET_ANYWHERE = re.compile(
    r"(?i)error|exception|throwable|failure|negativeresponse|keepalive|autocomplet|search|tokeni[sz]|"
    r"cancellation|continuation|expir|tokenid|tokentype|fcm|apns|devicetoken|pushtoken|hashtag|mention"
)
_NON_SECRET_SUFFIX = re.compile(
    r"(?:Count|Length|Size|Type|Changed|Updated|Received|Refreshed|Missing|Invalid|Expired|Required|Request|"
    r"Event|State|Status|Listener|Callback|Provider|Manager|Service|Repository|Store|Url|Uri|Endpoint|Label|"
    r"Title|Hint|Field|Format|Pattern|Regex|Key|Name|Prefix|Suffix|Policy|Id|Ids|Index|Enabled|Available)$"
)
# Files where a bare `token` means a word in text, a keep-alive counter, or a push registration.
_LEXICAL_TOKEN_FILE = re.compile(r"(?i)autocomplet|tokeni[sz]er|\btokenize|hashtag|keepalive|devicetoken|"
                                 r"didRegisterForRemoteNotifications|onNewToken|lexer|\bparser\b")
_WRAPPED = re.compile(r"(?:isEmpty|isNullOrEmpty|isNullOrBlank|isNotEmpty|TextUtils\.isEmpty|Objects\.isNull|"
                      r"isNull|nonNull|Strings\.isNullOrEmpty|hasText)\s*\(\s*$")


def _close_paren(code: str, start: int, limit: int = 600) -> int:
    depth = 0
    end = min(len(code), start + limit)
    for i in range(start, end):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return end


def _secret_expr(expr: str, before: str) -> bool:
    """Is `expr` (a name or an interpolated expression) the secret itself, not something derived?"""
    e = expr.strip()
    head = re.split(r"[.(\[?!]", e.lstrip("!$ {"), maxsplit=1)[0]
    last = re.findall(r"[A-Za-z_]\w*", e)
    tail_ident = last[-1] if last else head
    if not head or _BOOL_PREFIX.match(head) or _BOOL_PREFIX.match(tail_ident):
        return False
    secret_part = next((w for w in last if SENSITIVE_WORD.search(w)), head)
    if _NON_SECRET_ANYWHERE.search(secret_part) or _NON_SECRET_SUFFIX.search(secret_part) or secret_part.isupper():
        return False
    if _SAFE_SUFFIX.search(e) or _WRAPPED.search(before):
        return False
    if re.search(r"\bR\.string\.\w*$|getString\s*\(\s*R\.string\.\s*$", before + head):
        return False                  # an Android string resource ID, not a value
    if re.search(r"(?:\.\s*|\b)(?:get|Get)[A-Z]\w*Id\s*\(\s*\)$", e):
        return False
    return True


@detector("xpl_sensitive_log")
def sensitive_log(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        raw = ctx.text(path)
        if raw is None or not SENSITIVE_WORD.search(raw):
            continue
        bare = ctx.code(path, keep_strings=False) or ""     # string contents blanked
        full = ctx.code(path, keep_strings=True) or ""      # same offsets, strings kept
        seen: Set[int] = set()
        log_call = DART_LOG_CALL if path.endswith(".dart") else LOG_CALL
        for m in log_call.finditer(bare):
            open_at = m.end() - 1
            close = _close_paren(bare, open_at)
            if m.group(0).startswith("os_log") and "{public}" not in full[open_at:close]:
                continue                                    # os_log redacts dynamic values by default
            args_code = bare[open_at:close]
            args_text = full[open_at:close]
            names: List[str] = []
            # Sensitive names used as values (outside string literals).
            for w in SENSITIVE_IDENT.finditer(args_code):
                if not SENSITIVE_WORD.search(w.group(0)) or w.group(0) == "TAG":
                    continue
                # Take the whole expression the name heads: `token.get().length()`, `x != null`.
                rest = args_code[w.start():]
                expr = re.match(r"[\w.]+(?:\(\s*\))?(?:\.[\w]+(?:\(\s*\d*\s*\))?)*(?:\s*[!=]==?\s*\w+)?", rest)
                text = expr.group(0) if expr else w.group(0)
                if _secret_expr(text, args_code[:w.start()]):
                    names.append(w.group(0))
            for g in INTERP.finditer(args_text):
                expr = next(x for x in g.groups() if x is not None)
                if SENSITIVE_WORD.search(expr) and _secret_expr(expr, ""):
                    names.append(expr.strip())
            if names and all(n in ("token", "tokens") for n in names) and _LEXICAL_TOKEN_FILE.search(bare):
                continue
            if not names:
                continue
            line = ctx.line_of(bare, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), f"`{names[0]}` is written to the log.",
                      _hit_scope(ctx, path, m.start(), bare))


# ---------------------------------------------------------------------------- XPL-011

KEY_INLINE = re.compile(
    r"\bSecretKeySpec\(\s*(?:" + _LITERAL_BYTES
    + r"|(?:java\.util\.)?Base64\.(?:getDecoder\(\)\.decode|decode)\(\s*\"[^\"\n]+\")"
)
KEY_CALL_VAR = re.compile(r"\bSecretKeySpec\(\s*([A-Za-z_]\w*)\s*[,)]")
KEY_CALL_STRING_VAR = re.compile(
    r"\bSecretKeySpec\(\s*(?:[A-Za-z_][\w.]*\.)?([A-Za-z_]\w*)\s*\.\s*(?:toByteArray|getBytes|encodeToByteArray)\s*\("
)
SWIFT_KEY = re.compile(
    r"\bSymmetricKey\(\s*data:\s*(?:Data\(\s*\[|Data\(\s*\"|\"[^\"\n]*\"\s*\.data\(|\[|Array\(\s*\""
    r"|Data\(\s*base64Encoded:\s*\")"
    r"|\b(?:P256|P384|P521|Curve25519)\.(?:Signing|KeyAgreement)\.PrivateKey\(\s*rawRepresentation:\s*"
    r"(?:Data\(\s*(?:\[|\"|base64Encoded:\s*\")|\[)"
    r"|\bSecKeyCreateWithData\(\s*(?:Data\(\s*base64Encoded:\s*\"|\"[^\"\n]*\"\s*\.data\()"
)
SWIFT_KEY_VAR = re.compile(r"\bSymmetricKey\(\s*data:\s*(?:Data\(\s*)?([A-Za-z_]\w*)\s*(?:\.utf8|\.data\()")
# package:encrypt (Key.fromLength is all zeros; Key.fromSecureRandom is the safe one) and PointyCastle.
DART_KEY = re.compile(
    r"\bKey\s*\.\s*(?:from(?:Utf8|Base64|Base16)\s*\(\s*r?[\"']|fromLength\s*\()"
    r"|\bKey\s*\(\s*" + _DART_LITERAL_BYTES
    + r"|\bKeyParameter\s*\(\s*(?:" + _DART_LITERAL_BYTES + r"|utf8\.encode\s*\(\s*r?[\"'])"
)
_KEY_MSG = ("The encryption key is written in the code, so anyone who unpacks the app can read it "
            "and decrypt the data.")


def _mask_literals(snippet: str) -> str:
    """Hide key material in quoted literals: the report must not repeat the key."""
    return re.sub(r"([\"'])([^\"'\n]{4,})\1", lambda m: m.group(1) + m.group(2)[:2] + "…[masked]" + m.group(1),
                  snippet)


def _string_constant(code: str, name: str, *_args) -> bool:
    return bool(re.search(
        r"\b(?:val|var|let|String|final\s+String|static\s+final\s+String)?\s*\b" + re.escape(name)
        + r"\s*(?::\s*String)?\s*=\s*\"[^\"\n]+\"", code))


@detector("xpl_hardcoded_key")
def hardcoded_key(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "SecretKeySpec" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for regex, check in ((KEY_INLINE, None), (KEY_CALL_VAR, _var_is_literal),
                             (KEY_CALL_STRING_VAR, _string_constant)):
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line in seen or (check is not None and not check(code, m.group(1), m.start(), path, blank)):
                    continue
                seen.add(line)
                yield Hit(path, line, _mask_literals(ctx.snippet(path, line)), _KEY_MSG,
                          _hit_scope(ctx, path, m.start(), blank))
    for path in ctx.files(".swift"):
        raw = ctx.text(path) or ""
        if not any(p in raw for p in ("SymmetricKey", "PrivateKey(", "SecKeyCreateWithData")):
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen = set()
        for m in SWIFT_KEY.finditer(code):
            line = ctx.line_of(code, m.start())
            seen.add(line)
            yield Hit(path, line, _mask_literals(ctx.snippet(path, line)), _KEY_MSG, _hit_scope(ctx, path, m.start()))
        for m in SWIFT_KEY_VAR.finditer(code):
            line = ctx.line_of(code, m.start())
            if line not in seen and _string_constant(code, m.group(1)):
                seen.add(line)
                yield Hit(path, line, _mask_literals(ctx.snippet(path, line)), _KEY_MSG,
                          _hit_scope(ctx, path, m.start()))
    for path in ctx.files(*DART):
        raw = ctx.text(path) or ""
        if "Key" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen = set()
        for m in DART_KEY.finditer(code):
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield Hit(path, line, _mask_literals(ctx.snippet(path, line)), _KEY_MSG,
                          _hit_scope(ctx, path, m.start()))


# ============================================================================ shared helpers (XPL-012+)

NATIVE = (".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hpp")


def _args_of(blank: str, open_paren: int) -> List[Tuple[int, int]]:
    """(start, end) of each top-level argument of the call whose `(` is at `open_paren`."""
    close = guards.match(blank, open_paren, "(", ")")
    out: List[Tuple[int, int]] = []
    depth = 0
    start = open_paren + 1
    for i in range(open_paren + 1, min(close, open_paren + 4000)):
        c = blank[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append((start, i))
            start = i + 1
    if blank[start:close].strip():
        out.append((start, close))
    return out


def _local_body(code: str, blank: str, idx: int, path: str) -> str:
    """The enclosing function's body, or for an expression-bodied function, the text between the
    declarations before and after `idx`."""
    start, end, _head = _enclosing_function(blank, idx, path)
    if end - start < len(blank):
        return code[start:end]
    decl = re.compile(r"(?m)^[ \t]*(?:(?:private|public|internal|protected|override|static|final|suspend)\s+)*"
                      r"(?:fun|func|val|var|void|let)\b")
    before = [m.start() for m in decl.finditer(blank, max(0, idx - 2000), idx)]
    after = decl.search(blank, idx)
    return code[before[-1] if before else max(0, idx - 800):after.start() if after else min(len(code), idx + 300)]


def _int_literal(text: str) -> Optional[int]:
    t = text.strip().replace("_", "")
    if re.fullmatch(r"\d+[Ll]?", t):
        return int(t.rstrip("Ll"))
    return None


def _int_value(code: str, expr: str) -> Optional[int]:
    """An integer literal, or a constant assigned one in the same file."""
    v = _int_literal(expr)
    if v is not None:
        return v
    name = expr.strip().rsplit(".", 1)[-1]
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    m = re.search(r"\b" + re.escape(name) + r"\s*(?::\s*(?:Int|Long|UInt32|Int32))?\s*=\s*([\d_]+)[Ll]?\b", code)
    return _int_literal(m.group(1)) if m else None


def _words_of(text: str) -> Set[str]:
    """Lower-case words of identifiers, plus the identifiers themselves joined (`cardNumber` gives
    card, number, and cardnumber)."""
    words = _identifier_words(text)
    words |= {i.lower() for i in re.findall(r"[A-Za-z_]\w*", text)}
    return words


def _hit_at(ctx: Context, path: str, code: str, idx: int, message: str, blank: Optional[str] = None,
            mask: bool = False) -> Hit:
    line = ctx.line_of(code, idx)
    snippet = ctx.snippet(path, line)
    return Hit(path, line, _mask_literals(snippet) if mask else snippet, message, _hit_scope(ctx, path, idx, blank))


def _files_with(ctx: Context, suffixes: Tuple[str, ...], needles: Sequence[str]) -> Iterable[Tuple[str, str, str]]:
    """(path, code, blank) for files whose raw text contains any needle."""
    for path in ctx.files(*suffixes):
        raw = ctx.text(path)
        if raw is None or (needles and not any(n in raw for n in needles)):
            continue
        yield path, ctx.code(path, keep_strings=True) or "", ctx.code(path, keep_strings=False) or ""


# Words that name a secret a user or server would not want exposed.
_SECRET_WORDS = {"password", "passwd", "passcode", "passphrase", "token", "secret", "otp", "totp", "pin", "pincode",
                 "iban", "cvv", "cvc", "mnemonic", "seedphrase", "recoveryphrase", "recoverycode", "recoverykey",
                 "privatekey", "apikey", "secretkey", "cardnumber", "accesstoken", "refreshtoken"}


def _secret_words(text: str) -> List[str]:
    return sorted(_words_of(text) & _SECRET_WORDS)


# ---------------------------------------------------------------------------- XPL-012

CLIP_JVM = re.compile(r"\bClipData\s*\.\s*newPlainText\s*\(|\bsetText\s*\(\s*AnnotatedString\s*\(|"
                      r"\bsetPrimaryClip\s*\(\s*ClipData\s*\.\s*newPlainText\s*\(")
CLIP_DART = re.compile(r"\bClipboard\s*\.\s*setData\s*\(\s*(?:const\s+)?ClipboardData\s*\(")
_CLIP_SENSITIVE_FLAG = re.compile(r"EXTRA_IS_SENSITIVE|android\.content\.extra\.IS_SENSITIVE")


@detector("xpl_clipboard_secret")
def clipboard_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, JVM + DART, ("newPlainText", "AnnotatedString", "ClipboardData")):
        is_dart = path.endswith(".dart")
        regex = CLIP_DART if is_dart else CLIP_JVM
        if not is_dart and _CLIP_SENSITIVE_FLAG.search(code):
            continue
        if is_dart and re.search(r"ClipboardData\s*\(\s*text:\s*(?:''|\"\")", code):
            continue                          # the app clears the clipboard after copying
        seen: Set[int] = set()
        for m in regex.finditer(blank):
            open_paren = m.end() - 1
            close = guards.match(blank, open_paren, "(", ")")
            args_blank = blank[open_paren:close]
            args_code = code[open_paren:close]
            literals = " ".join(re.findall(r"[\"']([^\"'\n]{1,60})[\"']", args_code))
            found = _secret_words(args_blank) or _secret_words(literals)
            line = ctx.line_of(code, m.start())
            if not found or line in seen:
                continue
            seen.add(line)
            how = ("Flutter's Clipboard can't mark it sensitive, so clear it after a short timeout"
                   if is_dart else "the clip isn't marked with `ClipDescription.EXTRA_IS_SENSITIVE`")
            yield _hit_at(ctx, path, code, m.start(), f"A `{found[0]}` is copied to the clipboard and {how}.", blank)


# ---------------------------------------------------------------------------- XPL-013

BROKEN_CIPHER: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\b(?:Cipher|KeyGenerator|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*\""
                r"(DESede|DES|TripleDES|3DES|RC4|ARCFOUR|ARC4|RC2|Blowfish|PBEWith\w*(?:DES|RC2|RC4)\w*)(?=[/\"])"),
     "the JCA name"),
    (re.compile(r"\bKeyProperties\s*\.\s*KEY_ALGORITHM_3DES\b"), "a Keystore 3DES key"),
    (re.compile(r"\bkCCAlgorithm(DES|3DES|RC4|RC2|Blowfish|CAST)\b"), "CommonCrypto"),
    (re.compile(r"\b(Blowfish)\s*\(\s*key:"), "CryptoSwift"),
    (re.compile(r"\b(DESede|DES|RC4|RC2|Blowfish)Engine\s*\("), "PointyCastle"),
    (re.compile(r"\bEVP_(des_\w+|des_ede\w*|rc4\w*|bf_\w+|rc2_\w+)\s*\("), "OpenSSL"),
]


@detector("xpl_broken_cipher")
def broken_cipher(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE + NATIVE, ("DES", "RC4", "RC2", "ARC", "Blowfish", "3DES",
                                                             "des_", "rc4", "bf_", "rc2_", "CAST")):
        seen: Set[int] = set()
        for regex, where in BROKEN_CIPHER:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                algo = m.group(1) if regex.groups else "3DES"
                yield _hit_at(ctx, path, code, m.start(), f"{algo} ({where}) is a broken or retired cipher.", blank)


# ---------------------------------------------------------------------------- XPL-014

_RSA_IN = re.compile(r"\"(?:RSA|DSA|DH|DiffieHellman)\"|KEY_ALGORITHM_RSA\b|kSecAttrKeyTypeRSA\b")
_NOT_RSA_IN = re.compile(r"\"(?:EC|AES|HmacSHA\d+)\"|KEY_ALGORITHM_(?:EC|AES|HMAC_\w+)\b|kSecAttrKeyTypeEC\w*")
WEAK_CURVE = re.compile(r"\bECGenParameterSpec\s*\(\s*\"(secp112r[12]|secp128r[12]|secp160[rk][12]?|prime192v\d|"
                        r"secp192[rk]1|sect1[1-6]\d[rk]\d)\"")
KEY_SIZE_CALLS = re.compile(r"\b(?:initialize|setKeySize|RSAKeyGenParameterSpec)\s*\(\s*([\w.]+)")
KEYGEN_INIT = re.compile(r"\bKeyGenerator\s*\.\s*getInstance\s*\([^)]*\)\s*(?:\.\s*apply\s*\{\s*|\.\s*)?init\s*\(\s*(\d+)")
APPLE_KEY_SIZE = re.compile(r"\bkSecAttrKeySizeInBits\b[^\n,;\]]{0,40}?(\d{2,5})\b")
DART_RSA_SIZE = re.compile(r"\bRSAKeyGeneratorParameters\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(\d+)")


@detector("xpl_small_key")
def small_key(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, JVM, ("initialize", "setKeySize", "RSAKeyGenParameterSpec",
                                                   "ECGenParameterSpec", "KeyGenerator")):
        seen: Set[int] = set()
        for m in WEAK_CURVE.finditer(code):
            seen.add(ctx.line_of(code, m.start()))
            yield _hit_at(ctx, path, code, m.start(), f"`{m.group(1)}` is a curve below 224 bits.", blank)
        for m in KEY_SIZE_CALLS.finditer(code):
            n = _int_value(code, m.group(1))
            line = ctx.line_of(code, m.start())
            if n is None or n >= 2048 or line in seen:
                continue
            body = _local_body(code, blank, m.start(), path)
            if not m.group(0).startswith("RSAKeyGen") and (not _RSA_IN.search(body) or _NOT_RSA_IN.search(body)):
                continue
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), f"An RSA, DSA, or DH key of {n} bits; use at least 2048.", blank)
        for m in KEYGEN_INIT.finditer(code):
            n = int(m.group(1))
            line = ctx.line_of(code, m.start())
            if n < 128 and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"A symmetric key of {n} bits; use at least 128.", blank)
    for path, code, blank in _files_with(ctx, APPLE, ("kSecAttrKeySizeInBits", "kCCKeySizeDES", "kCCKeySize3DES")):
        seen = set()
        for m in APPLE_KEY_SIZE.finditer(code):
            n = int(m.group(1))
            window = code[max(0, m.start() - 400):m.end() + 400]
            line = ctx.line_of(code, m.start())
            if n < 2048 and "kSecAttrKeyTypeRSA" in window and "kSecAttrKeyTypeEC" not in window and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"An RSA key of {n} bits; use at least 2048.", blank)
        for m in re.finditer(r"\bkCCKeySize(?:DES|3DES)\b", code):
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), "A DES or 3DES key size (56 or 112 effective bits).", blank)
    for path, code, blank in _files_with(ctx, DART, ("RSAKeyGeneratorParameters",)):
        for m in DART_RSA_SIZE.finditer(code):
            n = int(m.group(1))
            if n < 2048:
                yield _hit_at(ctx, path, code, m.start(), f"An RSA key of {n} bits; use at least 2048.", blank)


# ---------------------------------------------------------------------------- XPL-015 / XPL-016

# OWASP Password Storage Cheat Sheet minimums for PBKDF2, by PRF.
_PBKDF2_MIN = {"sha1": 1_300_000, "sha256": 600_000, "sha512": 210_000}
_PRF_IN = re.compile(r"(?i)(?:hmac[_\s]?|PRFHmacAlg|\.sha2\(\.|Hmac\.)(sha-?1|sha-?256|sha-?512)\b|"
                     r"PBKDF2WithHmac(SHA1|SHA256|SHA512)|\b(SHA1|SHA256|SHA512)Digest\b|\.(sha1|sha256|sha512)\b")
PBE_SPEC = re.compile(r"\bPBEKeySpec\s*\(")
CC_PBKDF = re.compile(r"\bCCKeyDerivationPBKDF\s*\(")
SWIFT_PBKDF2 = re.compile(r"\bPKCS5\s*\.\s*PBKDF2\s*\(")
DART_PBKDF2 = re.compile(r"\bPbkdf2\s*\(|\bPbkdf2Parameters\s*\(")


def _prf(text: str) -> str:
    m = _PRF_IN.search(text)
    if not m:
        return "sha256"
    return next(g for g in m.groups() if g).lower().replace("-", "")


def _named_arg(blank: str, code: str, args: List[Tuple[int, int]], name: str) -> Optional[Tuple[int, int]]:
    for s, e in args:
        if re.match(r"\s*" + name + r"\s*:", blank[s:e]):
            colon = blank.index(":", s)
            return colon + 1, e
    return None


def _kdf_calls(ctx: Context) -> Iterable[Tuple[str, str, str, int, Optional[Tuple[int, int]],
                                              Optional[Tuple[int, int]], str]]:
    """(path, code, blank, call start, iterations span, salt span, prf) for every password KDF call."""
    for path, code, blank in _files_with(ctx, CODE, ("PBEKeySpec", "CCKeyDerivationPBKDF", "PBKDF2", "Pbkdf2")):
        if re.search(r"(?i)/(?:server|backend)/", "/" + path):
            continue
        prf_file = _prf(code)
        for regex in (PBE_SPEC, CC_PBKDF, SWIFT_PBKDF2, DART_PBKDF2):
            for m in regex.finditer(blank):
                args = _args_of(blank, m.end() - 1)
                call_text = code[m.start():guards.match(blank, m.end() - 1, "(", ")")]
                prf = _prf(call_text) if _PRF_IN.search(call_text) else prf_file
                it = salt = None
                if regex is PBE_SPEC and len(args) >= 3:
                    salt, it = args[1], args[2]
                elif regex is CC_PBKDF and len(args) >= 7:
                    salt, it = args[3], args[6]
                elif regex is SWIFT_PBKDF2 or not m.group(0).startswith("Pbkdf2Parameters"):
                    it = _named_arg(blank, code, args, "iterations")
                    salt = _named_arg(blank, code, args, "salt")
                    if salt is None:          # package:cryptography: deriveKey(secretKey:, nonce:)
                        tail = blank[m.end():m.end() + 600]
                        n = re.search(r"\bnonce\s*:", tail)
                        if n:
                            s0 = m.end() + n.end()
                            e0 = s0 + re.search(r"[,)]", blank[s0:] + ")").start()
                            salt = (s0, e0)
                elif len(args) >= 2:          # Pbkdf2Parameters(salt, iterations, length)
                    salt, it = args[0], args[1]
                yield path, code, blank, m.start(), it, salt, prf


# A derivation timed to calibrate the real iteration count derives no key.
_KDF_BENCHMARK = re.compile(r"(?i)bench|calibrat")
_TIMER = re.compile(r"\bcurrentTimeMillis\b|\bnanoTime\b|\belapsedRealtime\w*\b|\buptimeMillis\b|"
                    r"\bCFAbsoluteTimeGetCurrent\b|\bCACurrentMediaTime\b|\bDispatchTime\s*\.\s*now\b|"
                    r"\bDate\s*\(\s*\)\s*\.\s*timeIntervalSince|\bStopwatch\s*\(")
_LEGACY_KDF = re.compile(r"(?i)\b(?:old|legacy|fallback|backward)\b")
# The "password" fed to the KDF is random bytes the app generated, not something a person chose.
_RANDOM_PASSWORD = re.compile(r"(?i)\b\w*(?:password|passphrase)\w*\s*=\s*[\w.]*?(?:generateBytes|randomBytes|"
                              r"nextBytes|generateRandom\w*|secureRandom\w*)\s*\(")


def _enum_counts(code: str, blank: str, prop: str) -> List[Tuple[int, int, str]]:
    """(entry start, count, entry text) of each Kotlin enum entry that passes an integer for the
    constructor property `prop` (`algorithm.iterationCount` with `SHA1("PBKDF2WithHmacSHA1", 1024)`)."""
    out: List[Tuple[int, int, str]] = []
    for m in re.finditer(r"\benum\s+class\s+\w+\s*\(", blank):
        params = _args_of(blank, m.end() - 1)
        idx = next((i for i, (s, e) in enumerate(params)
                    if re.search(r"\bva[lr]\s+" + re.escape(prop) + r"\s*:", blank[s:e])), None)
        if idx is None:
            continue
        open_body = blank.find("{", guards.match(blank, m.end() - 1, "(", ")"))
        if open_body < 0:
            continue
        close_body = guards.match(blank, open_body, "{", "}")
        for e in re.finditer(r"(?m)^[ \t]*([A-Z]\w*)\s*\(", blank[open_body:close_body]):
            paren = open_body + e.end() - 1
            args = _args_of(blank, paren)
            if len(args) > idx:
                n = _int_literal(code[args[idx][0]:args[idx][1]])
                if n is not None:
                    out.append((open_body + e.start(1), n, code[open_body + e.start():guards.match(blank, paren, "(", ")")]))
    return out


def _random_password_input(ctx: Context, path: str, blank: str, idx: int) -> bool:
    """Is the function holding this KDF call fed a password the app generated at random? Callers are
    looked for in this file and its directory (one package)."""
    _s, _e, head = _enclosing_function(blank, idx, path)
    name = _function_name(head)
    if not name:
        return False
    folder = path.rsplit("/", 1)[0] if "/" in path else ""
    call = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    for other in ctx.files(*JVM):
        if (other.rsplit("/", 1)[0] if "/" in other else "") != folder:
            continue
        code = ctx.code(other, keep_strings=False) or ""
        if call.search(code) and _RANDOM_PASSWORD.search(code):
            return True
    return False


@detector("xpl_pbkdf2_iterations")
def pbkdf2_iterations(ctx: Context, rule: Rule) -> Iterable[Hit]:
    by_file: dict = {}
    for call in _kdf_calls(ctx):
        by_file.setdefault(call[0], []).append(call)
    for path, calls in by_file.items():
        code, blank = calls[0][1], calls[0][2]
        raw = ctx.text(path) or ""
        resolved = []                         # (call start, count, prf, iterations span)
        for _p, _c, _b, start, it, _salt, prf in calls:
            if it is None:
                continue
            expr = code[it[0]:it[1]]
            n = _int_value(code, expr)
            if n is not None:
                resolved.append((start, n, prf, it))
                continue
            prop = re.fullmatch(r"\s*\w+\s*[?!]?\s*\.\s*(\w+)\s*", expr)
            if prop and path.endswith(".kt"):
                # Report the enum's weakest entry once; the stronger ones still count as "strong".
                entries = [(s, n, _prf(t) if _PRF_IN.search(t) else prf, None)
                           for s, n, t in _enum_counts(code, blank, prop.group(1))]
                if entries:
                    weakest = min(entries, key=lambda e: e[1] / _PBKDF2_MIN.get(e[2], 600_000))
                    resolved.append(weakest)
                    resolved.extend((-1, n, p, None) for _s, n, p, _i in entries if (_s, n) != weakest[:2])
        strong = any(n >= _PBKDF2_MIN.get(prf, 600_000) for _s, n, prf, _it in resolved)
        seen: Set[int] = set()
        for start, n, prf, it in resolved:
            floor = _PBKDF2_MIN.get(prf, 600_000)
            if n >= floor or start < 0 or start in seen:
                continue
            seen.add(start)
            if n == 2048 and prf == "sha512" and re.search(r"(?i)mnemonic|bip-?39|seed", code):
                continue                      # BIP-39 fixes 2,048 rounds of PBKDF2-HMAC-SHA512
            if it is not None:
                call_end = guards.match(blank, blank.find("(", start), "(", ")")
                fn_name = _function_name(_enclosing_function(blank, start, path)[2])
                if _KDF_BENCHMARK.search(code[it[0]:it[1]]) or _KDF_BENCHMARK.search(fn_name) \
                        or _TIMER.search(blank[call_end:call_end + 400]):
                    continue                  # a timing benchmark that calibrates the real count
                if path.endswith(JVM) and _random_password_input(ctx, path, blank, start):
                    continue                  # a random, high-entropy "password" needs no stretching
            msg = f"PBKDF2-HMAC-{prf.upper()} with {n:,} iterations; OWASP's minimum is {floor:,}."
            severity = ""
            if strong or _LEGACY_KDF.search(raw[max(0, start - 300):start]):
                severity = "low"
                msg += (" A stronger derivation exists in this file, so this" if strong else " This") + \
                    " looks like a legacy-decrypt fallback; drop it once old data is migrated."
            elif n >= 100_000:
                severity = "medium"
            hit = _hit_at(ctx, path, code, start, msg, blank)
            hit.severity = severity
            yield hit


_DART_LITERAL_SALT = re.compile(r"^\s*(?:const\s+)?(?:utf8\.encode\s*\(\s*r?[\"']|" + _DART_LITERAL_BYTES
                                + r"|\[\s*\d|r?[\"']|SecretKey\s*\(\s*(?:utf8\.encode|const\s*\[|\[))")
_APPLE_LITERAL_SALT = re.compile(r"^\s*&?\s*(?:\"[^\"\n]*\"|Array\s*\(\s*\"|\[\s*(?:0x)?\d|Data\s*\(\s*(?:\"|\[)|"
                                 r"\(\s*\"[^\"\n]*\"\s*as\s+NSString\)|@\")")


def _salt_is_literal(path: str, code: str, blank: str, span: Tuple[int, int]) -> bool:
    expr = code[span[0]:span[1]]
    if path.endswith(JVM):
        if re.match(r"\s*" + _LITERAL_BYTES, expr):
            return not re.match(r"\s*(?:ByteArray\(|new\s+byte\s*\[\s*\d)", expr)
        name = re.match(r"\s*([A-Za-z_]\w*)\s*$", expr)
        return bool(name and _var_is_literal(code, name.group(1), span[0], path, blank))
    if path.endswith(".dart"):
        if _DART_LITERAL_SALT.match(expr):
            return True
        name = re.match(r"\s*([A-Za-z_]\w*)\s*$", expr)
        return bool(name and re.search(r"\b" + re.escape(name.group(1)) + r"\s*=\s*(?:const\s+)?(?:utf8\.encode\s*"
                                       r"\(\s*r?[\"']|" + _DART_LITERAL_BYTES + r"|r?[\"'])", code))
    if _APPLE_LITERAL_SALT.match(expr) or re.match(r"\s*\"[^\"\n]*\"\s*\.\s*(?:bytes|utf8|data)", expr):
        return True
    name = re.match(r"\s*&?\s*([A-Za-z_]\w*)\s*(?:\.bytes|\.utf8)?\s*$", expr)
    return bool(name and re.search(r"\b(?:let|var)\s+" + re.escape(name.group(1)) + r"\s*(?::\s*[\w\[\]]+)?\s*=\s*"
                                   r"(?:\"|Array\s*\(\s*\"|\[\s*(?:0x)?\d|Data\s*\(\s*\")", code))


@detector("xpl_fixed_salt")
def fixed_salt(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank, start, _it, salt, _prf in _kdf_calls(ctx):
        if salt is not None and _salt_is_literal(path, code, blank, salt):
            yield _hit_at(ctx, path, code, start, "The password-hashing salt is a fixed value in the code, so "
                                                  "every user's derived key can be attacked at once.", blank, mask=True)


# ---------------------------------------------------------------------------- XPL-017

GRPC_PLAIN: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\.\s*usePlaintext\s*\(\s*(?:true)?\s*\)"), "`usePlaintext()`"),
    (re.compile(r"\bClientConnection\s*\.\s*insecure\s*\(\s*group\s*:"), "`ClientConnection.insecure`"),
    (re.compile(r"\btransportSecurity\s*:\s*\.plaintext\b"), "`transportSecurity: .plaintext`"),
    (re.compile(r"\bChannelCredentials\s*\.\s*insecure\s*\("), "`ChannelCredentials.insecure()`"),
]
_LOCAL_TARGET = re.compile(r"[\"'](?:localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\[::1\])[\"':]")


@detector("xpl_grpc_plaintext")
def grpc_plaintext(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("usePlaintext", "insecure", "plaintext")):
        if path.endswith(JVM) and not re.search(r"ChannelBuilder|io\.grpc", code):
            continue
        for regex, what in GRPC_PLAIN:
            for m in regex.finditer(code):
                window = code[max(0, m.start() - 400):m.start()]
                if _LOCAL_TARGET.search(window[window.rfind(";") + 1:] if ";" in window else window):
                    continue
                yield _hit_at(ctx, path, code, m.start(), f"A gRPC channel with {what} sends calls unencrypted.", blank)


# ---------------------------------------------------------------------------- XPL-018

BIO_FALLBACK: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bsetAllowedAuthenticators\s*\([^;\n]*\bDEVICE_CREDENTIAL\b"),
     "The biometric prompt accepts the device PIN, pattern, or password instead of a biometric."),
    (re.compile(r"\bsetDeviceCredentialAllowed\s*\(\s*true\s*\)"),
     "The biometric prompt accepts the device PIN, pattern, or password instead of a biometric."),
    (re.compile(r"\bSecAccessControlCreateWithFlags\s*\([^;]{0,300}?(?:\.userPresence|\.devicePasscode|"
                r"kSecAccessControlUserPresence|kSecAccessControlDevicePasscode)\b"),
     "The Keychain item opens with the device passcode as well as a biometric."),
    (re.compile(r"(?:\.|\bLAPolicy)deviceOwnerAuthentication\b(?!WithBiometrics)|\bLAPolicyDeviceOwnerAuthentication\b"
                r"(?!WithBiometrics)"),
     "LocalAuthentication falls back to the device passcode; for a sensitive action, require biometrics."),
]


@detector("xpl_biometric_fallback")
def biometric_fallback(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, JVM + APPLE, ("DEVICE_CREDENTIAL", "setDeviceCredentialAllowed",
                                                           "SecAccessControlCreateWithFlags", "deviceOwnerAuthentication",
                                                           "DeviceOwnerAuthentication")):
        seen: Set[int] = set()
        for regex, message in BIO_FALLBACK:
            for m in regex.finditer(blank):
                line = ctx.line_of(code, m.start())
                if re.search(r"canEvaluatePolicy\s*\(\s*(?:LAPolicy)?\s*$", blank[max(0, m.start() - 60):m.start()]):
                    continue                  # an availability check, not the authentication itself
                if line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), message, blank)
    for path, code, blank in _files_with(ctx, DART, ("local_auth",)):
        for m in re.finditer(r"\.\s*authenticate\s*\(", blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            args = code[m.end():close]
            if "localizedReason" not in args or re.search(r"\bbiometricOnly\s*:\s*true\b", args):
                continue
            yield _hit_at(ctx, path, code, m.start(), "local_auth's `authenticate` without `biometricOnly: true` "
                                                      "accepts the device PIN or passcode.", blank)


# ---------------------------------------------------------------------------- XPL-019

PEM_PRIVATE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
# CI-006 already reports these extensions anywhere in the repository.
_CI006_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx", ".p8")
_SHIPPED_DIR = re.compile(r"/(?:assets|res/raw|resources|Resources|raw)/")
KEYSTORE_LOAD = re.compile(r"\.\s*load\s*\(\s*[^;\n]{0,160}?(?:assets|open|resources|openRawResource|"
                           r"getResourceAsStream)[^;\n]{0,160}?,\s*\"([^\"\n]+)\"\s*\.\s*toCharArray\s*\(")
P12_IMPORT = re.compile(r"\bkSecImportExportPassphrase\b[^\n:]{0,20}:\s*@?\"([^\"\n]+)\"")
DART_CLIENT_CERT = re.compile(r"\.\s*(?:useCertificateChain(?:Bytes)?|usePrivateKey(?:Bytes)?|setClientAuthorities"
                              r"(?:Bytes)?)\s*\([^;]*?\bpassword\s*:\s*r?[\"']([^\"'\n]+)[\"']")


def _shipped_key_files(ctx: Context) -> List[str]:
    """Names (never contents) of .pem and .key files in shipped resource folders; safety.walk skips them."""
    cached = getattr(ctx, "_xpl_key_files", None)
    if cached is not None:
        return cached
    import os

    from masaudit import safety
    root = os.path.abspath(ctx.root)
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in safety.SKIP_DIRS
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in filenames:
            if name.lower().endswith((".pem", ".key")):
                rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
                if _SHIPPED_DIR.search("/" + rel) and not os.path.islink(os.path.join(dirpath, name)):
                    out.append(rel)
        if len(out) > 200:
            break
    ctx._xpl_key_files = out  # type: ignore[attr-defined]
    return out


@detector("xpl_bundled_private_key")
def bundled_private_key(ctx: Context, rule: Rule) -> Iterable[Hit]:
    from masaudit import safety
    # (a) a PEM private key in a shipped text file (XPL-001 reports one inside source code).
    for path in ctx.files():
        if path.endswith(CODE + (".gradle", ".kts", ".toml", ".properties", ".pro")) or "/.github/" in "/" + path:
            continue
        if not (_SHIPPED_DIR.search("/" + path) or re.search(r"/src/\w+/(?:res|assets)/", "/" + path)
                or path.endswith((".plist", ".strings"))):
            continue                          # only files that end up in the app package
        raw = ctx.text(path) or ""
        if "PRIVATE KEY-----" not in raw:
            continue
        m = PEM_PRIVATE.search(raw)
        if m and PEM_WITH_BODY.search(raw):
            line = ctx.line_of(raw, m.start())
            yield Hit(path, line, "-----BEGIN PRIVATE KEY-----", "A private key ships inside the app package.")
    for path in _shipped_key_files(ctx):
        text = safety.read_text(ctx.root, path) or ""
        if PEM_PRIVATE.search(text):
            yield Hit(path, 0, path.rsplit("/", 1)[-1], "A private key file ships inside the app package.")
    # (c) a client certificate keystore opened with a password written in the code.
    for path, code, blank in _files_with(ctx, JVM, ("toCharArray",)):
        if "KeyManagerFactory" not in code and "PKCS12" not in code:
            continue
        for m in KEYSTORE_LOAD.finditer(code):
            yield _hit_at(ctx, path, code, m.start(), "A bundled client-certificate keystore is opened with a "
                                                      "password written in the code.", blank, mask=True)
    for path, code, blank in _files_with(ctx, APPLE, ("kSecImportExportPassphrase",)):
        for m in P12_IMPORT.finditer(code):
            yield _hit_at(ctx, path, code, m.start(), "A bundled PKCS #12 identity is imported with a passphrase "
                                                      "written in the code.", blank, mask=True)
    for path, code, blank in _files_with(ctx, DART, ("password",)):
        for m in DART_CLIENT_CERT.finditer(code):
            yield _hit_at(ctx, path, code, m.start(), "A client certificate is loaded with a password written in "
                                                      "the code.", blank, mask=True)


# ---------------------------------------------------------------------------- XPL-020

_ZIP_MARKERS = re.compile(r"\bZipInputStream\b|\bZipFile\b|\bZipEntry\b|\bnextEntry\b|\bgetNextEntry\b")
_ZIP_GUARD = re.compile(r"canonicalPath|getCanonicalPath|canonicalFile|getCanonicalFile|toRealPath|normalize\s*\(")
_ZIP_ENTRY_VAR = re.compile(r"\b(\w+)\s*(?::\s*ZipEntry\??)?\s*=\s*[\w.]{0,80}(?:nextEntry|getNextEntry\s*\(\s*\)|"
                            r"entries\s*\(\s*\)\s*\.\s*nextElement\s*\(\s*\))|\bZipEntry\s+(\w+)\s*[=;:]|"
                            r"\bfor\s*\(\s*(?:val\s+|final\s+ZipEntry\s+|ZipEntry\s+)?(\w+)\s*(?::\s*ZipEntry)?\s*"
                            r"(?:in|:)\s*[\w.]{0,80}entries")


@detector("xpl_zip_slip")
def zip_slip(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = "A zip entry's name becomes a file path with no check that it stays inside the target folder."
    for path, code, blank in _files_with(ctx, JVM, ("ZipEntry", "ZipInputStream", "ZipFile", "nextEntry")):
        if not _ZIP_MARKERS.search(blank):
            continue
        entries = {g for m in _ZIP_ENTRY_VAR.finditer(blank) for g in m.groups() if g}
        if not entries:
            continue
        reported: Set[int] = set()
        for entry in entries:
            name_vars = {entry + r"\s*\.\s*(?:name|getName\s*\(\s*\))"}
            for m in re.finditer(r"\b(\w+)\s*(?::\s*String\??)?\s*=\s*" + re.escape(entry)
                                 + r"\s*\.\s*(?:name|getName\s*\(\s*\))", blank):
                name_vars.add(re.escape(m.group(1)) + r"\b(?!\s*\.)")
            for nv in name_vars:
                sink = re.compile(r"\b(?:File|Paths\s*\.\s*get|Path\s*\.\s*of)\s*\([^;\n]*?\b" + nv
                                  + r"|\bresolve\s*\(\s*" + nv)
                for m in sink.finditer(blank):
                    start, end, _head = _enclosing_function(blank, m.start(), path)
                    body = blank[start:end]
                    if (_ZIP_GUARD.search(body) and "startsWith" in body) or re.search(r"contains\s*\(\s*\"\.\.\"",
                                                                                         code[start:end]):
                        continue
                    if start in reported:
                        continue
                    reported.add(start)
                    yield _hit_at(ctx, path, code, m.start(), msg, blank)
    for path, code, blank in _files_with(ctx, DART, ("package:archive",)):
        for m in re.finditer(r"\bjoin\s*\([^;\n]*?\b(\w+)\s*\.\s*name\b|['\"][^'\"\n]*\$\{?\w+\}?/\$\{(\w+)\.name\}",
                             code):
            start, end, _head = _enclosing_function(blank, m.start(), path)
            if re.search(r"isWithin|canonicalize|normalize", code[start:end]):
                continue
            yield _hit_at(ctx, path, code, m.start(), msg, blank)
    for path, code, blank in _files_with(ctx, (".swift",), ("ZIPFoundation",)):
        for m in re.finditer(r"\bappendingPathComponent\s*\(\s*(\w+)\s*\.\s*path\s*\)", blank):
            start, end, _head = _enclosing_function(blank, m.start(), path)
            body = blank[start:end]
            if re.search(r"standardized|resolvingSymlinksInPath", body) and "hasPrefix" in body:
                continue
            if "extract" not in body:
                continue
            yield _hit_at(ctx, path, code, m.start(), msg, blank)


# ---------------------------------------------------------------------------- absence rules: shared

# Commercial RASP and attestation SDKs bundle root, debugger, emulator, and hook detection.
_RASP = (r"com\.aheaditec\.talsec|\bfreerasp\b|\bTalsec\b|\bpromon\b|\bShieldSDK\b|\bdexguard\b|\bixguard\b|"
         r"\bappdome\b|\bio\.approov\b|\bApproov\b|\bzimperium\b|\bzDefend\b|\bverimatrix\b|\bonespan\b|"
         r"\bbuild38\b|\bGuardsquare\b")
_EVIDENCE_SUFFIXES = CODE + NATIVE + (".kts", ".gradle", ".toml", ".pbxproj", ".pro", ".resolved")
_EVIDENCE_NAMES = ("pubspec.yaml", "Podfile", "Package.swift", "Cartfile")


def _evidence_files(ctx: Context) -> List[Tuple[str, str]]:
    """(path, text with comments blanked) of every non-test file that can carry evidence; cached."""
    cached = getattr(ctx, "_xpl_evidence", None)
    if cached is not None:
        return cached
    out: List[Tuple[str, str]] = []
    for path in ctx.files():
        base = path.rsplit("/", 1)[-1]
        if not (path.endswith(_EVIDENCE_SUFFIXES) or base in _EVIDENCE_NAMES):
            continue
        if scope_of(path) == "test":
            continue
        text = ctx.code(path, keep_strings=True) if path.endswith(CODE + (".kts", ".gradle")) else ctx.text(path)
        if text:
            if base == "pubspec.yaml" or path.endswith(".toml"):
                text = re.sub(r"#[^\n]*", "", text)
            out.append((path, text))
    ctx._xpl_evidence = out  # type: ignore[attr-defined]
    return out


_RASP_NEEDLES = ("talsec", "freerasp", "promon", "shieldsdk", "dexguard", "ixguard", "appdome", "approov",
                 "zimperium", "zdefend", "verimatrix", "onespan", "build38", "guardsquare")
# Lower-case substrings at least one of which each evidence pattern needs. Set below, next to each pattern.
_NEEDLES: dict = {}


def _found(ctx: Context, pattern: Pattern[str], platform: str = "",
           accept: Optional[Callable[[str, str, "re.Match[str]"], bool]] = None) -> Optional[str]:
    """First file holding evidence. `platform` limits it to android, ios, or shared (Dart, deps) files.
    `accept(path, text, match)` can reject a match that isn't real evidence."""
    cache = getattr(ctx, "_xpl_evidence_joined", None)
    if cache is None:
        cache = ctx._xpl_evidence_joined = {}  # type: ignore[attr-defined]
    if platform not in cache:
        files = []
        for path, text in _evidence_files(ctx):
            if platform == "android" and not path.endswith((".kt", ".java", ".kts", ".gradle", ".toml", ".pro")
                                                           + NATIVE):
                continue
            if platform == "ios" and not path.endswith(APPLE + NATIVE + (".pbxproj", ".resolved", "Podfile",
                                                                          "Package.swift", "Cartfile")):
                continue
            files.append((path, text))
        # One search over the joined text is far faster than one per file; files are separated by a
        # line that no evidence pattern can span.
        cache[platform] = (files, "\n\x00\n".join(text for _p, text in files).lower())
    files, joined = cache[platform]
    needles = _NEEDLES.get(pattern.pattern)
    if needles is not None and not any(n in joined for n in needles):
        return None                           # a cheap substring test rules most projects out
    for path, text in files:
        if needles is not None and not any(n in text.lower() for n in needles):
            continue
        if accept is None:
            if pattern.search(text):
                return path
        elif any(accept(path, text, m) for m in pattern.finditer(text)):
            return path
    return None


_NOT_APP_PLIST_DIR = re.compile(r"(?i)(?:^|/)[^/]*(?:watch|test|mock|harness)[^/]*/")


def _app_anchors(ctx: Context) -> List[Tuple[str, str, int]]:
    """(platform, path, line) for each app the project builds: an Android manifest with a launcher
    activity, an Xcode application target. Library-only projects have none."""
    out: List[Tuple[str, str, int]] = []
    for path in ctx.files(name="AndroidManifest.xml"):
        if scope_of(path) != "main":
            continue
        text = ctx.text(path) or ""
        if re.search(r"(?i)(?:^|/)[^/]*(?:wear|watch)[^/]*/", path) or "android.hardware.type.watch" in text:
            continue                          # a Wear OS app, not the phone app
        if "android.intent.action.MAIN" in text and "<application" in text:
            out.append(("android", path, ctx.line_of(text, text.index("<application"))))
            break
    for path in ctx.files(".pbxproj"):
        if scope_of(path) != "main":
            continue
        text = ctx.text(path) or ""
        for m in re.finditer(r"com\.apple\.product-type\.application\"", text):
            # A watchOS app is also an "application"; its target block names it (WatchApp, SDKROOT watchos).
            block = text[max(0, text.rfind("isa = PBXNativeTarget", 0, m.start())):m.start()]
            if re.search(r"(?im)^\s*(?:name|productName)\s*=\s*[^;\n]*watch|SDKROOT\s*=\s*watchos", block):
                continue
            out.append(("ios", path, ctx.line_of(text, m.start())))
            break
        if any(p == "ios" for p, _, _ in out):
            break
    if not any(p == "ios" for p, _, _ in out):
        # No readable Xcode project (XcodeGen, or a project file over the size limit): an app's Info.plist,
        # not a watchOS app's or an extension's. A top folder named like the repository wins a tie in depth.
        repo = {w for w in re.split(r"[^a-z0-9]+", ctx.root.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower())
                if len(w) > 2}
        plists = [p for p in ctx.files("Info.plist") if scope_of(p) == "main" and not _NOT_APP_PLIST_DIR.search(p)]
        for path in sorted(plists, key=lambda p: (p.count("/"), p.split("/", 1)[0].lower() not in repo, p)):
            text = ctx.text(path) or ""
            if re.search(r"CFBundlePackageType</key>\s*<string>(?:APPL|\$\(PRODUCT_BUNDLE_PACKAGE_TYPE\))", text) \
                    and "NSExtension" not in text and "<key>CFBundleExecutable</key>" in text \
                    and not re.search(r"<key>(?:WKApplication|WKWatchKitApp|WKCompanionAppBundleIdentifier)</key>",
                                      text):
                out.append(("ios", path, ctx.line_of(text, text.index("CFBundlePackageType"))))
                break
    return out


def _absence(ctx: Context, rule: Rule, android: Pattern[str], ios: Pattern[str], shared: Pattern[str],
             what: str, accept: Optional[Callable[[str, str, "re.Match[str]"], bool]] = None) -> Iterable[Hit]:
    if _found(ctx, shared):
        return
    for platform, path, line in _app_anchors(ctx):
        if _found(ctx, android if platform == "android" else ios, platform, accept):
            continue
        name = "Android" if platform == "android" else "iOS"
        yield Hit(path, line, ctx.snippet(path, line), f"No {what} found in the {name} app.")


# ---------------------------------------------------------------------------- XPL-021

ROOT_ANDROID = re.compile(r"/system/xbin/su|/sbin/su\b|/system/bin/su\b|com\.topjohnwu\.magisk|me\.weishu\.kernelsu|"
                          r"me\.bmax\.apatch|\btest-keys\b|\bRootBeer\b|com\.scottyab:rootbeer|isDeviceRooted|"
                          r"\bisRooted\b|\bRootDetect\w*|IntegrityManagerFactory|StandardIntegrityManager|"
                          r"play[.:-]integrity|PlayIntegrityAppCheckProviderFactory")
ROOT_IOS = re.compile(r"/Applications/Cydia\.app|/var/jb\b|/Applications/Sileo\.app|cydia://|sileo://|"
                      r"IOSSecuritySuite|amIJailbroken|DTTJailbreakDetection|\bisJailbroken\b|\bJailbreak\w*Detect\w*|"
                      r"DCAppAttestService|AppAttestProvider")
ROOT_SHARED = re.compile(_RASP + r"|flutter_jailbreak_detection|\bsafe_device\b|jailbreak_root_detection|"
                         r"\bfirebase_app_check\b[^\n]*|AndroidProvider\.playIntegrity|AppleProvider\.appAttest")


@detector("xpl_no_root_detection")
def no_root_detection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, ROOT_ANDROID, ROOT_IOS, ROOT_SHARED, "root or jailbreak detection (or attestation)")


# ---------------------------------------------------------------------------- XPL-022

DEBUGGER_ANDROID = re.compile(r"\bisDebuggerConnected\b|\bwaitingForDebugger\b|\bTracerPid\b|/proc/self/status|"
                              r"\bptrace\s*\(")
DEBUGGER_IOS = re.compile(r"\bPT_DENY_ATTACH\b|\bptrace\s*\(|\bP_TRACED\b|\bkinfo_proc\b|"
                          r"\btask_get_exception_ports\b|\bgetppid\s*\(\s*\)\s*!=\s*1|amIDebugged|denyDebugger")
DEBUGGER_SHARED = re.compile(_RASP + r"|\bsafe_device\b|\bdebugger_detection\b")


# Debugger checks that aren't anti-debugging: an ANR watchdog skipping reports while a debugger is
# attached, or a debug-build helper that traps into the debugger.
_WATCHDOG_FILE = re.compile(r"(?i)/anrs?[-/_]|anr\w*(?:detector|supervisor|watchdog|monitor)|watchdog")
_NEGATED_DEBUG = re.compile(r"!\s*(?:android\s*\.\s*os\s*\.\s*)?Debug\s*\.\s*$")


def _real_debugger_check(path: str, text: str, m: "re.Match[str]") -> bool:
    if _WATCHDOG_FILE.search("/" + path):
        return False
    if path.endswith((".kt", ".java")) and _NEGATED_DEBUG.search(text[max(0, m.start() - 40):m.start()]):
        return False
    if path.endswith(APPLE + NATIVE) and guards.preprocessor_debug_guarded(text, m.start()):
        return False
    return True


@detector("xpl_no_debugger_detection")
def no_debugger_detection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, DEBUGGER_ANDROID, DEBUGGER_IOS, DEBUGGER_SHARED, "debugger detection",
                        _real_debugger_check)


# ---------------------------------------------------------------------------- XPL-038

EMULATOR_ANDROID = re.compile(r"Build\.FINGERPRINT[^\n]{0,80}generic|\bgoldfish\b|\branchu\b|\bgoogle_sdk\b|"
                              r"ro\.kernel\.qemu|\bisEmulator\b|\bisProbablyAnEmulator\b|EmulatorDetector")
EMULATOR_IOS = re.compile(r"\bSIMULATOR_DEVICE_NAME\b|environment\s*\[\s*\"SIMULATOR_|\bisSimulator\b\s*\(|"
                          r"amIRunInEmulator|amIRunningInSimulator")
EMULATOR_SHARED = re.compile(_RASP + r"|\bsafe_device\b|\bisRealDevice\b|\bdevice_info_plus\b[^\n]*isPhysicalDevice|"
                             r"\bisPhysicalDevice\b")


@detector("xpl_no_emulator_detection")
def no_emulator_detection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, EMULATOR_ANDROID, EMULATOR_IOS, EMULATOR_SHARED, "emulator or simulator detection")


# ---------------------------------------------------------------------------- XPL-039

HOOK_ANDROID = re.compile(r"(?i)frida-server|frida-agent|frida-gadget|re\.frida|gum-js-loop|\blinjector\b|\b27042\b|"
                          r"libfrida|/proc/self/maps|de\.robv\.android\.xposed|XposedBridge|\blsposed\b|"
                          r"com\.saurik\.substrate|\bzygisk\b")
HOOK_IOS = re.compile(r"(?i)frida-server|frida-agent|FridaGadget|re\.frida|\b27042\b|"
                      r"_dyld_get_image_name[\s\S]{0,400}?(?:Frida|Substrate|libhooker|SSLKillSwitch|cycript)|"
                      r"amIReverseEngineered|amIRuntimeHooked|MobileSubstrate")
HOOK_SHARED = re.compile(_RASP)


@detector("xpl_no_hook_detection")
def no_hook_detection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, HOOK_ANDROID, HOOK_IOS, HOOK_SHARED, "hooking or instrumentation detection")


# ---------------------------------------------------------------------------- XPL-040

UPDATE_ANDROID = re.compile(r"AppUpdateManagerFactory|AppUpdateType\.IMMEDIATE|startUpdateFlow\w*|"
                            r"com\.google\.android\.play:app-update|play[.-]app[.-]update|RemoteDeprecation|"
                            r"ExpiredBuild\w*|isClientDeprecated|minAppVersion|MIN_APP_VERSION")
UPDATE_IOS = re.compile(r"itunes\.apple\.com/lookup|SKStoreProductViewController|\bSiren\b|\bAppExpiry\b|"
                        r"isAppExpired|minAppVersion|minimumAppVersion")
# Dart packages (dependency lines in pubspec.yaml) and app-version keys compared at runtime.
UPDATE_SHARED = re.compile(r"(?mi)^[ \t]+(?:upgrader|in_app_update|new_version_plus|new_version|force_update_helper|"
                           r"version_check|update_available)[ \t]*:|"
                           r"\b(?:min|minimum)_?(?:supported_?|required_?)?app_?version\b|"
                           r"\bforce_?update_?(?:required|version|app)\b|\brequired_?app_?version\b|"
                           r"\bapp_?version_?(?:expired|unsupported|deprecated)\b")


@detector("xpl_no_forced_update")
def no_forced_update(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, UPDATE_ANDROID, UPDATE_IOS, UPDATE_SHARED, "way to force an update")


# ---------------------------------------------------------------------------- XPL-028

LOCK_ANDROID = re.compile(r"\bisDeviceSecure\b|\bisKeyguardSecure\b|BiometricManager[\w.]*\s*\.\s*canAuthenticate\b|"
                          r"\bcanAuthenticate\s*\(|setUserAuthenticationRequired\s*\(\s*true|"
                          r"setUnlockedDeviceRequired\s*\(\s*true")
LOCK_IOS = re.compile(r"\bcanEvaluatePolicy\b|kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly|"
                      r"\.whenPasscodeSetThisDeviceOnly\b|SecAccessControlCreateWithFlags")
LOCK_SHARED = re.compile(r"\bisDeviceSupported\b|\bcanCheckBiometrics\b|\bgetAvailableBiometrics\b|"
                         r"passcode_set_this_device|\bscreen_lock_check\b")

_NEEDLES.update({
    ROOT_ANDROID.pattern: ("/su", "magisk", "kernelsu", "apatch", "test-keys", "rootbeer", "rooted", "rootdetect",
                           "integritymanager", "integrity"),
    ROOT_IOS.pattern: ("cydia", "/var/jb", "sileo", "iossecuritysuite", "jailbr", "appattest"),
    ROOT_SHARED.pattern: _RASP_NEEDLES + ("jailbreak", "safe_device", "firebase_app_check", "playintegrity",
                                          "appattest"),
    DEBUGGER_ANDROID.pattern: ("debugger", "tracerpid", "/proc/self/status", "ptrace"),
    DEBUGGER_IOS.pattern: ("pt_deny_attach", "ptrace", "p_traced", "kinfo_proc", "exception_ports", "getppid",
                           "amidebugged", "denydebugger"),
    DEBUGGER_SHARED.pattern: _RASP_NEEDLES + ("safe_device", "debugger_detection"),
    EMULATOR_ANDROID.pattern: ("fingerprint", "goldfish", "ranchu", "google_sdk", "qemu", "emulator"),
    EMULATOR_IOS.pattern: ("simulator", "emulator"),
    EMULATOR_SHARED.pattern: _RASP_NEEDLES + ("safe_device", "isrealdevice", "isphysicaldevice"),
    HOOK_ANDROID.pattern: ("frida", "gum-js-loop", "linjector", "27042", "/proc/self/maps", "xposed", "lsposed",
                           "substrate", "zygisk"),
    HOOK_IOS.pattern: ("frida", "27042", "_dyld_get_image_name", "amireverseengineered", "amiruntimehooked",
                       "substrate"),
    HOOK_SHARED.pattern: _RASP_NEEDLES,
    UPDATE_ANDROID.pattern: ("appupdate", "startupdateflow", "app-update", "app.update", "deprecat", "expiredbuild",
                             "minappversion", "min_app_version"),
    UPDATE_IOS.pattern: ("itunes.apple.com/lookup", "skstoreproductviewcontroller", "siren", "appexpir",
                         "minappversion", "minimumappversion"),
    UPDATE_SHARED.pattern: ("upgrader", "in_app_update", "new_version", "force_update", "version_check",
                            "update_available", "appversion", "app_version", "forceupdate"),
    LOCK_ANDROID.pattern: ("isdevicesecure", "iskeyguardsecure", "canauthenticate", "setuserauthenticationrequired",
                           "setunlockeddevicerequired"),
    LOCK_IOS.pattern: ("canevaluatepolicy", "whenpasscodeset", "secaccesscontrolcreatewithflags"),
    LOCK_SHARED.pattern: ("isdevicesupported", "cancheckbiometrics", "getavailablebiometrics",
                          "passcode_set_this_device", "screen_lock_check"),
})


@detector("xpl_no_screen_lock_check")
def no_screen_lock_check(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _absence(ctx, rule, LOCK_ANDROID, LOCK_IOS, LOCK_SHARED, "check that the device has a screen lock")


# ---------------------------------------------------------------------------- XPL-023

RSA_PKCS1: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bCipher\s*\.\s*getInstance\s*\(\s*\"RSA(?:/(?:ECB|NONE)/(?:PKCS1Padding|NoPadding))?\""),
     "RSA encryption with PKCS #1 v1.5 padding (the default for \"RSA\") or none."),
    (re.compile(r"\bENCRYPTION_PADDING_RSA_PKCS1\b"), "A Keystore RSA key that allows PKCS #1 v1.5 encryption."),
    (re.compile(r"\.rsaEncryptionPKCS1\b|\bkSecKeyAlgorithmRSAEncryptionPKCS1\b|\bkSecKeyAlgorithmRSAEncryptionRaw\b|"
                r"\.rsaEncryptionRaw\b"),
     "SecKey RSA encryption with PKCS #1 v1.5 padding or none."),
    (re.compile(r"\bSecKeyEncrypt\s*\([^;\n]*(?:kSecPaddingPKCS1\b|kSecPaddingNone\b|\.PKCS1\b|\.none\b)"),
     "SecKeyEncrypt with PKCS #1 v1.5 padding or none."),
    (re.compile(r"\bPKCS1Encoding\s*\(|\bRSAEncoding\s*\.\s*PKCS1\b"), "Dart RSA encryption with PKCS #1 v1.5 padding."),
]


@detector("xpl_rsa_pkcs1")
def rsa_pkcs1(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("RSA", "PKCS1", "SecKeyEncrypt")):
        seen: Set[int] = set()
        for regex, message in RSA_PKCS1:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    yield _lower_if_legacy(ctx, _hit_at(ctx, path, code, m.start(), message, blank))
        if path.endswith(".dart") and "package:encrypt" in code:
            for m in re.finditer(r"\bRSA\s*\(", blank):
                args = code[m.end():guards.match(blank, m.end() - 1, "(", ")")]
                line = ctx.line_of(code, m.start())
                if "publicKey" in args and "encoding" not in args and line not in seen:
                    seen.add(line)
                    yield _lower_if_legacy(ctx, _hit_at(
                        ctx, path, code, m.start(),
                        "package:encrypt `RSA` defaults to PKCS #1 v1.5 padding; pass `encoding: RSAEncoding.OAEP`.",
                        blank))


# ---------------------------------------------------------------------------- XPL-024

WEAK_SIGNATURE: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bSignature\s*\.\s*getInstance\s*\(\s*\"((?:SHA1|SHA-1|MD5|MD2|NONE)with\w+)\""), "JCA"),
    (re.compile(r"\.(rsaSignature(?:Message|Digest)(?:PKCS1v15|PSS)SHA1|ecdsaSignature(?:Message|Digest)X962SHA1)\b"),
     "SecKey"),
    (re.compile(r"\b(kSecKeyAlgorithm(?:RSASignature|ECDSASignature)\w*SHA1)\b"), "SecKey"),
    (re.compile(r"\bSigner\s*\(\s*[\"']((?:SHA-1|MD5)/(?:RSA|ECDSA|DET-ECDSA))[\"']|\b(RSASigner)\s*\(\s*SHA1Digest"),
     "PointyCastle"),
]


@detector("xpl_weak_signature")
def weak_signature(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("Signature", "SHA1", "Signer", "DIGEST_SHA1")):
        seen: Set[int] = set()
        for regex, where in WEAK_SIGNATURE:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    algo = next(g for g in m.groups() if g)
                    yield _hit_at(ctx, path, code, m.start(), f"`{algo}` ({where}) signs with SHA-1, MD5, or no hash.",
                                  blank)
        if path.endswith(JVM) and "PURPOSE_SIGN" in code:
            for m in re.finditer(r"\bDIGEST_SHA1\b", blank):
                window = blank[max(0, m.start() - 800):m.start()]
                window = window[window.rfind("KeyGenParameterSpec"):] if "KeyGenParameterSpec" in window else ""
                line = ctx.line_of(code, m.start())
                if "PURPOSE_SIGN" in window and line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), "A Keystore signing key that allows SHA-1.", blank)


# ---------------------------------------------------------------------------- XPL-025

_MAC_API = re.compile(r"\bMac\s*\.\s*getInstance\b|\bHMAC\s*<|\bCCHmac\w*\b|\bHmac\s*\(|\bHMac\s*\(|\bhmacSha\w*\b")
_MAC_OPERAND = {"mac", "hmac", "tag", "signature", "sig", "digest", "checksum", "authtag"}
# An operand: a name with up to six member accesses and an optional empty call, starting at a token
# boundary (bounded, so long dotted runs can't make the search quadratic).
_OPERAND = r"(?<![\w.])(\w+(?:\.\w+){0,6}(?:\(\s*\))?)"
MAC_COMPARE = re.compile(
    r"\bArrays\s*\.\s*equals\s*\(\s*" + _OPERAND + r"\s*,\s*" + _OPERAND + r"\s*\)"
    r"|" + _OPERAND + r"\s*\.\s*(?:contentEquals|equals)\s*\(\s*" + _OPERAND + r"\s*\)"
    r"|\blistEquals\s*\(\s*" + _OPERAND + r"\s*,\s*" + _OPERAND + r"\s*\)"
    r"|" + _OPERAND + r"\s*[!=]==?\s*" + _OPERAND
)


# Network or IPC input in the same file, where a remote caller could measure the comparison's timing.
_REMOTE_IO = re.compile(r"\bHttpURLConnection\b|\bHttpsURLConnection\b|\bOkHttp\w*\b|\bokhttp3\b|\bRetrofit\b|"
                        r"\bSocket\b|\bServerSocket\b|\bURLSession\b|\bNSURLConnection\b|\bNWConnection\b|"
                        r"\bIntent\b|\bBinder\b|\bIBinder\b|\bMessenger\b|\bContentProvider\b|\bBroadcastReceiver\b|"
                        r"\bWebSocket\w*\b|\bHttpClient\b|\bhttp\s*\.\s*(?:get|post)\s*\(|\bDio\s*\(|"
                        r"\bMethodChannel\b|\bXPCConnection\b|\bNSXPCConnection\b")


@detector("xpl_mac_compare")
def mac_compare(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("Mac", "HMAC", "Hmac", "hmac")):
        if not _MAC_API.search(blank):
            continue
        seen: Set[int] = set()
        for m in MAC_COMPARE.finditer(blank):
            a, b = [g for g in m.groups() if g][:2]
            if any(x in ("null", "nil", "true", "false", "0") or x.isdigit() for x in (a, b)):
                continue
            if any(re.fullmatch(r"[A-Z_][A-Z0-9_]*", x.rsplit(".", 1)[-1]) for x in (a, b)):
                continue                       # TAG, constants
            words = _identifier_words(a + " " + b)
            if not words & _MAC_OPERAND or words & {"view", "holder", "item", "length", "size", "count", "type",
                                                   "name", "algorithm", "id"}:
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            hit = _hit_at(ctx, path, code, m.start(), "A MAC or signature is compared with an ordinary equality "
                                                     "check, which stops at the first differing byte.", blank)
            if not _REMOTE_IO.search(blank):
                hit.severity = "low"
                hit.message += (" This file does no network or IPC I/O, so an attacker can't time the comparison "
                                "remotely; still use a constant-time compare.")
            yield hit


# ---------------------------------------------------------------------------- XPL-026

_GENERATED_KEY = re.compile(r"\bKeyGenerator\s*\.\s*getInstance\s*\(|\bSymmetricKey\s*\(\s*size\s*:|"
                            r"\bKey\s*\.\s*fromSecureRandom\s*\(|\bAesGcm\s*\.\s*\w+\s*\(\s*\)\s*\.\s*newSecretKey|"
                            r"\bnewSecretKey\s*\(")
_RAW_KEY = re.compile(r"\.\s*(?:encoded|getEncoded\s*\(\s*\))|\bwithUnsafeBytes\b|\bData\s*\(\s*\w*[Kk]ey\b|"
                      r"\bextractBytes\s*\(|\.\s*base64\b|\.\s*bytes\b")
_STORE_SINK = re.compile(r"\bputString\s*\(|\bputBytes\s*\(|\.\s*edit\s*\(|\bedit\s*\{|\bwriteBytes\s*\(|"
                         r"\bwriteText\s*\(|\bopenFileOutput\s*\(|\bdataStore\b|\bUserDefaults\b|"
                         r"\.\s*write\s*\(\s*to\s*:|\bsetString\s*\(|\bFileOutputStream\s*\(")
_KEY_WRAPPED = re.compile(r"AndroidKeyStore|WRAP_MODE|\bwrap\s*\(|SecItemAdd|FlutterSecureStorage|Keychain|"
                          r"\bencrypt\w*\s*\(|\baead\b|\bseal\s*\(")


@detector("xpl_key_beside_data")
def key_beside_data(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("KeyGenerator", "SymmetricKey", "fromSecureRandom",
                                                    "newSecretKey")):
        reported: Set[int] = set()
        for m in _GENERATED_KEY.finditer(blank):
            start, end, _head = _enclosing_function(blank, m.start(), path)
            if start in reported or end - start >= len(blank):
                continue
            body, body_code = blank[start:end], code[start:end]
            if not _RAW_KEY.search(body) or not _STORE_SINK.search(body) or _KEY_WRAPPED.search(body_code):
                continue
            reported.add(start)
            yield _hit_at(ctx, path, code, m.start(), "A key generated in app memory is written to app storage as "
                                                      "raw bytes, next to the data it protects.", blank)


# ---------------------------------------------------------------------------- XPL-027

SECRANDOM_IGNORED = re.compile(r"\b_\s*=\s*SecRandomCopyBytes\s*\(|^[ \t]*(?:\(void\)\s*)?SecRandomCopyBytes\s*\(",
                               re.MULTILINE)


@detector("xpl_secrandom_unchecked")
def secrandom_unchecked(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, APPLE, ("SecRandomCopyBytes",)):
        for m in SECRANDOM_IGNORED.finditer(blank):
            yield _hit_at(ctx, path, code, m.start() + len(m.group(0)) - len(m.group(0).lstrip()),
                          "`SecRandomCopyBytes` can fail, and its status is ignored, so the buffer may stay zero.",
                          blank)


# ---------------------------------------------------------------------------- XPL-029

_DOM_SINK = re.compile(r"innerHTML|outerHTML|textContent|innerText|\.value\s*=|document\.write|insertAdjacentHTML")
_DOM_SECRET = {"otp", "token", "password", "passcode", "pin", "balance", "card", "cardnumber", "iban", "account",
               "accountnumber", "ssn", "cvv", "secret"}
JS_EVAL = re.compile(r"\bevaluateJavaScript\s*\(|\bevaluateJavascript\s*\(|\bloadUrl\s*\(\s*\"javascript:|"
                     r"\brunJavaScript\w*\s*\(")


@detector("xpl_webview_dom_secret")
def webview_dom_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("evaluateJavaScript", "evaluateJavascript", "javascript:",
                                                    "runJavaScript")):
        for m in JS_EVAL.finditer(code):
            open_paren = code.index("(", m.start())
            close = guards.match(blank, open_paren, "(", ")")
            text = code[open_paren:min(close, open_paren + 800)]
            if not _DOM_SINK.search(text):
                continue
            exprs = " ".join(next(x for x in g.groups() if x is not None) for g in INTERP.finditer(text))
            exprs += " " + blank[open_paren:min(close, open_paren + 800)]     # concatenated identifiers
            found = sorted(_words_of(exprs) & _DOM_SECRET)
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"Native code writes a `{found[0]}` into the web page's DOM, "
                                                          "where every script on the page can read it.", blank)


# ---------------------------------------------------------------------------- XPL-030

NATIVE_TLS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bCURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|0L|false|FALSE)\b"), "libcurl stops verifying the server certificate."),
    (re.compile(r"\bCURLOPT_SSL_VERIFYHOST\s*,\s*(?:0|0L|false|FALSE)\b"), "libcurl stops checking the host name."),
    (re.compile(r"\b(?:SSL_CTX_set_verify|SSL_set_verify|wolfSSL_CTX_set_verify)\s*\([^,;]*,\s*(?:SSL_VERIFY_NONE|"
                r"WOLFSSL_VERIFY_NONE)\b"), "The TLS library is told not to verify the peer."),
    (re.compile(r"\bmbedtls_ssl_conf_authmode\s*\([^,;]*,\s*MBEDTLS_SSL_VERIFY_(?:NONE|OPTIONAL)\b"),
     "mbedTLS doesn't require a valid server certificate."),
    (re.compile(r"\bSSL_CTX_set_min_proto_version\s*\([^,;]*,\s*(?:SSL3_VERSION|TLS1_VERSION|TLS1_1_VERSION)\b"),
     "The TLS library allows protocol versions below TLS 1.2."),
    (re.compile(r"\bmbedtls_ssl_conf_min_version\s*\([^;]*MBEDTLS_SSL_MINOR_VERSION_[0-2]\b"),
     "mbedTLS allows protocol versions below TLS 1.2."),
]


@detector("xpl_native_tls")
def native_tls(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, NATIVE, ("CURLOPT_SSL", "set_verify", "VERIFY_", "min_proto_version",
                                                      "conf_min_version")):
        seen: Set[int] = set()
        for regex, message in NATIVE_TLS:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), message, blank)


# ---------------------------------------------------------------------------- XPL-031

_DB_SECRET_FIELD = re.compile(
    r"(?:^|[(,])[ \t]*(?:@\w+(?:\([^)\n]*\))?\s+)*(?:(?:private|public|protected|internal|override|final|open|lateinit|"
    r"@JvmField)\s+)*(?:val|var|String|Int|Long|dynamic|late\s+String\??|final\s+String\??)\s+"
    r"(password|passwd|passcode|pin|pinCode|accessToken|refreshToken|authToken|sessionToken|token|apiKey|secret|"
    r"clientSecret|privateKey|cardNumber|cvv|cvc|iban|ssn)\b", re.MULTILINE | re.IGNORECASE)
_DB_ENCRYPTED = re.compile(r"SupportOpenHelperFactory\s*\(|SupportFactory\s*\(|net\.zetetic|sqlcipher|"
                           r"SQLiteDatabase\.loadLibs|encryptionKey\b|encryptionCipher\s*:|HiveAesCipher|"
                           r"sqflite_sqlcipher|encrypted_shared|EncryptedRealm|NSPersistentStoreFileProtectionKey")


@detector("xpl_db_plain_credentials")
def db_plain_credentials(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if _found(ctx, _DB_ENCRYPTED):
        return
    for path, code, blank in _files_with(ctx, JVM, ("@Entity", "RealmObject")):
        marks = [m.start() for m in re.finditer(r"@Entity\b|\bclass\s+\w+[^{\n]*\bRealmObject\b", blank)]
        for i, start in enumerate(marks):
            end = marks[i + 1] if i + 1 < len(marks) else min(len(code), start + 4000)
            region = code[start:end]
            owner = _words_of(region[:300])
            for m in _DB_SECRET_FIELD.finditer(region):
                if m.group(1).lower() == "token" and not owner & {"account", "user", "session", "auth", "credential",
                                                                   "login", "profile"}:
                    continue                  # a share or page token, not a credential
                yield _hit_at(ctx, path, code, start + m.start(1),
                              f"Database field `{m.group(1)}` is stored without database encryption.", blank)
    for path, code, blank in _files_with(ctx, DART, ("Hive", "openBox")):
        if not re.search(r"\.\s*put\s*\(\s*['\"](?:\w*_)?(?:token|password|secret|pin|access_?token|refresh_?token)"
                         r"['\"]", code, re.IGNORECASE):
            continue
        for m in re.finditer(r"\bHive\s*\.\s*openBox\s*(?:<[^>]*>)?\s*\(", blank):
            args = code[m.end():guards.match(blank, m.end() - 1, "(", ")")]
            if "encryptionCipher" not in args:
                yield _hit_at(ctx, path, code, m.start(), "A Hive box that stores a token or password is opened "
                                                          "without `encryptionCipher`.", blank)
    for path, code, blank in _files_with(ctx, (".swift",), ("Realm.Configuration", "Object")):
        if not re.search(r"@Persisted\s+var\s+(?:password|token|accessToken|refreshToken|pin|secret)\b", code):
            continue
        for m in re.finditer(r"\bRealm\s*\.\s*Configuration\s*\(", blank):
            yield _hit_at(ctx, path, code, m.start(), "A Realm that stores a token or password is configured "
                                                      "without an `encryptionKey`.", blank)


# ---------------------------------------------------------------------------- XPL-032

_NOTIF_SECRET = {"otp", "passcode", "password", "pin", "balance", "iban", "cardnumber", "cvv", "onetimecode",
                 "verificationcode", "securitycode", "authcode", "smscode", "logincode", "otpcode", "accountbalance"}
NOTIF_TEXT = re.compile(r"\.\s*(?:setContentText|setContentTitle|bigText|setTicker|setSubText)\s*\(")
IOS_NOTIF = re.compile(r"\.\s*(?:body|title|subtitle)\s*=\s*")
_NOTIF_PRIVATE = re.compile(r"VISIBILITY_(?:PRIVATE|SECRET)|setPublicVersion\s*\(|NotificationVisibility\.(?:private|"
                            r"secret)")


def _notif_found(text_code: str, text_blank: str) -> List[str]:
    exprs = " ".join(next(x for x in g.groups() if x is not None) for g in INTERP.finditer(text_code))
    return sorted(_words_of(exprs + " " + text_blank) & _NOTIF_SECRET)


@detector("xpl_notification_secret")
def notification_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, JVM, ("setContentText", "setContentTitle", "bigText")):
        for m in NOTIF_TEXT.finditer(blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            found = _notif_found(code[m.end():close], blank[m.end():close])
            if not found:
                continue
            start, end, _head = _enclosing_function(blank, m.start(), path)
            if _NOTIF_PRIVATE.search(blank[start:end]):
                continue
            yield _hit_at(ctx, path, code, m.start(), f"A notification shows a `{found[0]}`, which appears on the "
                                                      "lock screen unless the notification is private.", blank)
    for path, code, blank in _files_with(ctx, (".swift",), ("UNMutableNotificationContent",)):
        for m in IOS_NOTIF.finditer(blank):
            s, e = _line_span(code, m.end())
            found = _notif_found(code[m.end():e], blank[m.end():e])
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"A notification shows a `{found[0]}` on the lock screen.",
                              blank)
    for path, code, blank in _files_with(ctx, DART, ("flutter_local_notifications",)):
        if _NOTIF_PRIVATE.search(code):
            continue
        for m in re.finditer(r"\.\s*show\s*\(", blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            found = _notif_found(code[m.end():close], blank[m.end():close])
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"A notification shows a `{found[0]}` on the lock screen.",
                              blank)


# ---------------------------------------------------------------------------- XPL-033

_FIELD_SECRET = re.compile(r"(?i)pass(?:word|code|wd)|(?<![a-z])pin(?![a-z])|(?<![a-z])pin(?=[A-Z_]|code)")
_XML_FIELD = re.compile(r"<(?:[\w.]+\.)?(?:EditText|TextInputEditText|AppCompatEditText|MaterialAutoCompleteTextView)"
                        r"\b[^>]*>")
_MASKED_TYPE = re.compile(r"android:inputType\s*=\s*\"[^\"]*(?:textPassword|numberPassword|textWebPassword)")
COMPOSE_FIELD = re.compile(r"(?<![\w.])(?:OutlinedTextField|TextField|BasicTextField)\s*\(")
DART_FIELD = re.compile(r"(?<![\w.])(?:TextField|TextFormField|CupertinoTextField)\s*\(")
SWIFTUI_FIELD = re.compile(r"(?<![\w.])TextField\s*\(\s*(?:String\s*\(\s*localized:\s*)?\"([^\"\n]*)\"")


def _field_label_secret(args_code: str) -> bool:
    labels = re.findall(r"(?:label|placeholder|hint|labelText|hintText|helperText)\s*[=:]\s*([^,\n]{0,120})", args_code)
    return any(_FIELD_SECRET.search(lbl) for lbl in labels)


@detector("xpl_unmasked_secret_field")
def unmasked_secret_field(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".xml"):
        if "/res/layout" not in "/" + path:
            continue
        text = ctx.text(path) or ""
        if "EditText" not in text:
            continue
        for m in _XML_FIELD.finditer(text):
            tag = m.group(0)
            names = " ".join(re.findall(r"android:(?:id|hint|autofillHints|contentDescription)\s*=\s*\"([^\"]*)\"",
                                        tag))
            if not _FIELD_SECRET.search(names) or _MASKED_TYPE.search(tag):
                continue
            if "textVisiblePassword" not in tag and "android:inputType" in tag and \
                    not re.search(r"android:inputType\s*=\s*\"(?:text|number|phone)\"", tag):
                continue
            line = ctx.line_of(text, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      "A password or PIN field shows the typed characters (no password input type).")
    for path, code, blank in _files_with(ctx, (".kt",), ("TextField",)):
        for m in COMPOSE_FIELD.finditer(blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            args = code[m.end():close]
            if "visualTransformation" in args or not _field_label_secret(args):
                continue
            yield _hit_at(ctx, path, code, m.start(), "A password or PIN text field has no "
                                                      "`PasswordVisualTransformation`, so it shows what's typed.", blank)
        for m in re.finditer(r"\btextObfuscationMode\s*=\s*TextObfuscationMode\s*\.\s*Visible\b", blank):
            yield _hit_at(ctx, path, code, m.start(), "A `SecureTextField` is set to show its text.", blank)
    for path, code, blank in _files_with(ctx, DART, ("TextField", "TextFormField")):
        for m in DART_FIELD.finditer(blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            args = code[m.end():close]
            if re.search(r"\bobscureText\s*:\s*(?!false\b)", args) or not _field_label_secret(args):
                continue
            yield _hit_at(ctx, path, code, m.start(), "A password or PIN field without `obscureText: true` shows "
                                                      "what's typed.", blank)
    for path, code, blank in _files_with(ctx, (".swift",), ("TextField",)):
        for m in SWIFTUI_FIELD.finditer(code):
            if _FIELD_SECRET.search(m.group(1)):
                yield _hit_at(ctx, path, code, m.start(), "A password or PIN is typed into a `TextField`; use "
                                                          "`SecureField`.", blank)


# ---------------------------------------------------------------------------- XPL-034

_PII_WORDS = {"email", "phone", "msisdn", "username", "fullname", "nationalid", "ssn", "iban", "phonenumber",
              "emailaddress", "mobilenumber", "displayname", "dob", "birthdate", "address"}
ANALYTICS_ID = re.compile(r"\b(?:setUserId|setUserID|identify|setUserIdentifier|setCustomerUserId)\s*\(")
ANALYTICS_KEYED = re.compile(r"\b(?:setUserProperty|setCustomKey|setCustomValue|setUserProperties|setAttribute)\s*\(\s*"
                             r"(?:forName\s*:\s*|key\s*:\s*|name\s*:\s*)?[\"']\$?(email|phone|msisdn|name|full_?name|"
                             r"user_?name|phone_?number|address|dob|birthday|national_?id|ssn|iban)[\"']",
                             re.IGNORECASE)
_ANALYTICS_FILE = re.compile(r"Analytics|Crashlytics|Amplitude|Mixpanel|Segment|AppsFlyer|Adjust|Braze|Sentry|"
                             r"Bugsnag|Datadog|PostHog|Countly")


@detector("xpl_analytics_pii")
def analytics_pii(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("setUserId", "setUserID", "identify", "setUserProperty",
                                                    "setCustomKey", "setCustomValue", "setAttribute",
                                                    "setUserIdentifier", "setCustomerUserId")):
        if not _ANALYTICS_FILE.search(code):
            continue
        seen: Set[int] = set()
        for m in ANALYTICS_ID.finditer(blank):
            close = guards.match(blank, m.end() - 1, "(", ")")
            found = sorted(_words_of(blank[m.end():close]) & _PII_WORDS)
            line = ctx.line_of(code, m.start())
            if found and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"An analytics or crash SDK receives the user's "
                                                          f"`{found[0]}` as their identity.", blank)
        for m in ANALYTICS_KEYED.finditer(code):
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"An analytics or crash SDK receives the user's "
                                                          f"`{m.group(1)}`.", blank)


# ---------------------------------------------------------------------------- XPL-035

COMPILER_FLAGS: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"-fno-stack-protector\b"), "turns off stack canaries"),
    (re.compile(r"(?<![\w-])-(?:fno-pie|fno-PIE|fno-pic|fno-PIC|no-pie)\b"), "turns off position-independent code"),
    (re.compile(r"-z\s*,?\s*execstack\b"), "makes the stack executable"),
    (re.compile(r"-z\s*,?\s*norelro\b"), "turns off RELRO"),
    (re.compile(r"-D\s*_FORTIFY_SOURCE\s*=\s*0\b"), "turns off FORTIFY_SOURCE"),
    (re.compile(r"\bCLANG_ENABLE_OBJC_ARC\s*=\s*NO\b"), "turns off Automatic Reference Counting"),
    (re.compile(r"-fno-objc-arc\b"), "turns off Automatic Reference Counting for a file"),
    (re.compile(r"\bGCC_DYNAMIC_NO_PIC\s*=\s*YES\b"), "turns off position-independent code"),
]


@detector("xpl_compiler_protections")
def compiler_protections(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".txt", ".xcconfig", ".pbxproj", ".gradle", ".kts", ".cmake"):
        base = path.rsplit("/", 1)[-1]
        if path.endswith(".txt") and base != "CMakeLists.txt":
            continue
        raw = ctx.text(path) or ""
        if not any(k in raw for k in ("-fno", "-no-pie", "execstack", "norelro", "FORTIFY", "OBJC_ARC", "DYNAMIC_NO_PIC")):
            continue
        if base == "CMakeLists.txt":
            text = re.sub(r"#[^\n]*", lambda c: " " * len(c.group(0)), raw)
        elif path.endswith(".xcconfig"):
            text = re.sub(r"//[^\n]*", lambda c: " " * len(c.group(0)), raw)
        elif path.endswith((".gradle", ".kts")):
            text = ctx.code(path, keep_strings=True) or ""
        else:
            text = raw
        seen: Set[int] = set()
        for regex, what in COMPILER_FLAGS:
            for m in regex.finditer(text):
                line = ctx.line_of(text, m.start())
                if line not in seen:
                    seen.add(line)
                    yield Hit(path, line, ctx.snippet(path, line), f"`{m.group(0)}` {what}.")


# ---------------------------------------------------------------------------- XPL-036

URL_HOST = re.compile(r"[\"']https?://([A-Za-z0-9.-]+)(?::\d+)?(?=[/\"'?#:])")
# `staging-api.`, `api.dev.`, `api-qa.`; "test" and "sandbox" only as a whole label or a suffix, since
# `test-kitchen.` or `testflight.` name production services.
_NON_PROD_LABEL = re.compile(r"(?:^|[.-])(?:staging|stage|stg|dev|develop|qa|uat|preprod|pre-prod)(?=[.-])|"
                             r"(?:^|[.-])(?:test|testing|sandbox|integration)(?=\.)", re.IGNORECASE)
_PRIVATE_HOST = re.compile(r"^(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)$")
_DOC_HOSTS = re.compile(r"(?:^|\.)(?:example\.(?:com|org|net)|test|invalid|localhost|w3\.org|apple\.com|google\.com|"
                        r"android\.com|github\.com|githubusercontent\.com|mozilla\.org|wikipedia\.org)$",
                        re.IGNORECASE)


@detector("xpl_nonprod_endpoint")
def nonprod_endpoint(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("http",)):
        if (scope_of(path) in ("test", "build-script", "debug") or _TEST_IMPORT.search(code)
                or _NON_RELEASE_SOURCE_SET.search("/" + path)):
            continue                          # only code that ships in the release variant
        seen: Set[int] = set()
        for m in URL_HOST.finditer(code):
            host = m.group(1).lower().rstrip(".")
            if host in ("10.0.2.2", "10.0.3.2"):
                why = "the Android emulator's host address"
            elif _PRIVATE_HOST.match(host):
                why = "a private network address"
            elif "." in host and not _DOC_HOSTS.search(host) and _NON_PROD_LABEL.search("." + host.rsplit(".", 1)[0]):
                why = "a non-production host name"
            else:
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), f"`{host}` is {why}, in code that ships.", blank)


# ---------------------------------------------------------------------------- XPL-037

OAUTH_BAD: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"response_type=(?:id_token(?:\+|%20| ))?token\b(?![-_])"), "the implicit flow (`response_type=token`)"),
    (re.compile(r"[\"']response_type[\"']\s*(?:,|to|:|=>)\s*[\"'](?:id_token )?token[\"']"),
     "the implicit flow (`response_type=token`)"),
    (re.compile(r"grant_type=password\b"), "the password grant"),
    (re.compile(r"[\"']grant_type[\"']\s*(?:,|to|:|=>)\s*[\"']password[\"']"), "the password grant"),
    (re.compile(r"code_challenge_method=plain\b|[\"']code_challenge_method[\"']\s*(?:,|to|:|=>)\s*[\"']plain[\"']"),
     "PKCE with the `plain` method"),
    (re.compile(r"\.\s*setCodeVerifier\s*\(\s*(?:null|nil)\b"), "an authorization request without PKCE"),
    (re.compile(r"\b(?:loadUrl|load)\s*\([^;\n]{0,200}(?:/oauth2?/authorize|/oauth2/auth\b|/authorize\?|"
                r"response_type=)"), "a sign-in page loaded in a WebView"),
]


@detector("xpl_oauth_flow")
def oauth_flow(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("response_type", "grant_type", "code_challenge_method",
                                                    "setCodeVerifier", "authorize", "oauth")):
        if re.search(r"(?i)/(?:server|backend)/", "/" + path):
            continue
        seen: Set[int] = set()
        for regex, what in OAUTH_BAD:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), f"Sign-in uses {what}, which RFC 8252 and RFC 9700 "
                                                              "rule out for mobile apps.", blank)


# ---------------------------------------------------------------------------- XPL-041

JACKSON_TYPING = re.compile(r"\benableDefaultTyping\s*\(|\bactivateDefaultTyping\s*\(|"
                            r"\bJsonTypeInfo\s*\.\s*Id\s*\.\s*(?:CLASS|MINIMAL_CLASS)\b")


@detector("xpl_jackson_typing")
def jackson_typing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, JVM, ("DefaultTyping", "JsonTypeInfo")):
        for m in JACKSON_TYPING.finditer(blank):
            yield _hit_at(ctx, path, code, m.start(), "Jackson builds whatever class the JSON names, which lets "
                                                      "input pick a gadget class.", blank)


# ---------------------------------------------------------------------------- XPL-042

SHELL_EXEC = re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(|"
                        r"(?<![\w.])(?:system|popen)\s*\(|\bProcess\s*\.\s*(?:run|start)\s*\(")
_STRING_LIT = re.compile(r"^\s*(?:\"(?:[^\"\\\n$]|\\.)*\"|'(?:[^'\\\n$]|\\.)*'|@\"[^\"\n]*\")\s*$")
_LIST_LIT = re.compile(r"^\s*(?:(?:arrayOf|listOf|mutableListOf|Arrays\s*\.\s*asList|List\s*\.\s*of)\s*(\()|"
                       r"new\s+String\s*\[\s*\]\s*(\{)|(?:const\s+)?(\[))")
_SHELLS = {"sh", "bash", "zsh", "su", "/system/bin/sh", "/system/xbin/su", "/bin/sh", "/bin/bash"}


def _constant_piece(code: str, expr: str) -> bool:
    """A literal, an UPPER_CASE or file-level string constant, or a concatenation of those."""
    for piece in re.split(r"\+", expr):
        piece = piece.strip()
        if _STRING_LIT.match(piece) or re.fullmatch(r"(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*", piece):
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", piece) and (_string_constant(code, piece) or re.search(
                r"\b" + re.escape(piece) + r"\s*=\s*(?:arrayOf|listOf)\s*\(\s*(?:\"[^\"\n]*\"\s*,?\s*)*\)", code)):
            continue
        return False
    return True


def _elements(code: str, blank: str, span: Tuple[int, int]) -> Optional[List[str]]:
    """Elements of a list or array literal argument, or None when the argument is something else."""
    m = _LIST_LIT.match(blank[span[0]:span[1]])
    if not m:
        return None
    open_at = span[0] + max(m.start(g) for g in (1, 2, 3) if m.group(g))
    closer = {"(": ")", "{": "}", "[": "]"}[blank[open_at]]
    close = guards.match(blank, open_at, blank[open_at], closer)
    out: List[str] = []
    depth, start = 0, open_at + 1
    for i in range(open_at + 1, close):
        c = blank[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(code[start:i])
            start = i + 1
    if code[start:close].strip():
        out.append(code[start:close])
    return out


def _shell_risk(ctx_code: str, blank: str, path: str, call: str, idx: int, args: List[Tuple[int, int]]) -> bool:
    code = ctx_code
    texts = [code[s:e] for s, e in args]
    if path.endswith(NATIVE):
        return not _constant_piece(code, texts[0])           # system() and popen() always use a shell
    if path.endswith(".dart"):
        elements: Optional[List[str]] = [texts[0]] + ((_elements(code, blank, args[1]) or []) if len(args) > 1 else [])
        in_shell = bool(re.search(r"\brunInShell\s*:\s*true\b", code[args[0][0]:args[-1][1]]))
    else:
        elements = _elements(code, blank, args[0]) if (len(args) == 1 or not call.startswith("Process")) else texts
        in_shell = False
    if elements is not None:
        words = [e.strip().strip("\"'") for e in elements]
        shell = in_shell or (len(words) >= 2 and words[0] in _SHELLS and "-c" in words)
        return shell and not all(_constant_piece(code, e) for e in elements)
    # Runtime.exec(String) splits on spaces without a shell, but an interpolated value can still add
    # options or, with `sh -c`, commands. A bare variable passed through from a parameter is judged at the caller.
    expr = texts[0]
    name = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", expr)
    if name:
        return False
    return not _constant_piece(code, expr) and bool(re.search(r"\+|\$\{?[A-Za-z_]", expr))


@detector("xpl_shell_command")
def shell_command(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = "A shell command is built from a variable; if any part comes from input, it can run other commands."
    for path, code, blank in _files_with(ctx, JVM + NATIVE + DART, ("exec", "ProcessBuilder", "system", "popen",
                                                                   "Process.")):
        is_c, is_dart = path.endswith(NATIVE), path.endswith(".dart")
        for m in SHELL_EXEC.finditer(blank):
            call = m.group(0)
            if is_c != call.startswith(("system", "popen")) or is_dart != bool(re.match(r"Process\s*\.", call)):
                continue
            args = _args_of(blank, m.end() - 1)
            if args and _shell_risk(code, blank, path, call, m.start(), args):
                yield _hit_at(ctx, path, code, m.start(), msg, blank)
