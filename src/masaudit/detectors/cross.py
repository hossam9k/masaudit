# SPDX-License-Identifier: Apache-2.0
"""Cross-platform code detectors (Kotlin, Java, Swift, Objective-C): secrets, crypto misuse,
cleartext URLs, and sensitive logging. Book: §15.2, Chapter 0.2, §6.5, §7.1.

Every detector runs on code with comments blanked, so commented-out code and prose never match.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Pattern, Sequence, Set, Tuple

from masaudit.detect import scope_of
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule

CODE = (".kt", ".java", ".swift", ".m", ".mm", ".h")
JVM = (".kt", ".java")
APPLE = (".swift", ".m", ".mm", ".h")


def _mask_in(snippet: str, value: str) -> str:
    """Mask `value` in a snippet even when it is too short for the generic masker."""
    if value and value in snippet:
        return snippet.replace(value, (value[:4] if len(value) > 8 else "") + "…[masked]")
    return snippet


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
                yield Hit(path, line, snippet, message)


def _placeholder(value: str) -> bool:
    v = value.upper()
    return "EXAMPLE" in v or bool(re.search(r"(.)\1{7,}", value))


# ---------------------------------------------------------------------------- XPL-001

RESTRICTED: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
     "A private key is embedded in the code."),
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
        if raw is None or not any(p in raw for p in ("PRIVATE KEY", "AKIA", "ASIA", "sk-", "k_live_",
                                                      "gh", "github_pat_", "xox")):
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen: Set[int] = set()
        for regex, message in RESTRICTED:
            for m in regex.finditer(code):
                if _placeholder(m.group(0)):
                    continue
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                snippet = ctx.snippet(path, line)
                if not m.group(0).startswith("-----"):      # a PEM header line is not itself secret
                    snippet = _mask_in(snippet, m.group(0))
                yield Hit(path, line, snippet, message)


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
    r"\s*(?:=|:|\bto\b)\s*@?\"([^\"\n]{8,})\"",
    re.IGNORECASE,
)


def _real_secret_value(value: str) -> bool:
    v = value.strip()
    low = v.lower()
    if any(s in v for s in ("${", "$(", "{{", "%", "<", "\\(")):
        return False
    if any(low.startswith(p) for p in ("your", "replace", "change", "placeholder", "todo", "insert", "xxx")):
        return False
    if re.fullmatch(r"[a-z]+(?:[_.\-][a-z]+)*", v) or re.fullmatch(r"[A-Z]+(?:_[A-Z]+)*", v):
        return False                                # a key name such as "client_secret", not a value
    return not _placeholder(v)


@detector("xpl_secret_assignment")
def secret_assignment(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        raw = ctx.text(path)
        if raw is None or "secret" not in raw.lower():
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen: Set[int] = set()
        for m in SECRET_ASSIGN.finditer(code):
            if not _real_secret_value(m.group(2)):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, _mask_in(ctx.snippet(path, line), m.group(2)),
                      f"`{m.group(1)}` is set to a literal value, so it ships inside the app.")


# ---------------------------------------------------------------------------- XPL-004

ECB: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"Cipher\.getInstance\(\s*\"AES\"\s*[,)]"),
     "`Cipher.getInstance(\"AES\")` names no mode, and Android can silently pick ECB."),
    (re.compile(r"\"AES/ECB[^\"]*\""), "AES in ECB mode: identical blocks give identical ciphertext."),
    (re.compile(r"\bkCC(?:OptionECBMode|ModeECB)\b"), "CommonCrypto in ECB mode."),
    (re.compile(r"\bECB\(\)"), "A block cipher in ECB mode."),
]


@detector("xpl_ecb")
def ecb(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for hit in _scan(ctx, ECB, prefilter=("AES", "ECB")):
        yield hit
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
            yield Hit(path, line, ctx.snippet(path, line), "A Keystore AES key that allows ECB mode.")


# ---------------------------------------------------------------------------- XPL-005

CBC: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\"AES/CBC[^\"]*\""), "AES-CBC encrypts but doesn't detect tampering."),
    (re.compile(r"\bBLOCK_MODE_CBC\b"), "A Keystore key that uses CBC mode."),
    (re.compile(r"\bkCCModeCBC\b"), "CommonCrypto in CBC mode."),
    (re.compile(r"\bCBC\(\s*iv:"), "A block cipher in CBC mode."),
]


@detector("xpl_cbc")
def cbc(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for hit in _scan(ctx, CBC, prefilter=("CBC",)):
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
    r"\b(?:AES\.GCM|ChaChaPoly)\.Nonce\(\s*data:\s*(?:Data\(\s*\[|Data\(\s*\"|\"[^\"\n]*\"\s*\.data\(|\[)"
    r"|\biv:\s*(?:\"[^\"\n]*\"|Array\(\s*\"|\[\s*(?:0x)?[0-9])"
)


def _var_is_literal(code: str, name: str) -> bool:
    decl = re.search(
        r"\b" + re.escape(name) + r"\b(?:\s*:\s*ByteArray)?\s*=\s*(" + _LITERAL_BYTES + r"|\{)", code
    )
    if decl is None:
        decl = re.search(r"byte\s*\[\s*\]\s*" + re.escape(name) + r"\s*=\s*(\{|" + _LITERAL_BYTES + ")", code)
    if decl is None:
        return False
    init = decl.group(1)
    if re.match(r"ByteArray\(|new\s+byte\s*\[\s*\d", init):
        # A sized buffer is fine when SecureRandom fills it.
        return not re.search(r"nextBytes\(\s*" + re.escape(name) + r"\s*\)", code)
    return True


@detector("xpl_static_iv")
def static_iv(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = "The IV or nonce is a fixed value, so it repeats for every message encrypted with this key."
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "ParameterSpec" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen: Set[int] = set()
        for m in IV_INLINE.finditer(code):
            line = ctx.line_of(code, m.start())
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), msg)
        for m in IV_CALL_VAR.finditer(code):
            line = ctx.line_of(code, m.start())
            if line not in seen and _var_is_literal(code, m.group(1)):
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), msg)
    for hit in _scan(ctx, [(SWIFT_NONCE, msg)], suffixes=(".swift",), prefilter=("Nonce(", "iv:")):
        yield hit


# ---------------------------------------------------------------------------- XPL-007

WEAK_HASH: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\""), "MD5 or SHA-1 through MessageDigest."),
    (re.compile(r"\bInsecure\.(?:MD5|SHA1)\b"), "CryptoKit's `Insecure` MD5 or SHA-1."),
    (re.compile(r"\bCC_(?:MD5|SHA1)\s*\("), "CommonCrypto MD5 or SHA-1."),
    (re.compile(r"\bDigestUtils\.(?:md5|sha1)\w*\s*\("), "MD5 or SHA-1 through DigestUtils."),
    (re.compile(r"\bHashing\.(?:md5|sha1)\s*\("), "MD5 or SHA-1 through Guava."),
]


@detector("xpl_weak_hash")
def weak_hash(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for hit in _scan(ctx, WEAK_HASH, prefilter=("MD5", "SHA1", "SHA-1", "md5", "sha1")):
        yield hit


# ---------------------------------------------------------------------------- XPL-008

RNG_JVM: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bjava\.util\.Random\s*[.(]"), "`java.util.Random` is predictable from a few outputs."),
    (re.compile(r"\bkotlin\.random\.Random\s*[.(]"), "`kotlin.random.Random` is not a secure generator."),
    (re.compile(r"\bMath\.random\s*\("), "`Math.random()` is predictable."),
    (re.compile(r"\bSecureRandom\s*\(\s*[A-Za-z_\"]"), "A SecureRandom seeded by the caller."),
    (re.compile(r"\bsetSeed\s*\("), "A generator seeded by the caller."),
]
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


@detector("xpl_insecure_random")
def insecure_random(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "Random" not in raw and "random" not in raw and "setSeed" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        pats = list(RNG_JVM)
        for imp, message in RNG_IMPORTS:
            if imp.search(code):
                pats.append((RNG_IMPORTED_USE, message))
                break
        for regex, message in pats:
            for m in regex.finditer(code):
                if regex.pattern.startswith(r"\bsetSeed") and "Random" not in code:
                    continue
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    yield Hit(path, line, ctx.snippet(path, line), message)
    for hit in _scan(ctx, RNG_APPLE, suffixes=APPLE, keep_strings=False, prefilter=("rand",)):
        yield hit


# ---------------------------------------------------------------------------- XPL-009

HTTP_URL = re.compile(r"\"http://([^\"\s/?#]*)")
SAFE_HOSTS = re.compile(
    r"^(?:localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\[::1\]|"
    r"(?:[\w-]+\.)*example\.(?:com|org|net)|schemas\.android\.com|schemas\.xmlsoap\.org|"
    r"schemas\.microsoft\.com|www\.w3\.org|w3\.org|ns\.adobe\.com|www\.apple\.com|purl\.org|xmlpull\.org|"
    r"(?:[\w-]+\.)*(?:localhost|test|invalid|local))(?::\d+)?$",
    re.IGNORECASE,
)


@detector("xpl_http_url")
def http_url(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        if scope_of(path) == "test":
            continue
        raw = ctx.text(path)
        if raw is None or "http://" not in raw:
            continue
        code = ctx.code(path, keep_strings=True) or ""
        seen: Set[int] = set()
        for m in HTTP_URL.finditer(code):
            host = m.group(1)
            if not host or host.startswith(("%", "$", "\\(")) or SAFE_HOSTS.match(host):
                continue                     # a bare scheme prefix, a placeholder, or a safe host
            line_start = code.rfind("\n", 0, m.start()) + 1
            if re.search(r"xmlns|DOCTYPE", code[line_start:m.start()]):
                continue
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), f"A plain-HTTP URL to `{host}`.")


# ---------------------------------------------------------------------------- XPL-010

LOG_CALL = re.compile(
    r"(?<![\w.])(?:Log\.(?:v|d|i|w|e|wtf)|Timber\.(?:v|d|i|w|e|wtf)|System\.(?:out|err)\.print(?:ln|f)?|"
    r"println|print|debugPrint|NSLog|os_log)\s*\("
)
SENSITIVE_WORD = re.compile(r"(?i)token|passw(?:or)?d|passwd|secret|authorization|bearer")
SENSITIVE_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
INTERP = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*)|\\\(([^)]*)\)")


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


@detector("xpl_sensitive_log")
def sensitive_log(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        raw = ctx.text(path)
        if raw is None or not SENSITIVE_WORD.search(raw):
            continue
        bare = ctx.code(path, keep_strings=False) or ""     # string contents blanked
        full = ctx.code(path, keep_strings=True) or ""      # same offsets, strings kept
        seen: Set[int] = set()
        for m in LOG_CALL.finditer(bare):
            open_at = m.end() - 1
            close = _close_paren(bare, open_at)
            if m.group(0).startswith("os_log") and "{public}" not in full[open_at:close]:
                continue                                    # os_log redacts dynamic values by default
            args_code = bare[open_at:close]
            args_text = full[open_at:close]
            # Sensitive names used as values (outside string literals), or interpolated into strings.
            names = [w for w in SENSITIVE_IDENT.findall(args_code) if SENSITIVE_WORD.search(w)]
            for g in INTERP.finditer(args_text):
                expr = next(x for x in g.groups() if x is not None)
                if SENSITIVE_WORD.search(expr):
                    names.append(expr.strip())
            names = [n for n in names if n not in ("TAG",) and not n.isupper()]
            if not names:
                continue
            line = ctx.line_of(bare, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), f"`{names[0]}` is written to the log.")
