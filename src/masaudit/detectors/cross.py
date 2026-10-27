# SPDX-License-Identifier: Apache-2.0
"""Cross-platform code detectors (Kotlin, Java, Swift, Objective-C, Dart): secrets, crypto misuse,
cleartext URLs, and sensitive logging. Book: §15.2, Chapter 0.2, §6.5, §7.1.

Every detector runs on code with comments blanked, so commented-out code and prose never match.
A hit in debug-only code (`if (BuildConfig.DEBUG)`, `#if DEBUG`, `if (kDebugMode)`) or in a file that
imports a test framework is reported with that scope, so it is lowered rather than dropped.
"""

from __future__ import annotations

import bisect
import itertools
import re
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

from masaudit import safety
from masaudit.guards import debug_guarded, preprocessor_debug_guarded
from masaudit.textscan import _raw_index, bracket_match, finditer_lit, holds_any, text_memo, xml_tags
from masaudit.detect import scope_of as _scope_of
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.detectors import reactnative as rn


_SCOPES: Dict[str, str] = {}


def scope_of(path: str) -> str:
    """detect.scope_of, memoised: detectors ask it about the same paths many times per scan."""
    s = _SCOPES.get(path)
    if s is None:
        if len(_SCOPES) >= 200_000:
            _SCOPES.clear()
        s = _SCOPES[path] = _scope_of(path)
    return s


CODE = (".kt", ".java", ".swift", ".m", ".mm", ".h", ".dart")
JVM = (".kt", ".java")
APPLE = (".swift", ".m", ".mm", ".h")
DART = (".dart",)
JS = rn.JS                              # React Native JavaScript and TypeScript, read only in RN projects


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
    r"io\.kotest|androidx\.test)\b|import[ \t]+['\"]package:(?:flutter_test|test|mockito|mocktail)/"
    r"|import\b[^\n]{0,200}?\bfrom[ \t]+['\"](?:@testing-library/[\w-]+|@jest/globals|vitest|detox|react-test-renderer)['\"])",
    re.MULTILINE,
)


def _has_test_import(text: str) -> bool:
    """bool(_TEST_IMPORT.search(text)), without trying the pattern at every offset: a match starts at the
    start of a line holding `import` (every alternative contains it, on the same line), so only those
    line starts are tried."""
    seen = -1                                  # offset of the previous `import`; -1 before the first
    i = text.find("import")
    while i >= 0:
        nl = text.rfind("\n", max(seen, 0), i)   # only the text since the previous `import`: linear overall
        if nl >= 0 or seen < 0:                  # a line not tried yet
            if _TEST_IMPORT.match(text, nl + 1):
                return True
        seen = i
        i = text.find("import", i + 1)
    return False


def _test_file(ctx: Context, path: str) -> bool:
    """_has_test_import on the file's raw text, once per file (it was asked again for every hit)."""
    cache = getattr(ctx, "_xpl_test_file", None)
    if cache is None:
        cache = ctx._xpl_test_file = {}  # type: ignore[attr-defined]
    if path not in cache:
        cache[path] = _has_test_import(ctx.text(path) or "")
    return cache[path]


# Gradle source sets of internal, QA, or staging flavors don't ship to users.
_NON_RELEASE_SOURCE_SET = re.compile(r"/src/(?:internal|qa|staging|dev|develop|uat)(?:Debug|Release)?/")


def _hit_scope(ctx: Context, path: str, idx: int, blank: Optional[str] = None) -> str:
    """'test' for a test-framework file, 'debug' under a debug-only guard, else '' (path decides)."""
    if _test_file(ctx, path):
        return "test"
    if blank is None:
        blank = ctx.code(path, keep_strings=False) or ""
    if debug_guarded(path, blank, idx) or _NON_RELEASE_SOURCE_SET.search("/" + path):
        return "debug"
    if path.endswith(JS) and js_dev_guarded(ctx.code(path) or "", blank, idx):
        return "debug"
    return ""


# ---------------------------------------------------------------------------- React Native: __DEV__

def js_dev_guarded(code: str, blank: str, idx: int) -> bool:
    """Whether offset idx of a JavaScript/TypeScript file runs only in development builds (reactnative.DevGuard:
    `if (__DEV__)`, NODE_ENV checks, `__DEV__ &&`, the first branch of `__DEV__ ?`, early returns)."""
    return rn.in_dev(code, blank, idx)


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
    h = h[:m.start()].rstrip() if m else h        # `throws` may sit on its own line
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


# [text, {question: answer}] for the last few texts: a whole-file search that a rule repeats for every hit
# (is this name a constant, where is it declared) is answered once per file.
def _enclosing_function(blank: str, idx: int, path: str) -> Tuple[int, int, str]:
    """(body start, body end, head text) of the innermost function around `idx`, or the whole file."""
    blocks = _blocks_of(blank, path)
    if blocks is not None:
        return blocks.enclosing_function(idx)
    return _enclosing_function_scan(blank, idx, path)


class _Blocks:
    """The `{ }` blocks of one text, for answering _enclosing_function about many offsets in it: the walk
    back from each offset was a pass over the file per hit. A `{` the backward walk finds unmatched is
    exactly a `{` still open at `idx` when braces are paired forwards (a `}` with nothing open is
    ignored), so the open blocks at each brace, innermost first, give the same answer."""

    def __init__(self, blank: str, path: str):
        self.blank, self.path = blank, path
        self.events: List[int] = []           # offsets of every { and }
        self.tops: List[int] = []             # the innermost open { after each event, or -1
        self.parent: dict = {}                # { -> the { open around it, or -1
        stack: List[int] = []
        for m in re.finditer(r"[{}]", blank):
            i = m.start()
            if blank[i] == "{":
                self.parent[i] = stack[-1] if stack else -1
                stack.append(i)
            elif stack:
                stack.pop()
            self.events.append(i)
            self.tops.append(stack[-1] if stack else -1)
        self.owner: dict = {}                 # { -> the innermost function { at or around it, or -1
        self.answer: dict = {}                # function { -> (start, end, head)

    def _head(self, i: int) -> str:
        head = self.blank[max(0, i - 400):i]
        cut = max(head.rfind(";"), head.rfind("}"), head.rfind("{"))
        return head[cut + 1:]

    def enclosing_function(self, idx: int) -> Tuple[int, int, str]:
        k = bisect.bisect_left(self.events, idx) - 1     # events before idx
        brace = self.tops[k] if k >= 0 else -1
        chain = []
        while brace >= 0 and brace not in self.owner:
            chain.append(brace)
            if _is_function_head(self._head(brace), self.path):
                self.owner[brace] = brace
                break
            brace = self.parent[brace]
        found = self.owner.get(brace, -1) if brace >= 0 else -1
        for b in chain:
            self.owner[b] = found
        if found < 0:
            return 0, len(self.blank), ""
        if found not in self.answer:
            self.answer[found] = (found, bracket_match(self.blank, found, "{", "}"), self._head(found))
        return self.answer[found]


# The texts _enclosing_function was last asked about: (text, path, _Blocks or None until a second question).
_BLOCKS: List[list] = []


def _blocks_of(blank: str, path: str) -> Optional[_Blocks]:
    for entry in _BLOCKS:
        if entry[0] is blank and entry[1] == path:
            if entry[2] is None:
                entry[2] = _Blocks(blank, path)
            return entry[2]
    _BLOCKS.insert(0, [blank, path, None])
    del _BLOCKS[4:]
    return None


def _enclosing_function_scan(blank: str, idx: int, path: str) -> Tuple[int, int, str]:
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
                return i, bracket_match(blank, i, "{", "}"), head
    return 0, len(blank), ""


# An annotation or attribute with arguments (`@Throws(X::class)`, `@objc(name:)`, `@available(iOS 13, *)`).
_ANNOTATION_ARGS = re.compile(r"[@#][\w.]+\s*\((?:[^()]|\([^()]*\))*\)")


def _function_name(head: str) -> str:
    # An annotation's `(` before the declaration isn't the parameter list: `@Throws(…) fun f(` is f.
    head = _ANNOTATION_ARGS.sub(lambda a: " " * len(a.group()), head)
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
    if len(code) < 8192:
        start = code.rfind("\n", 0, idx) + 1
        end = code.find("\n", idx)
        return start, (len(code) if end < 0 else end)
    # A long text: its newline offsets once, then a binary search per call (rfind from each call on a long
    # line walked back to the line's start every time).
    newlines = text_memo(code, ("newlines",), lambda: [m.start() for m in re.finditer("\n", code)])
    k = bisect.bisect_left(newlines, idx)
    return (newlines[k - 1] + 1 if k else 0), (newlines[k] if k < len(newlines) else len(code))


# Patterns whose every match starts with one of the listed literals (checked alternative by alternative),
# so _finditer can jump between occurrences of those literals instead of trying every offset.
_STARTS: Dict[Pattern[str], Tuple[str, ...]] = {}


def _finditer(rx: Pattern[str], text: str) -> Iterator["re.Match[str]"]:
    """rx.finditer(text), sped up for patterns listed in _STARTS."""
    starts = _STARTS.get(rx)
    return finditer_lit(rx, text, starts) if starts else rx.finditer(text)


def _scan(ctx: Context, rule_patterns: Sequence[Tuple[Pattern[str], str]], suffixes: Tuple[str, ...] = CODE,
          keep_strings: bool = True, prefilter: Sequence[str] = (),
          mask_group: Optional[int] = None) -> Iterable[Hit]:
    """Run (regex, message) pairs over code; at most one hit per line."""
    for path in ctx.files(*suffixes):
        if prefilter:
            if not holds_any(ctx, path, prefilter):
                continue
        elif ctx.text(path) is None:
            continue
        code = ctx.code(path, keep_strings=keep_strings)
        if code is None:
            continue
        seen: Set[int] = set()
        for regex, message in rule_patterns:
            for m in _finditer(regex, code):
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
    for path in ctx.files(*CODE) + _rn_secret_files(ctx, config=True):
        if not holds_any(ctx, path, ("PRIVATE KEY", "AKIA", "ASIA", "sk-", "k_live_", "ghp_", "gho_", "ghu_", "ghs_",
                                     "ghr_", "github_pat_", "xox")):
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
    if rn.is_react_native(ctx):
        for hit in _scan(ctx, [(GOOGLE_KEY, msg)], suffixes=JS, prefilter=("AIza",), mask_group=0):
            if hit.path in _rn_js_set(ctx):
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
    yield from _c_define_secrets(ctx)
    yield from _js_secret_assignment(ctx)


# C and Objective-C: `#define VENDORKEY "olsdfgad;lh"`.
C_DEFINE_SECRET = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+(\w*(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|KEY|Secret|Password|"
                             r"Passphrase|Key))[ \t]+@?\"([^\"\s]{6,})\"")
# A define that names a key's location or label, not the key.
_DEFINE_LABEL = {"name", "file", "filename", "path", "url", "uri", "tag", "id", "pref", "prefs", "notification",
                 "defaults", "header", "field", "param", "column", "table", "dir", "ext", "type", "attr", "attribute",
                 "keychain", "service", "account", "label", "length", "len", "size", "public"}


def _c_define_secrets(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, (".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hpp"), ("define",)):
        for m in C_DEFINE_SECRET.finditer(code):
            name, value = m.group(1), m.group(2)
            if _identifier_words(name) & _DEFINE_LABEL or not _real_secret_value(value, name) or \
                    re.search(r"\.[A-Za-z]{2,4}$|^[a-z]+://|/", value):
                continue
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, _mask_in(ctx.snippet(path, line), value),
                      f"`{name}` is defined as a literal value, so it ships inside the app.",
                      _hit_scope(ctx, path, m.start(), blank))


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
    yield from _js_ecb(ctx)


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
        for decl in text_memo(code, ("decls", pat), lambda pat=pat: list(re.finditer(pat, code))):
            in_function = start <= decl.start() < end
            if not in_function:
                if idx < 0:
                    in_function = True
                elif _enclosing_function(blank, decl.start(), path)[2]:
                    continue                 # declared inside another function
            local = in_function and idx >= 0          # the function is the scope; else the whole file
            init = decl.group(1)
            if re.match(r"ByteArray\(|new\s+byte\s*\[\s*\d", init):
                stmt_end = code.find("\n", decl.end())
                stmt = code[decl.end():stmt_end if stmt_end >= 0 else len(code)]
                if re.match(r"\s*\)?\s*\.\s*(?:also|apply)\s*\{[^}]*nextBytes", stmt):
                    return False
                # Once per declaration and scope: at file level the scope is the whole file.
                key = ("filled", name, decl.start(), decl.end(), local, start, end)
                if text_memo(code, key, lambda d=decl, local=local: _filled_in_scope(
                        code[start:end] if local else code, code[d.start():d.end()], name)):
                    return False
            return True
    return False


def _filled_in_scope(scope_text: str, decl_text: str, name: str) -> bool:
    """The buffer declared by `decl_text` is filled (or a secure source is used) elsewhere in its scope."""
    return bool(_filled(scope_text.replace(decl_text, "", 1), name)
                or re.search(r"getSecretBytes|SecureRandom", scope_text))


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
            if line in seen:
                continue
            if not _var_is_literal(code, m.group(1), m.start(), path, blank):
                for call in _literal_arg_callers(code, blank, m.group(1), m.start(), path):
                    call_line = ctx.line_of(code, call)  # a helper whose callers in this file pass a fixed IV
                    if call_line not in seen:
                        seen.add(call_line)
                        yield Hit(path, call_line, _mask_literals(ctx.snippet(path, call_line)),
                                  msg[:-1] + "; it reaches the cipher through a helper in this file.",
                                  _hit_scope(ctx, path, call, blank))
                continue
            seen.add(line)
            if _per_message_key(code, blank, m.start(), path):
                continue
            yield Hit(path, line, ctx.snippet(path, line), msg, _hit_scope(ctx, path, m.start(), blank))
    for hit in _scan(ctx, [(SWIFT_NONCE, msg)], suffixes=(".swift",), prefilter=("Nonce(", "iv:")):
        yield hit
    for hit in _scan(ctx, [(DART_IV, msg)], suffixes=DART, prefilter=("IV",)):
        yield hit
    yield from _js_static_iv(ctx)


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
_STARTS.update({
    WEAK_HASH[0][0]: ("MessageDigest",), WEAK_HASH[1][0]: ("Insecure",), WEAK_HASH[2][0]: ("CC_",),
    WEAK_HASH[3][0]: ("DigestUtils",), WEAK_HASH[4][0]: ("Hashing",),
    WEAK_HASH_DART[0][0]: ("md5", "sha1"), WEAK_HASH_DART[1][0]: ("MD5", "SHA1", "Digest"),
})
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
            if not holds_any(ctx, path, ("MD5", "SHA1", "SHA-1", "md5", "sha1")):
                continue
            code = ctx.code(path, keep_strings=True) or ""
            blank = ctx.code(path, keep_strings=False) or ""
            seen: Set[int] = set()
            for regex, what in pats:
                for m in _finditer(regex, code):
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
    yield from _js_weak_hash(ctx)


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
# The literals each generator pattern's matches start with, for finditer_lit ("rand" also starts "random").
_RNG_STARTS = {
    RNG_JVM[0][0]: ("java.util.Random",), RNG_JVM[1][0]: ("kotlin.random.Random",), RNG_JVM[2][0]: ("Math.random",),
    RNG_JVM[3][0]: ("setSeed",), RNG_IMPORTED_USE: ("Random", "new"), RNG_SEEDED_SECURE: ("SecureRandom",),
    RNG_APPLE[0][0]: ("rand", "drand48", "lrand48"), RNG_APPLE[1][0]: ("srand",), DART_RANDOM: ("Random",),
}
# A literal every match of each RNG_IMPORTS pattern contains.
_RNG_IMPORT_NEEDLES = ("java.util.", "kotlin.random.")
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
    # The line's own words are the same for every call on it: worked out once per line, so a one-line file
    # with thousands of calls isn't rescanned per call.
    line_words, line_idents = text_memo(blank, ("rng_line", s), lambda: (
        _identifier_words(blank[s:e]), {i.lower() for i in re.findall(r"[A-Za-z_]\w*", blank[s:e])}))
    rest = _declaration(head) + " " + call
    words = set(line_words) | _identifier_words(rest)
    if _RNG_NON_SECURITY_PATH.search("/" + path):
        words.add("analytics")
    idents = set(line_idents) | {i.lower() for i in re.findall(r"[A-Za-z_]\w*", rest)}
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


_RNG_ASSIGNED = re.compile(r"\b([A-Za-z_]\w*)\s*(?::\s*[\w.]+\??)?\s*=\s*(?:java\.util\.|kotlin\.random\.)?$")


def _rng_variable_uses(code: str, line_start: int, idx: int, path: str, followed: Set[tuple]) -> List[int]:
    """When the generator made at `idx` is assigned to a variable (`val random = Random()`), the offsets
    of each `random.next…(` in its function, or in the file for a field."""
    m = _RNG_ASSIGNED.search(code[line_start:idx])
    if not m:
        return []
    start, end, _head = _enclosing_function(code, idx, path)

    def uses_by_name() -> Dict[str, List[int]]:     # one pass per scope, however many generators it makes
        found: Dict[str, List[int]] = {}
        for u in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*next\w*\s*\(", code[start:end]):
            found.setdefault(u.group(1), []).append(start + u.start())
        return found
    if (m.group(1), start, end) in followed:
        return []                             # this name in this scope was followed already
    followed.add((m.group(1), start, end))
    return text_memo(code, ("rng_uses", start, end), uses_by_name).get(m.group(1), [])


@detector("xpl_insecure_random")
def insecure_random(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*JVM):
        raw = ctx.text(path) or ""
        if "Random" not in raw and "random" not in raw and "setSeed" not in raw:
            continue
        code = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in finditer_lit(RNG_SEEDED_SECURE, code, _RNG_STARTS[RNG_SEEDED_SECURE]):
            line = ctx.line_of(code, m.start())
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), "A SecureRandom seeded by the caller.",
                      _hit_scope(ctx, path, m.start(), code))
        pats = list(RNG_JVM)
        followed: Set[tuple] = set()      # (variable, scope) pairs whose uses were judged
        for (imp, message), needle in zip(RNG_IMPORTS, _RNG_IMPORT_NEEDLES):
            if needle in code and imp.search(code):
                pats.append((RNG_IMPORTED_USE, message))
                break
        for regex, message in pats:
            for m in finditer_lit(regex, code, _RNG_STARTS[regex]):
                if regex.pattern.startswith(r"\bsetSeed") and "Random" not in code:
                    continue
                s, _e = _line_span(code, m.start())
                if re.match(r"\s*import\b", code[s:m.start()]):
                    continue                   # `import kotlin.random.Random.Default.nextInt`
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                words = _rng_security_words(code, m.start(), path)
                # Tests seed a plain generator for repeatable data; their uses are not followed.
                uses = [] if words or regex is RNG_JVM[2][0] or scope_of(path) == "test" or \
                    _test_file(ctx, path) else _rng_variable_uses(code, s, m.start(), path, followed)
                for use in uses:               # `val random = Random()`, then `random.nextInt(...)` per use
                    use_line = ctx.line_of(code, use)
                    use_words = [] if use_line in seen else _rng_security_words(code, use, path)
                    if use_words:
                        seen.add(use_line)
                        yield Hit(path, use_line, ctx.snippet(path, use_line),
                                  f"{message[:-1]}, and it produces a `{use_words[0]}`.", _hit_scope(ctx, path, use, code))
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
            for m in finditer_lit(regex, code, _RNG_STARTS[regex]):
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
        for m in finditer_lit(DART_RANDOM, code, _RNG_STARTS[DART_RANDOM]):
            line = ctx.line_of(code, m.start())
            words = _rng_security_words(code, m.start(), path)
            if line in seen or not words:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"dart:math `Random()` is predictable, and it produces a `{words[0]}`.",
                      _hit_scope(ctx, path, m.start(), code))
    yield from _js_insecure_random(ctx)


# ---------------------------------------------------------------------------- XPL-009

HTTP_URL = re.compile(r"[\"']http://([^\"'\s/?#]*)")
DART_URI_HTTP = re.compile(r"\bUri\s*\.\s*http\s*\(\s*[\"']([^\"'\s/?#]*)")
_PORT = r"(?::(?:\d+|\$\{[^}]*\}|\$\w+|\\\([^)]*\)|%\w))?"
SAFE_HOSTS = re.compile(
    r"^(?:localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\[::1\]|"
    r"(?:[\w-]+\.)*example\.(?:com|org|net)|schemas\.android\.com|schemas\.xmlsoap\.org|"
    r"schemas\.microsoft\.com|www\.w3\.org|w3\.org|ns\.adobe\.com|ns\.apple\.com|www\.apple\.com|purl\.org|"
    r"maps\.apple\.com|"                       # Apple's documented Maps link: iOS opens the Maps app
    r"xmlpull\.org|(?:www\.)?itunes\.com|search\.yahoo\.com|podlove\.org|"
    r"ns\.(?:[\w-]+\.)+[a-z]{2,}|"               # XML and XMP namespace names (ns.google.com/photos/1.0/)
    # Captive-portal checks are plain HTTP by design: the OS and VPN clients look for the redirect.
    r"captive\.apple\.com|connectivitycheck\.(?:gstatic|android)\.com|clients[13]\.google\.com|"
    r"cp\.cloudflare\.com|detectportal\.firefox\.com|(?:www\.)?msftconnecttest\.com|"
    r"(?:[\w-]+\.)*(?:localhost|test|invalid|local))" + _PORT + "$",
    re.IGNORECASE,
)
PLACEHOLDER_HOST = re.compile(
    r"^(?:www\.)?(?:domain|mydomain|myserver|yourserver|your-server|server|host|hostname|foo|bar|local-ip|"
    r"ip-address|ip|address|example|not[.-]?required|not[.-]?set|change[.-]?me|replace[.-]?me|placeholder|todo)"
    r"(?:\.(?:com|org|net|tld))?" + _PORT + "$", re.IGNORECASE)
# Private address ranges are XPL-036's job (non-production endpoints).
PRIVATE_IP = re.compile(r"^(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)" + _PORT + "$")
_NOT_A_FETCH = {"ns", "nsuri", "namespace", "namespaces", "xmlns", "dtd", "license", "licenses", "placeholder",
                "hint", "prefix", "prefixes", "schema", "referer", "referrer", "library", "libraries", "homepage"}


# The URL is opened in the user's browser (a help link), not fetched by the app.
_BROWSER_OPEN = re.compile(r"\b(?:launchUri|launchUrl|launchUrlString|launchBrowser|openInBrowser|openBrowser|"
                           r"openExternal\w*|openUri|openURL|openUrl)\s*\(|\bIntent\s*\.\s*ACTION_VIEW\b|"
                           r"\bACTION_VIEW\b|\bCustomTabsIntent\b|\bUIApplication\s*\.\s*shared\s*\.\s*open\s*\(|"
                           r"\bSFSafariViewController\s*\(|\buriHandler\s*\.\s*openUri\b")


# A scheme constant (`String protocol = "http://"`) that URLs are built from.
HTTP_SCHEME_CONST = re.compile(r"\b([A-Za-z_]\w*)\s*(?::\s*String\??)?\s*=\s*@?\"http://\"")


_CONCAT_USE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\+\s*(?:this\s*\.\s*)?[A-Za-z_]")


_TYPE_DECL = re.compile(r"\b(?:class|object|enum|struct|interface|extension)\s+([A-Za-z_]\w*)")
_NAMESPACE_WORDS = {"namespace", "namespaces", "ns", "xmlns", "xmp", "schema", "schemas", "uri", "uris"}


def _in_namespace_type(blank: str, pos: int) -> bool:
    """Inside the body of a type named for namespace URIs (XmpNamespaces, XmlNs, SchemaUris): identifiers, not
    fetches. Types and their bodies come from one pass over the file; nested types are checked outward."""
    def build() -> List[Tuple[int, int, str]]:
        out = []
        for m in _TYPE_DECL.finditer(blank):
            brace = blank.find("{", m.end(), m.end() + 300)
            end = bracket_match(blank, brace, "{", "}") if brace != -1 else m.end()
            out.append((m.start(), end, m.group(1)))
        return out
    decls = text_memo(blank, ("xpl_type_decls",), build)
    k = bisect.bisect_left(decls, (pos,)) - 1  # type: ignore[arg-type]
    steps = 0                                  # bounded: past 64 closed types, report as before (no skip)
    for _ in range(8):                         # the nearest enclosing types, innermost first
        while k >= 0 and decls[k][1] < pos and steps < 64:  # type: ignore[index]
            k -= 1
            steps += 1
        if steps >= 64:
            return False
        if k < 0:
            return False
        if _identifier_words(decls[k][2]) & _NAMESPACE_WORDS:  # type: ignore[index]
            return True
        k -= 1
    return False


@detector("xpl_http_url")
def http_url(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        if scope_of(path) in ("test", "build-script"):
            continue                         # tests and build tooling never ship
        raw = ctx.text(path)
        is_dart = path.endswith(".dart")
        if raw is None or not ("http://" in raw or (is_dart and "Uri.http" in raw)) or _has_test_import(raw):
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
            if re.match(r"[^\"'\s]*/generate_204\b", code[m.end():m.end() + 80]):
                continue                     # a connectivity check, plain HTTP by design (generate_204)
            if _in_namespace_type(blank, m.start()):
                continue                     # class XmpNamespaces { static const gImage = 'http://...' }
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
        # The scheme-constant regex has no literal to anchor on; run it only where the bare scheme is.
        names = set(HTTP_SCHEME_CONST.findall(code)) if '"http://"' in code else set()
        # `String protocol = "http://"`, then `new HttpPost(protocol + serverip + ...)`. One pass over the file for
        # every `name + identifier`, kept when the name holds the scheme (a pass per name is quadratic).
        for use in (_CONCAT_USE.finditer(blank) if names else ()):
            name = use.group(1)
            if name in names:
                line = ctx.line_of(code, use.start())
                if line not in seen:
                    seen.add(line)
                    yield Hit(path, line, ctx.snippet(path, line), f"A URL is built from `{name}`, which holds "
                              "`http://`, so the request goes out in plain HTTP.",
                              _hit_scope(ctx, path, use.start(), blank))
    yield from _js_http_url(ctx)


# ---------------------------------------------------------------------------- XPL-010

LOG_CALL = re.compile(
    r"(?<![\w.])(?:Log\.(?:v|d|i|w|e|wtf)|Timber\.(?:v|d|i|w|e|wtf)|System\.(?:out|err)\.print(?:ln|f)?|"
    r"println|print|debugPrint|NSLog|os_log)\s*\("
)
DART_LOG_CALL = re.compile(r"(?<![\w.])(?:print|debugPrint|debugPrintSynchronously|log|developer\.log)\s*\(")
# The literals each log-call match starts with (`print` also starts `println`, `debugPrint` also starts
# `debugPrintSynchronously`); every match therefore contains one of them.
_STARTS[LOG_CALL] = ("Log.", "Timber.", "System.", "print", "debugPrint", "NSLog", "os_log")
_STARTS[DART_LOG_CALL] = ("print", "debugPrint", "log", "developer.")
SENSITIVE_WORD = re.compile(r"(?i)token|passw(?:or)?d|passwd|secret|authorization|bearer|card_?number|credit_?card|"
                            r"(?<![a-z])cvv|(?<![a-z])cvc(?![a-z])")
# A log message that labels the value it prints as card data: "... credit card: " + field.getText().
CARD_LABEL = re.compile(r"(?i)(?:credit|debit)\s*card|card\s*(?:number|no\b)|\bcvv\b|\bcvc\b")
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
    if re.match(r"k[A-Z]|(?i:option)", secret_part):
        return False                  # a constant naming an option (`$kOptionAllowDeepLinkPassword`), not its value
    if _SAFE_SUFFIX.search(e) or _WRAPPED.search(before):
        return False
    if re.search(r"\bR\.string\.\w*$|getString\s*\(\s*R\.string\.\s*$", before + head):
        return False                  # an Android string resource ID, not a value
    if re.search(r"(?:\.\s*|\b)(?:get|Get)[A-Z]\w*Id\s*\(\s*\)$", e):
        return False
    return True


def _labelled_card_values(full: str, bare: str, open_at: int, close: int) -> List[str]:
    """Values concatenated right after a literal that names card data (`"credit card: " + cc.getText()`)."""
    out = []
    for lit in re.finditer(r"\"([^\"\n]*)\"\s*\+\s*([A-Za-z_][\w.]*(?:\(\s*\))?(?:\.[\w]+(?:\(\s*\))?)*)",
                           full[open_at:close]):
        expr = lit.group(2)
        if CARD_LABEL.search(lit.group(1)) and not _NON_SECRET_ANYWHERE.search(expr) and not _SAFE_SUFFIX.search(expr) \
                and not expr.isupper() and not re.search(r"(?i)message|stacktrace|getenv", expr):
            out.append(expr)
    return out


# `user["password"] = …` or `user.password = …`: the object now holds a secret. The member is captured once and
# checked in Python; a pattern per logged name with `\w*password\w*` inside backtracks over the whole window.
_MEMBER_ASSIGN = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*(?:\[\s*\"([^\"\n]*)\"\s*\]|\.\s*(\w+))\s*=(?!=)")
_SECRET_KEY = re.compile(r"password|passwd|token|secret")
_SECRET_MEMBER = re.compile(r"[Pp]assword|[Tt]oken|[Ss]ecret")


def _objects_holding_secrets(full: str, bare: str, open_at: int, close: int, path: str) -> List[str]:
    """Whole objects logged (`\\(user)`, `user.description`, `"$user"`) after the same function stored a
    password or token in them."""
    exprs = [next(x for x in g.groups() if x is not None) for g in INTERP.finditer(full[open_at:close])]
    exprs += re.findall(r"(?<![\w.\"])([A-Za-z_]\w*(?:\.(?:description|debugDescription|toString\(\s*\)))?)\s*[,)]",
                        bare[open_at:close + 1])
    out = []
    holders: Optional[Set[str]] = None
    for expr in exprs:
        m = re.fullmatch(r"\s*([A-Za-z_]\w*)(?:\s*\.\s*(?:description|debugDescription|toString\(\s*\)))?\s*", expr)
        if not m or SENSITIVE_WORD.search(m.group(1)):
            continue                          # a sensitive name is the other check's job
        if holders is None:                   # the function, at most the 4,000 characters before the call
            start = max(_enclosing_function(bare, open_at, path)[0], open_at - 4000)
            holders = {a.group(1) for a in _MEMBER_ASSIGN.finditer(full, start, open_at)
                       if (a.group(2) is not None and _SECRET_KEY.search(a.group(2)))
                       or (a.group(3) is not None and _SECRET_MEMBER.search(a.group(3)))}
        if m.group(1) in holders:
            out.append(m.group(1))
    return out


@detector("xpl_sensitive_log")
def sensitive_log(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE):
        log_call = DART_LOG_CALL if path.endswith(".dart") else LOG_CALL
        if not holds_any(ctx, path, _STARTS[log_call]):
            continue                                        # no log call in the file
        low = ctx.lower(path)
        # Every SENSITIVE_WORD match contains one of these (passw covers passw(or)d and passwd).
        if low is None or not any(w in low for w in ("token", "passw", "secret", "authorization", "bearer", "card",
                                                     "cvv", "cvc")):
            continue
        bare = ctx.code(path, keep_strings=False) or ""     # string contents blanked
        full = ctx.code(path, keep_strings=True) or ""      # same offsets, strings kept
        seen: Set[int] = set()
        lexical: Optional[bool] = None          # _LEXICAL_TOKEN_FILE.search(bare), once per file
        for m in _finditer(log_call, bare):
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
            names += _labelled_card_values(full, bare, open_at, close)
            names += _objects_holding_secrets(full, bare, open_at, close, path)
            if names and all(n in ("token", "tokens") for n in names):
                if lexical is None:
                    lexical = bool(_LEXICAL_TOKEN_FILE.search(bare))
                if lexical:
                    continue
            if not names:
                continue
            line = ctx.line_of(bare, m.start())
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), f"`{names[0]}` is written to the log.",
                      _hit_scope(ctx, path, m.start(), bare))
    yield from _js_sensitive_log(ctx)


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
    return text_memo(code, ("string_constant", name), lambda: bool(re.search(
        r"\b(?:val|var|let|String|final\s+String|static\s+final\s+String)?\s*\b" + re.escape(name)
        + r"\s*(?::\s*String)?\s*=\s*\"[^\"\n]+\"", code)))


# A key made from a variable: `SecKeyCreateWithData(privateKeyData as CFData, …)`,
# `P256.Signing.PrivateKey(rawRepresentation: privateKeyData)`, `SymmetricKey(data: keyData)`.
SWIFT_KEY_FROM_VAR = re.compile(
    r"\bSecKeyCreateWithData\(\s*([A-Za-z_]\w*)\s*(?:as\s+CFData\s*)?,"
    r"|\b(?:P256|P384|P521|Curve25519)\.(?:Signing|KeyAgreement)\.PrivateKey\(\s*rawRepresentation:\s*([A-Za-z_]\w*)\s*\)"
    r"|\bSymmetricKey\(\s*data:\s*([A-Za-z_]\w*)\s*\)")
# RNCryptor with a literal password: Swift `password: "…"`/`withPassword: "…"`, Objective-C `password:@"…"`.
RNCRYPTOR_PASSWORD = re.compile(r"\bRN(?:En|De)cryptor\b[^;\n]{0,200}?\b(?:withPassword|password)\s*:\s*@?\"([^\"\n]{4,})\"")


def _swift_literal_bytes(code: str, blank: str, name: Optional[str], idx: int, path: str, depth: int = 0) -> bool:
    """Is the Swift variable `name` a byte-array, base64, or string literal, directly or through
    `Data(otherName)`? Looked for in the function around `idx`, then in the file."""
    if not name or depth > 2:
        return False
    start, end, _head = _enclosing_function(blank, idx, path)
    decl = re.compile(r"\b(?:let|var)\s+" + re.escape(name) + r"\s*(?::\s*[\w\[\]]+)?\s*=\s*")
    m = decl.search(code, start, end) or text_memo(code, ("swift_decl", name), lambda: decl.search(code))
    if not m:
        return False
    init = code[m.end():m.end() + 200]
    if re.match(r"\[\s*(?:0x[0-9A-Fa-f]+|\d+)\s*,(?:\s*(?:0x[0-9A-Fa-f]+|\d+)\s*,){14}|Data\(\s*\[\s*(?:0x|\d)|"
                r"Data\(\s*base64Encoded:\s*\"|\"[^\"\n]{16,}\"\s*\.data\(|Data\(\s*\"[^\"\n]{16,}\"\.utf8", init):
        return True
    inner = re.match(r"Data\(\s*([A-Za-z_]\w*)\s*\)", init)
    return bool(inner) and _swift_literal_bytes(code, blank, inner.group(1), m.start(), path, depth + 1)


def _param_index(head: str, name: str) -> int:
    """Position of parameter `name` in a Java or Kotlin function head, or -1."""
    open_paren = head.rfind("(", 0, head.rfind(")") + 1) if ")" in head else -1
    if open_paren < 0:
        return -1
    params = head[open_paren + 1:head.rfind(")")]
    for i, p in enumerate(params.split(",")):
        if re.search(r"(?:^|\s)" + re.escape(name) + r"\s*(?::|$)", p.strip()):
            return i
    return -1


_CALL_SITE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*)\s*\(")
# A declaration, not a call: `fun f(`, `func f<T>(`, `fun Type.f(`; or Java's `Type f(…) {` / `throws`, with the
# type on the same line (a word before a call on the same line is a keyword such as `return`).
_KEYWORD_LAST = re.compile(r"(?<![\w$])(?:fun|func|def|function)$")
_DECLARED_BY_KEYWORD = re.compile(r"\b(?:fun|func|def|function)\s+(?:<[^<>{}]{0,200}>\s*)?(?:[\w.?<>]{1,200}\.)?$")
_NOT_A_TYPE = {"return", "new", "else", "throw", "case", "await", "yield", "in", "is", "as", "try", "do", "not", "and",
               "or", "typeof", "delete", "void", "of"}
_JAVA_BODY = re.compile(r"\((?:[^()]|\([^()]{0,400}\)){0,400}\)\s*(?:throws\b|\{)")


def _declares(blank: str, start: int, paren: int) -> bool:
    before = blank[max(0, start - 300):start]
    tail = before.rstrip()
    if not tail or not (tail[-1].isalnum() or tail[-1] in "_$>]"):
        return False                          # `(f(`, `= f(`, `, f(`: most calls stop here
    if _KEYWORD_LAST.search(tail[-9:]) or (tail[-1] == ">" and _DECLARED_BY_KEYWORD.search(tail[-250:] + " ")):
        return True
    gap = before[len(tail):]
    if not gap or "\n" in gap:
        return False                          # the type, if any, is on the same line, one space or more before
    word = re.search(r"(\w+)$", tail[-60:])
    return not (word and word.group(1) in _NOT_A_TYPE) and bool(_JAVA_BODY.match(blank, paren))


def _call_sites(blank: str) -> Dict[str, List[Tuple[int, int, bool]]]:
    """name -> [(start, offset of its `(`, called on a receiver)] for every call in the text, built once per text:
    a regex per helper over the whole file is quadratic when a file declares thousands of helpers. Declarations
    of a function (`fun f(`, Java's `int f(…) {`) are left out."""
    def build() -> Dict[str, List[Tuple[int, int, bool]]]:
        sites: Dict[str, List[Tuple[int, int, bool]]] = {}
        for m in _CALL_SITE.finditer(blank):
            dotted = m.start() > 0 and blank[m.start() - 1] == "."
            if not dotted and _declares(blank, m.start(), m.end() - 1):
                continue
            sites.setdefault(m.group(1), []).append((m.start(), m.end() - 1, dotted))
        return sites
    return text_memo(blank, ("call_sites",), build)


def _literal_arg_callers(code: str, blank: str, name: str, idx: int, path: str) -> List[int]:
    """`SecretKeySpec(keyBytes, …)` or `IvParameterSpec(ivBytes)` where the argument is a parameter of the
    enclosing function: the offsets of the calls in the same file that pass a literal there, directly or
    as `keyString.getBytes()` of a string constant."""
    start, _end, head = _enclosing_function(blank, idx, path)
    pos = _param_index(head, name)
    fn = _function_name(head)
    if pos < 0 or not fn:
        return []
    return text_memo(code, ("key_callers", fn, pos, start),
                     lambda: _literal_arg_calls(code, blank, fn, pos, start - len(head), start, path))


def _literal_arg_calls(code: str, blank: str, fn: str, pos: int, decl_start: int, decl_end: int,
                       path: str) -> List[int]:
    out = []
    for call_start, paren, _dotted in _call_sites(blank).get(fn, []):
        if decl_start <= call_start < decl_end:
            continue                          # the declaration itself
        args = _args_of(blank, paren)
        if len(args) <= pos:
            continue
        arg = code[args[pos][0]:args[pos][1]].strip()
        lit = re.match(r"\"[^\"\n]+\"\s*\.\s*(?:getBytes|toByteArray|encodeToByteArray)\s*\(", arg)
        var = re.fullmatch(r"([A-Za-z_]\w*)", arg)
        if not lit and var:
            n = re.escape(var.group(1))
            if _var_is_literal(code, var.group(1), call_start, path, blank) or re.search(
                    r"(?:byte\s*\[\s*\]\s*" + n + r"|\b(?:val|var)\s+" + n + r"(?:\s*:\s*ByteArray)?)\s*=\s*"
                    r"(?:\{|byteArrayOf\()", code[max(0, call_start - 3000):call_start]):
                # (the second test: a literal in the enclosing function of an inner listener or lambda)
                lit = var
            else:
                c_start, _c_end, _c_head = _enclosing_function(blank, call_start, path)
                src = re.search(r"\b" + re.escape(var.group(1)) + r"\s*=\s*(?:this\.)?([A-Za-z_]\w*)\s*\.\s*"
                                r"(?:getBytes|toByteArray|encodeToByteArray)\s*\(", code[c_start:call_start])
                lit = src if src and _string_constant(code, src.group(1)) else None
        if lit:
            out.append(call_start)
    return out


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
        for m in KEY_CALL_VAR.finditer(code):
            for call in _literal_arg_callers(code, blank, m.group(1), m.start(), path):
                line = ctx.line_of(code, call)
                if line not in seen:
                    seen.add(line)
                    yield Hit(path, line, _mask_literals(ctx.snippet(path, line)),
                              _KEY_MSG[:-1] + ": it reaches `SecretKeySpec` through a helper in this file.",
                              _hit_scope(ctx, path, call, blank))
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
        blank = ctx.code(path, keep_strings=False) or ""
        for m in SWIFT_KEY_FROM_VAR.finditer(code):
            line = ctx.line_of(code, m.start())
            name = m.group(1) or m.group(2) or m.group(3)
            if line in seen or not _swift_literal_bytes(code, blank, name, m.start(), path):
                continue
            if m.group(0).startswith("SecKey"):
                start, end, _head = _enclosing_function(blank, m.start(), path)
                if "kSecAttrKeyClassPrivate" not in code[start:end]:
                    continue                  # a public key ships by design
            seen.add(line)
            yield Hit(path, line, _mask_literals(ctx.snippet(path, line)), _KEY_MSG,
                      _hit_scope(ctx, path, m.start(), blank))
    for path, code, blank in _files_with(ctx, APPLE, ("RNEncryptor", "RNDecryptor", "RNCryptor")):
        for m in RNCRYPTOR_PASSWORD.finditer(code):
            value = m.group(1)                # `$` is not interpolation in Swift or Objective-C strings
            if "\\(" not in value and not _FAKE_VALUE.match(value) and not _placeholder(value):
                yield _hit_at(ctx, path, code, m.start(), "RNCryptor encrypts with a password written in the code, "
                                                          "so anyone who unpacks the app can decrypt the data.",
                              blank, mask=True)
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
    yield from _js_hardcoded_key(ctx)


# ============================================================================ shared helpers (XPL-012+)

NATIVE = (".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hpp")


def _args_of(blank: str, open_paren: int) -> List[Tuple[int, int]]:
    """(start, end) of each top-level argument of the call whose `(` is at `open_paren`."""
    close = bracket_match(blank, open_paren, "(", ")")
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
    return safety.small_int(text.strip().replace("_", "").rstrip("Ll"))


def _int_value(code: str, expr: str) -> Optional[int]:
    """An integer literal, or a constant assigned one in the same file."""
    v = _int_literal(expr)
    if v is not None:
        return v
    name = expr.strip().rsplit(".", 1)[-1]
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    value = _int_constants(code).get(name)
    return _int_literal(value) if value is not None else None


_INT_ASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*(?::\s*(?:Int|Long|UInt32|Int32))?\s*=\s*([\d_]+)[Ll]?\b")


def _int_constants(code: str) -> Dict[str, str]:
    """name -> the digits of its first `name = 123` in the text, built once per text (a search per lookup
    over the whole file is quadratic when a file has thousands of KDF calls)."""
    def build() -> Dict[str, str]:
        found: Dict[str, str] = {}
        for m in _INT_ASSIGN.finditer(code):
            found.setdefault(m.group(1), m.group(2))
        return found
    return text_memo(code, ("int_constants",), build)


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
        if needles:
            if not holds_any(ctx, path, needles):
                continue
        elif ctx.text(path) is None:
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
            close = bracket_match(blank, open_paren, "(", ")")
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
    yield from _js_clipboard_secret(ctx)


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
# The literals each BROKEN_CIPHER match starts with ("DES" also starts "DESede"), for finditer_lit.
_BROKEN_CIPHER_STARTS = [("Cipher", "KeyGenerator", "SecretKeyFactory"), ("KeyProperties",), ("kCCAlgorithm",),
                         ("Blowfish",), ("DES", "RC4", "RC2", "Blowfish"), ("EVP_",)]


@detector("xpl_broken_cipher")
def broken_cipher(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE + NATIVE, ("DES", "RC4", "RC2", "ARC", "Blowfish", "3DES",
                                                             "des_", "rc4", "bf_", "rc2_", "CAST")):
        seen: Set[int] = set()
        for (regex, where), starts in zip(BROKEN_CIPHER, _BROKEN_CIPHER_STARTS):
            for m in finditer_lit(regex, code, starts):
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                algo = m.group(1) if regex.groups else "3DES"
                yield _hit_at(ctx, path, code, m.start(), f"{algo} ({where}) is a broken or retired cipher.", blank)
    yield from _js_broken_cipher(ctx)


# ---------------------------------------------------------------------------- XPL-014

_RSA_IN = re.compile(r"\"(?:RSA|DSA|DH|DiffieHellman)\"|KEY_ALGORITHM_RSA\b|kSecAttrKeyTypeRSA\b")
_NOT_RSA_IN = re.compile(r"\"(?:EC|AES|HmacSHA\d+)\"|KEY_ALGORITHM_(?:EC|AES|HMAC_\w+)\b|kSecAttrKeyTypeEC\w*")
WEAK_CURVE = re.compile(r"\bECGenParameterSpec\s*\(\s*\"(secp112r[12]|secp128r[12]|secp160[rk][12]?|prime192v\d|"
                        r"secp192[rk]1|sect1[1-6]\d[rk]\d)\"")
KEY_SIZE_CALLS = re.compile(r"\b(?:initialize|setKeySize|RSAKeyGenParameterSpec)\s*\(\s*([\w.]+)")
KEYGEN_INIT = re.compile(r"\bKeyGenerator\s*\.\s*getInstance\s*\([^)]*\)\s*(?:\.\s*apply\s*\{\s*|\.\s*)?init\s*\(\s*(\d+)")
APPLE_KEY_SIZE = re.compile(r"\bkSecAttrKeySizeInBits\b[^\n,;\]]{0,40}?(\d{2,5})\b")
DART_RSA_SIZE = re.compile(r"\bRSAKeyGeneratorParameters\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(\d+)")


def _keygen_algorithm(code: str, body: str, idx: int) -> Optional[str]:
    """The algorithm argument of the `KeyPairGenerator.getInstance(...)` that the receiver of the
    `initialize(...)` at `idx` was assigned, looked for in the function and then the file; None when the
    call has no receiver or its declaration isn't found."""
    recv = re.search(r"([A-Za-z_]\w*)\s*\.\s*$", code[max(0, idx - 120):idx])
    if not recv:
        return None
    decl = re.compile(r"\b" + re.escape(recv.group(1)) + r"\s*(?::\s*[\w.]+\??)?\s*=\s*(?:[\w.]+\.)?"
                      r"KeyPairGenerator\s*\.\s*getInstance\s*\(\s*([^,()]+)")
    m = decl.search(body) or text_memo(code, ("kpg_decl", recv.group(1)), lambda: decl.search(code))
    return m.group(1) if m else None


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
            algo = _keygen_algorithm(code, body, m.start())
            if algo is not None:
                if not _RSA_IN.search(algo) or _NOT_RSA_IN.search(algo):
                    continue
            elif not m.group(0).startswith("RSAKeyGen") and (not _RSA_IN.search(body) or _NOT_RSA_IN.search(body)):
                continue
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), f"An RSA, DSA, or DH key of {n} bits; use at least 2048.", blank)
        for m in KEYGEN_INIT.finditer(code):
            n = safety.small_int(m.group(1))
            if n is None:
                continue
            line = ctx.line_of(code, m.start())
            if n < 128 and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"A symmetric key of {n} bits; use at least 128.", blank)
    for path, code, blank in _files_with(ctx, APPLE, ("kSecAttrKeySizeInBits", "kCCKeySizeDES", "kCCKeySize3DES")):
        seen = set()
        for m in APPLE_KEY_SIZE.finditer(code):
            n = safety.small_int(m.group(1))
            if n is None:
                continue
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
            n = safety.small_int(m.group(1))
            if n is None:
                continue
            if n < 2048:
                yield _hit_at(ctx, path, code, m.start(), f"An RSA key of {n} bits; use at least 2048.", blank)
    yield from _js_small_key(ctx)


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


def _params(head: str, path: str) -> List[Tuple[str, str]]:
    """(call label, name) of each parameter in a function head; the label is "" for a positional one.
    Swift `salt: Data` and `with salt: Data` and `_ salt: Data`, Kotlin `salt: ByteArray`, Java
    `byte[] salt`."""
    close = head.rfind(")")
    name_at = re.search(r"([A-Za-z_]\w*)\s*(?:<[^<>]*>)?\s*\(", head)
    if close < 0 or not name_at:
        return []
    inner = head[name_at.end():close]
    out: List[Tuple[str, str]] = []
    for p in inner.split(","):
        p = re.sub(r"@\w+(?:\([^)]*\))?|\b(?:final|vararg|inout)\b", " ", p).strip()
        if path.endswith(".swift"):
            m = re.match(r"(?:(\w+)\s+)?(\w+)\s*:", p)
            if m:
                label = m.group(1) if m.group(1) else m.group(2)
                out.append(("" if label == "_" else label, m.group(2)))
        elif path.endswith(".kt"):
            m = re.match(r"(?:va[lr]\s+)?(\w+)\s*:", p)
            if m:
                out.append(("", m.group(1)))
        else:
            m = re.search(r"(\w+)\s*$", p)
            if m:
                out.append(("", m.group(1)))
    return out


# Calls of one wrapper judged per file: the report lists only the first few hits in a file anyway, and a
# crafted file calling it tens of thousands of times made each KDF call a pass over all of them.
_MAX_FORWARDED = 200


def _forwarded(code: str, blank: str, path: str, span: Optional[Tuple[int, int]]) -> Optional[Dict[int, Tuple[int, int]]]:
    """When the KDF argument at `span` is a parameter of its function (through a cast such as
    `UInt32(rounds)` or a `salt.withUnsafeBytes { saltBytes in` alias), {call start: argument span} for
    each call of that function in the file. None when the argument is not a parameter."""
    if span is None:
        return None
    expr = code[span[0]:span[1]].strip()
    cast = re.fullmatch(r"(?:UInt32|Int32|UInt|Int|CUnsignedInt|UInt64|Int64)\s*\(\s*(\w+)\s*\)|&?\s*(\w+)", expr)
    if not cast:
        return None
    name = cast.group(1) or cast.group(2)
    start, _end, head = _enclosing_function(blank, span[0], path)
    if not head:
        return None                           # not inside a function: no parameters to forward
    alias = re.search(r"\b(\w+)\s*\.\s*withUnsafe(?:Mutable)?Bytes\s*\{\s*\(?\s*" + re.escape(name) + r"\b",
                      code[max(start, span[0] - 3000):span[0]])
    if alias:
        name = alias.group(1)
    params = _params(head, path)
    pos = next((i for i, (_label, n) in enumerate(params) if n == name), -1)
    fn = _function_name(head)
    if pos < 0 or not fn:
        return None
    label = params[pos][0]
    out: Dict[int, Tuple[int, int]] = {}
    for call_start, paren, dotted in _call_sites(blank).get(fn, [])[:_MAX_FORWARDED]:
        if dotted or start - len(head) <= call_start < start:
            continue                          # a method of another object, or the declaration itself
        args = _args_of(blank, paren)
        arg = _named_arg(blank, code, args, label) if label else (args[pos] if len(args) > pos else None)
        if arg is not None:
            out[call_start] = arg
    return out


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
                call_text = code[m.start():bracket_match(blank, m.end() - 1, "(", ")")]
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
                fw_it, fw_salt = _forwarded(code, blank, path, it), _forwarded(code, blank, path, salt)
                if not fw_it and not fw_salt:     # not a parameter, or no caller in this file
                    yield path, code, blank, m.start(), it, salt, prf
                    continue
                # A same-file wrapper (`func pbkdf2(password:salt:rounds:)`) passes its parameters on: judge
                # each call of the wrapper by the arguments it gets.
                for call in sorted(set(fw_it or {}) | set(fw_salt or {})):
                    yield (path, code, blank, call, (fw_it or {}).get(call) if fw_it is not None else it,
                           (fw_salt or {}).get(call) if fw_salt is not None else salt, prf)


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
        open_body = blank.find("{", bracket_match(blank, m.end() - 1, "(", ")"))
        if open_body < 0:
            continue
        close_body = bracket_match(blank, open_body, "{", "}")
        for e in re.finditer(r"(?m)^[ \t]*([A-Z]\w*)\s*\(", blank[open_body:close_body]):
            paren = open_body + e.end() - 1
            args = _args_of(blank, paren)
            if len(args) > idx:
                n = _int_literal(code[args[idx][0]:args[idx][1]])
                if n is not None:
                    out.append((open_body + e.start(1), n, code[open_body + e.start():bracket_match(blank, paren, "(", ")")]))
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
                call_end = bracket_match(blank, blank.find("(", start), "(", ")")
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
    yield from _js_pbkdf2_iterations(ctx)


_DART_LITERAL_SALT = re.compile(r"^\s*(?:const\s+)?(?:utf8\.encode\s*\(\s*r?[\"']|" + _DART_LITERAL_BYTES
                                + r"|\[\s*\d|r?[\"']|SecretKey\s*\(\s*(?:utf8\.encode|const\s*\[|\[))")
_APPLE_LITERAL_SALT = re.compile(r"^\s*&?\s*(?:\"[^\"\n]*\"|Array\s*\(\s*\"|\[\s*(?:0x)?\d|Data\s*\(\s*(?:bytes\s*:\s*)?(?:\"|\[)|"
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
                                   r"(?:\"|Array\s*\(\s*\"|\[\s*(?:0x)?\d|Data\s*\(\s*(?:\"|bytes\s*:\s*\[))", code))


@detector("xpl_fixed_salt")
def fixed_salt(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank, start, _it, salt, _prf in _kdf_calls(ctx):
        if salt is not None and _salt_is_literal(path, code, blank, salt):
            yield _hit_at(ctx, path, code, start, "The password-hashing salt is a fixed value in the code, so "
                                                  "every user's derived key can be attacked at once.", blank, mask=True)
    yield from _js_fixed_salt(ctx)


# ---------------------------------------------------------------------------- XPL-017

GRPC_PLAIN: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\.\s*usePlaintext\s*\(\s*(?:true)?\s*\)"), "`usePlaintext()`"),
    (re.compile(r"\bClientConnection\s*\.\s*insecure\s*\(\s*group\s*:"), "`ClientConnection.insecure`"),
    (re.compile(r"\btransportSecurity\s*:\s*\.plaintext\b"), "`transportSecurity: .plaintext`"),
    (re.compile(r"\bChannelCredentials\s*\.\s*insecure\s*\("), "`ChannelCredentials.insecure()`"),
]
_LOCAL_TARGET = re.compile(r"[\"'](?:localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.3\.2|0\.0\.0\.0|\[::1\])[\"':]")


# The host a channel is opened to: ClientChannel('h', ...), forAddress("h", ...), forTarget("h:port"),
# .connect(host: "h", ...).
_GRPC_TARGET = re.compile(r"\b(?:ClientChannel|forAddress|forTarget)\s*\(\s*[\"']([^\"':]+)[\"':]"
                          r"|\.connect\s*\(\s*host\s*:\s*\"([^\"]+)\"")


@detector("xpl_grpc_plaintext")
def grpc_plaintext(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("usePlaintext", "insecure", "plaintext")):
        if path.endswith(JVM) and not re.search(r"ChannelBuilder|io\.grpc", code):
            continue
        targets = [a or b for a, b in _GRPC_TARGET.findall(code)]
        if targets and all(_LOCAL_TARGET.match(f'"{t}"') for t in targets):
            continue                  # every channel this file opens goes to the device itself (127.0.0.1)
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
            close = bracket_match(blank, m.end() - 1, "(", ")")
            args = code[m.end():close]
            if "localizedReason" not in args or re.search(r"\bbiometricOnly\s*:\s*true\b", args):
                continue
            yield _hit_at(ctx, path, code, m.start(), "local_auth's `authenticate` without `biometricOnly: true` "
                                                      "accepts the device PIN or passcode.", blank)
    yield from _js_biometric_fallback(ctx)


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
    return [rel for rel in ctx.all_names()
            if rel.lower().endswith((".pem", ".key")) and _SHIPPED_DIR.search("/" + rel)][:200]


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
        guarded: dict = {}                    # (start, end) of a function -> it checks the path; once each
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
                    if (start, end) not in guarded:
                        body = blank[start:end]
                        guarded[(start, end)] = bool((_ZIP_GUARD.search(body) and "startsWith" in body) or re.search(
                            r"contains\s*\(\s*\"\.\.\"", code[start:end]))
                    if guarded[(start, end)]:
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
    files = _evidence_files(ctx)
    needles = _NEEDLES.get(pattern.pattern)
    if needles is None:
        candidates: Iterable[int] = range(len(files))
    else:
        # Only files whose lower-cased text holds a needle can match.
        hit_set: Set[int] = set()
        for n in needles:
            hit_set.update(_evidence_holding(ctx, n))
        candidates = sorted(hit_set)
    suffixes = _PLATFORM_SUFFIXES.get(platform)
    for i in candidates:
        path, text = files[i]
        if suffixes is not None and not path.endswith(suffixes):
            continue
        if accept is None:
            if pattern.search(text):
                return path
        elif any(accept(path, text, m) for m in pattern.finditer(text)):
            return path
    return None


_PLATFORM_SUFFIXES = {
    "android": (".kt", ".java", ".kts", ".gradle", ".toml", ".pro") + NATIVE,
    "ios": APPLE + NATIVE + (".pbxproj", ".resolved", "Podfile", "Package.swift", "Cartfile"),
}


def _evidence_holding(ctx: Context, needle: str) -> List[int]:
    """Indices into _evidence_files of the files whose text, lower-cased, contains `needle`; cached.
    Candidates come from the raw-text index (an evidence text is its file's raw text with comments
    blanked, so a needle without spaces in it lies in the raw text too); files outside that index are
    always candidates. Each candidate is then tested directly."""
    cache = getattr(ctx, "_xpl_evidence_cache", None)
    if cache is None:
        files = _evidence_files(ctx)
        index, pos = _raw_index(ctx)
        of_raw: dict = {}
        unindexed: List[int] = []
        for i, (path, _text) in enumerate(files):
            k = pos.get(path)
            if k is None:
                unindexed.append(i)
            else:
                of_raw[k] = i
        cache = ctx._xpl_evidence_cache = ({}, {}, of_raw, unindexed)  # type: ignore[attr-defined]
    answers, lowered, of_raw, unindexed = cache
    if needle not in answers:
        files = _evidence_files(ctx)
        index, _pos = _raw_index(ctx)
        if " " in needle:
            candidates: Iterable[int] = range(len(files))
        else:
            candidates = sorted({of_raw[k] for k in index.candidates_lower(needle) if k in of_raw}
                                | set(unindexed))
        out = []
        for i in candidates:
            low = lowered.get(i)
            if low is None:
                low = lowered[i] = files[i][1].lower()
            if needle in low:
                out.append(i)
        answers[needle] = out
    return answers[needle]


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
    # A managed Expo app commits no native project: `expo prebuild` generates it from app.json, so the
    # app is anchored there, for each platform it targets.
    from masaudit.detectors import rn_expo
    for platform, managed in (("android", rn_expo.managed_android), ("ios", rn_expo.managed_ios)):
        if any(p == platform for p, _, _ in out) or platform not in ctx.project.platforms:
            continue
        app = managed(ctx)
        if app is not None:
            out.append((platform, app.path, app.line(platform) if app.get(platform) is not None else app.line("expo")))
    return out


def _absence(ctx: Context, rule: Rule, android: Pattern[str], ios: Pattern[str], shared: Pattern[str],
             what: str, accept: Optional[Callable[[str, str, "re.Match[str]"], bool]] = None) -> Iterable[Hit]:
    if _found(ctx, shared):
        return
    missing: Dict[Tuple[str, int], List[str]] = {}
    for platform, path, line in _app_anchors(ctx):
        if not _found(ctx, android if platform == "android" else ios, platform, accept):
            missing.setdefault((path, line), []).append("Android" if platform == "android" else "iOS")
    for (path, line), names in missing.items():
        # One Expo config holds both apps: one finding that names both.
        apps = " and ".join(names) + (" apps" if len(names) > 1 else " app")
        yield Hit(path, line, ctx.snippet(path, line), f"No {what} found in the {apps}.")


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
    if _rn_evidence(ctx, "root", RN_ROOT_DEPS, RN_ROOT_JS, ("Jail", "jail", "Rooted")):
        return
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
    if path.endswith(APPLE + NATIVE) and preprocessor_debug_guarded(text, m.start()):
        return False
    return True


@detector("xpl_no_debugger_detection")
def no_debugger_detection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if _rn_evidence(ctx, "debugger", RN_DEBUGGER_DEPS, RN_DEBUGGER_JS, ("isDebug",)):
        return
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
    if _rn_evidence(ctx, "emulator", RN_EMULATOR_DEPS, RN_EMULATOR_JS, ("isEmulator", "isDevice", "isRealDevice")):
        return
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
    if _rn_evidence(ctx, "hook", RN_HOOK_DEPS, RN_HOOK_JS, ("hookDetected", "isHooked", "isFridaDetected")):
        return
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
                           r"\bapp_?version_?(?:expired|unsupported|deprecated)\b|"
                           r"[Vv]ersion_?[Bb]lock(?:er|ed|Check)")


@detector("xpl_no_forced_update")
def no_forced_update(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if _rn_evidence(ctx, "update", RN_UPDATE_DEPS, RN_UPDATE_JS, ("version", "Version", "VERSION", "update",
                                                                    "Update", "UPDATE", "itunes", "eprecated",
                                                                    "EPRECATED"), fold=True):
        return
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
                args = code[m.end():bracket_match(blank, m.end() - 1, "(", ")")]
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


# A call at the start of a line is still checked when the line before ends an expression that goes on
# (`guard`, `if`, `return`, `=`, `&&`), or when the status is compared right after the call.
_STATUS_USED_BEFORE = re.compile(r"(?:\b(?:guard|if|while|return|let|var)|[=(,?:]|&&|\|\|)\s*$")
_STATUS_USED_AFTER = re.compile(r"\s*(?:[=!]=|[<>?]|\.|&&|\|\|)")
# The call alone in a closure: `{ SecRandomCopyBytes(…) }` or `{ ptr in SecRandomCopyBytes(…) }`.
_CLOSURE_START = re.compile(r"\{\s*(?:\(?\s*[\w\s,:]{0,120}\)?\s*in)?\s*$")
# What the closure's value goes to, on the line that opens it: a binding, a return, a condition, a comparison.
_CLOSURE_VALUE_USED = re.compile(r"(?:\b(?:let|var)\s+\w+[^=\n]*=(?!=)|\breturn\b|\bguard\b|\bif\b|[=!]=|(?<![=!<>])=(?!=))")


def _secrandom_status_used(blank: str, at: int) -> bool:
    """Is the status of the `SecRandomCopyBytes(` call at `at` (first on its line) used after all?"""
    before = blank[max(0, at - 300):at].rstrip()
    close = bracket_match(blank, blank.index("(", at), "(", ")")
    if _STATUS_USED_AFTER.match(blank, close + 1):
        return True
    if _STATUS_USED_BEFORE.search(before) and not re.search(r"(?<![\w$])_\s*=$", before):
        return True                               # (`_ =` on the line before discards it)
    opened = _CLOSURE_START.search(before)
    if opened and re.match(r"\s*\}", blank[close + 1:close + 200]):
        # Swift returns a one-expression closure's value: the status is the closure's, so ask what the
        # code does with the closure's result (`let status = data.withUnsafeMutableBytes {`).
        line = before[:opened.start()].rsplit("\n", 1)[-1]
        return bool(_CLOSURE_VALUE_USED.search(line)) and not re.match(r"\s*_\s*=", line)
    return False


@detector("xpl_secrandom_unchecked")
def secrandom_unchecked(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, APPLE, ("SecRandomCopyBytes",)):
        for m in SECRANDOM_IGNORED.finditer(blank):
            at = m.start() + len(m.group(0)) - len(m.group(0).lstrip())
            if m.group(0).lstrip().startswith("SecRandomCopyBytes") and _secrandom_status_used(blank, at):
                continue
            yield _hit_at(ctx, path, code, at,
                          "`SecRandomCopyBytes` can fail, and its status is ignored, so the buffer may stay zero.",
                          blank)


# ---------------------------------------------------------------------------- XPL-029

# Writes only: `el.textContent` alone reads the DOM, it doesn't put a secret there.
_DOM_SINK = re.compile(r"(?:innerHTML|outerHTML|textContent|innerText|\.value)\s*\+?=(?!=)|document\.write|"
                       r"insertAdjacentHTML|\.setAttribute\s*\(\s*\\?[\"']value")
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
            args = _args_of(blank, open_paren)
            # The script is the first argument; a completion handler after it only receives a result.
            close = args[0][1] if args else bracket_match(blank, open_paren, "(", ")")
            text = code[open_paren:min(close, open_paren + 800)]
            if not _DOM_SINK.search(text):
                continue
            exprs = " ".join(next(x for x in g.groups() if x is not None) for g in INTERP.finditer(text))
            exprs += " " + blank[open_paren:min(close, open_paren + 800)]     # concatenated identifiers
            found = sorted(_words_of(exprs) & _DOM_SECRET)
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"Native code writes a `{found[0]}` into the web page's DOM, "
                                                          "where every script on the page can read it.", blank)
    yield from _js_webview_dom_secret(ctx)


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


_DB_SECRET_NAMES = {"password", "passwd", "passcode", "pin", "pincode", "accesstoken", "refreshtoken", "authtoken",
                    "sessiontoken", "token", "apikey", "secret", "clientsecret", "privatekey", "cardnumber",
                    "creditcard", "cvv", "cvc", "iban", "ssn", "useraccesstoken", "appaccesstoken"}
# Whose credential it is: a bare `token` or `secret` in a SQL table, and any field of a Realm or Core Data
# model, counts only on a user, account, or session record (a share link's password or a password-history
# entry the app encrypted first are not the user's login).
_DB_OWNER = {"account", "user", "session", "auth", "authentication", "credential", "credentials", "login",
             "profile", "member", "customer"}
# Realm models: Swift `class User: Object {`, Objective-C `@interface User : RLMObject`.
REALM_MODEL = re.compile(r"\bclass\s+(\w+)\s*:\s*(?:Realm\w*\.)?Object\b[^{\n]*\{|@interface\s+(\w+)\s*:\s*RLMObject\b")
# Whitespace stays on one line (`\s+` across lines rescans the rest of the body from every line start), and an
# Objective-C property's name is the last word of its declaration, taken in Python, not by a lazy match.
REALM_SECRET_FIELD = re.compile(r"(?m)^[ \t]*(?:@\w+(?:\([^)\n]*\))?[ \t]+)*(?:(?:private|public|internal|"
                                r"fileprivate|dynamic)[ \t]+)*var[ \t]+(\w+)[ \t]*[:=]|^[ \t]*@property\b([^;\n]*);")
# A literal `CREATE TABLE name (col TYPE, ...)` handed to SQLite.
SQL_CREATE = re.compile(r"(?i)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?[`\"]?(\w+)[`\"]?\s*\(([^)\"\n]{1,600})\)")


def _db_secret_name(name: str, owner: Set[str]) -> bool:
    norm = re.sub(r"[_\-]", "", name).lower()
    if norm not in _DB_SECRET_NAMES:
        return False
    return norm not in ("token", "secret") or bool(owner & _DB_OWNER)


def _current_core_data_models(ctx: Context) -> List[str]:
    """The `contents` file of each Core Data model, newest version only: `Model 10.xcdatamodel` over
    `Model 9.xcdatamodel` over `Model.xcdatamodel` (old versions stay in the bundle for migration)."""
    newest: Dict[str, Tuple[int, str]] = {}
    for path in ctx.files(name="contents"):
        parts = path.split("/")
        if len(parts) < 2 or not parts[-2].endswith(".xcdatamodel"):
            continue
        group = "/".join(parts[:-2])
        num = re.search(r"(\d+)\.xcdatamodel$", parts[-2])
        rank = (safety.small_int(num.group(1)) or 1) if num else 1
        if group not in newest or rank > newest[group][0]:
            newest[group] = (rank, path)
    return [p for _r, p in newest.values()]


def _core_data_created(ctx: Context) -> Set[str]:
    """Entity and class names the app's code creates: `insertNewObject(forEntityName: "User", …)`,
    `NSEntityDescription.entity(forEntityName: "User", …)`, `User(context: …)`."""
    names: Set[str] = set()
    for _path, code, _blank in _files_with(ctx, APPLE, ("forEntityName", "(context:")):
        names.update(re.findall(r"forEntityName\s*:\s*@?\"(\w+)\"", code))
        names.update(re.findall(r"\b([A-Z]\w*)\s*\(\s*context\s*:", code))
    return names


@detector("xpl_db_plain_credentials")
def db_plain_credentials(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _db_plain_native(ctx)
    yield from _js_db_plain_credentials(ctx)
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
            args = code[m.end():bracket_match(blank, m.end() - 1, "(", ")")]
            if "encryptionCipher" not in args:
                yield _hit_at(ctx, path, code, m.start(), "A Hive box that stores a token or password is opened "
                                                          "without `encryptionCipher`.", blank)
    for path, code, blank in _files_with(ctx, (".swift",), ("Realm.Configuration", "Object")):
        if not re.search(r"@Persisted\s+var\s+(?:password|token|accessToken|refreshToken|pin|secret)\b", code):
            continue
        for m in re.finditer(r"\bRealm\s*\.\s*Configuration\s*\(", blank):
            yield _hit_at(ctx, path, code, m.start(), "A Realm that stores a token or password is configured "
                                                      "without an `encryptionKey`.", blank)


_VENDORED = re.compile(r"(?i)/(?:vendor|vendors|third[_-]?party|3rdparty)/")


def _db_encryption_evidence(ctx: Context) -> Set[str]:
    """Which local stores the app encrypts: "sql" (SQLCipher), "realm" (an `encryptionKey` in a file that
    uses Realm), "coredata" (a file-protection class on the store or app-wide). Looked for per store, so
    an unrelated `encryptionKey` (a crypto library's parameter) doesn't hide every database."""
    found: Set[str] = set()
    for path, code, _blank in _files_with(ctx, CODE + NATIVE + (".gradle", ".kts", ".toml", ".entitlements"),
                                          ("sqlcipher", "zetetic", "SupportFactory", "loadLibs", "PRAGMA key",
                                           "sqlite3_key", "encryptionKey", "FileProtection", "data-protection")):
        if _VENDORED.search("/" + path):
            continue                          # a bundled library's own code (YapDatabase calls sqlite3_key)
        if re.search(r"(?i)sqlcipher|net\.zetetic|SQLiteDatabase\.loadLibs|SupportOpenHelperFactory|"
                     r"SupportFactory\s*\(|PRAGMA\s+key\b|sqlite3_key\b", code):
            found.update(("sql", "coredata"))
        if "Realm" in code and re.search(r"\bencryptionKey\s*[:=(]", code):
            found.add("realm")
        if re.search(r"NSPersistentStoreFileProtectionKey|SQLITE_OPEN_FILEPROTECTION_|"
                     r"com\.apple\.developer\.default-data-protection", code):
            found.add("coredata")
    return found


# Tags are bounded so a crafted model with no closing `>` or `</entity>` can't make every tag rescan the file.
_CORE_DATA_ENTITY = re.compile(r"<entity\b([^>]{0,2000})>")
_CORE_DATA_ATTRIBUTE = re.compile(r"<attribute\b([^>]{0,2000})>")


def _core_data_entities(text: str) -> Iterator[Tuple[str, int, int]]:
    """(entity tag attributes, body start, body end) for each `<entity ...>...</entity>` in a Core Data model."""
    pos = 0
    while True:
        m = _CORE_DATA_ENTITY.search(text, pos)
        if not m:
            return
        end = text.find("</entity>", m.end())
        if end < 0:
            return                            # no entity after this one can close either
        yield m.group(1), m.end(), end
        pos = end + len("</entity>")


def _db_plain_native(ctx: Context) -> Iterable[Hit]:
    """Raw SQLite tables, Realm models, and Core Data entities that hold a password or token."""
    encrypted = _db_encryption_evidence(ctx)
    for path, code, blank in _files_with(ctx, APPLE, ("Object", "RLMObject")):
        if "realm" in encrypted or ("import RealmSwift" not in code and "Realm/" not in code
                                    and "RLMObject" not in code):
            continue
        for m in REALM_MODEL.finditer(blank):
            owner = _words_of(code[m.start():m.end()])
            body_end = bracket_match(blank, m.end() - 1, "{", "}") if blank[m.end() - 1] == "{" else \
                blank.find("@end", m.end())
            for f in REALM_SECRET_FIELD.finditer(code, m.end(), body_end if body_end > 0 else len(code)):
                name = f.group(1) or (re.findall(r"\w+", f.group(2)) or [""])[-1]
                if owner & _DB_OWNER and _db_secret_name(name, owner):
                    yield _hit_at(ctx, path, code, f.start(), f"Realm field `{name}` is stored without an "
                                                              "`encryptionKey`.", blank)
    for path, code, blank in _files_with(ctx, CODE, ("CREATE TABLE", "create table")):
        if "sql" in encrypted:
            break
        for m in SQL_CREATE.finditer(code):
            owner = _words_of(m.group(1))
            for col in re.split(r",", m.group(2)):
                name = col.split()[0] if col.split() else ""
                if _db_secret_name(name, owner):
                    yield _hit_at(ctx, path, code, m.start(), f"Table `{m.group(1)}` stores a `{name}` column "
                                                              "without database encryption.", blank)
                    break
    models = [] if "coredata" in encrypted else _current_core_data_models(ctx)
    created = _core_data_created(ctx) if models else set()
    for path in models:
        text = ctx.text(path) or ""
        for head, body_start, body_end in _core_data_entities(text):
            names = set(re.findall(r"\b(?:name|representedClassName)=\"\.?(\w+)\"", head))
            if not names & created:
                continue                      # an entity no code makes any more (kept for migration)
            owner = _words_of(" ".join(names))
            for a in _CORE_DATA_ATTRIBUTE.finditer(text, body_start, body_end):
                name = re.search(r"\bname=\"([^\"]+)\"", a.group(1))
                if not name or 'attributeType="String"' not in a.group(1):
                    continue
                if owner & _DB_OWNER and _db_secret_name(name.group(1), owner):
                    line = ctx.line_of(text, a.start())
                    yield Hit(path, line, ctx.snippet(path, line), f"Core Data attribute `{name.group(1)}` is "
                              "stored in a plain SQLite file.")


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
            close = bracket_match(blank, m.end() - 1, "(", ")")
            found = _notif_found(code[m.end():close], blank[m.end():close])
            if not found:
                continue
            start, end, _head = _enclosing_function(blank, m.start(), path)
            if text_memo(blank, ("notif_private", start, end),
                         lambda b=blank, s=start, e=end: bool(_NOTIF_PRIVATE.search(b[s:e]))):
                continue                      # (searched once per function, not once per call in it)
            yield _hit_at(ctx, path, code, m.start(), f"A notification shows `{found[0]}`, which appears on the "
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
            close = bracket_match(blank, m.end() - 1, "(", ")")
            found = _notif_found(code[m.end():close], blank[m.end():close])
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"A notification shows a `{found[0]}` on the lock screen.",
                              blank)
    yield from _js_notification_secret(ctx)


# ---------------------------------------------------------------------------- XPL-033

_FIELD_SECRET = re.compile(r"(?i)pass(?:word|code|wd)|(?<![a-z])pin(?![a-z])|(?<![a-z])pin(?=[A-Z_]|code)")
_XML_FIELD = re.compile(r"<(?:[\w.]+\.)?(?:EditText|TextInputEditText|AppCompatEditText|MaterialAutoCompleteTextView)"
                        r"\b")
# The deprecated `android:password="true"` masks the input too.
_MASKED_TYPE = re.compile(r"android:inputType\s*=\s*\"[^\"]*(?:textPassword|numberPassword|textWebPassword)|"
                          r"android:password\s*=\s*\"true\"")
COMPOSE_FIELD = re.compile(r"(?<![\w.])(?:OutlinedTextField|TextField|BasicTextField)\s*\(")
DART_FIELD = re.compile(r"(?<![\w.])(?:TextField|TextFormField|CupertinoTextField)\s*\(")
SWIFTUI_FIELD = re.compile(r"(?<![\w.])TextField\s*\(\s*(?:String\s*\(\s*localized:\s*)?\"([^\"\n]*)\"")


def _field_label_secret(args_code: str) -> bool:
    labels = re.findall(r"(?:label|placeholder|hint|labelText|hintText|helperText)\s*[=:]\s*([^,\n]{0,120})", args_code)
    return any(_FIELD_SECRET.search(lbl) for lbl in labels)


# UIKit: `field.isSecureTextEntry = false`, `field.secureTextEntry = NO`, `[field setSecureTextEntry:NO]`.
UIKIT_UNMASKED = re.compile(r"(?<![\w.$])([$\w][\w.$]*?)\s*\.\s*(?:isSecureTextEntry|secureTextEntry)\s*=\s*"
                            r"(?:false|NO)\b|\[\s*([$\w][\w.$]*)\s+setSecureTextEntry\s*:\s*NO\s*\]")
# A show-password toggle turns masking off on purpose, after the user asks.
_REVEAL_NAME = re.compile(r"(?i)toggle|reveal|show|hide|visib|unmask|eye|peek")


def _innermost_block(blank: str, idx: int, limit: int = 4000) -> Tuple[int, int]:
    """(start, end) of the innermost `{ }` block around `idx`, looked for within `limit` characters,
    or (-1, -1)."""
    depth = 0
    for i in range(idx - 1, max(0, idx - limit) - 1, -1):
        c = blank[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                return i, bracket_match(blank, i, "{", "}")
            depth -= 1
    return -1, -1


def _uikit_field_is_secret(code: str, blank: str, idx: int, receiver: str, path: str) -> bool:
    """Is the UIKit field whose masking is turned off at `idx` a password or PIN field? Its name, or the
    placeholder, accessibility ID, or content type set on it in the same block, must say so. A switch
    made in a branch or a show-password function is a toggle, not a field that never masks."""
    start, end = _innermost_block(blank, idx)
    if start < 0:
        return False
    head = blank[max(0, start - 200):start]
    head = head[max(head.rfind(";"), head.rfind("}"), head.rfind("{")) + 1:]
    if re.search(r"\b(?:if|else|guard|switch|case|while|for)\b|\?", head):
        return False
    _s, _e, fn_head = _enclosing_function(blank, idx, path)
    if _REVEAL_NAME.search(_function_name(fn_head)) or _REVEAL_NAME.search(receiver):
        return False
    name = receiver.rsplit(".", 1)[-1]
    if _FIELD_SECRET.search(name):
        return True
    props = re.finditer(re.escape(receiver) + r"\s*\.\s*(?:placeholder|accessibilityIdentifier|accessibilityLabel|"
                        r"textContentType)\s*=\s*([^;\n]{1,120})", code[start:end])
    return any(_FIELD_SECRET.search(p.group(1)) for p in props)


@detector("xpl_unmasked_secret_field")
def unmasked_secret_field(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".xml"):
        if "/res/layout" not in "/" + path:
            continue
        text = ctx.text(path) or ""
        if "EditText" not in text:
            continue
        for at, tag in xml_tags(text, _XML_FIELD):
            names = " ".join(re.findall(r"android:(?:id|hint|autofillHints|contentDescription)\s*=\s*\"([^\"]*)\"",
                                        tag))
            if not _FIELD_SECRET.search(names) or _MASKED_TYPE.search(tag):
                continue
            if "textVisiblePassword" not in tag and "android:inputType" in tag and \
                    not re.search(r"android:inputType\s*=\s*\"(?:text|number|phone)\"", tag):
                continue
            line = ctx.line_of(text, at)
            yield Hit(path, line, ctx.snippet(path, line),
                      "A password or PIN field shows the typed characters (no password input type).")
    for path, code, blank in _files_with(ctx, (".kt",), ("TextField",)):
        for m in COMPOSE_FIELD.finditer(blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
            args = code[m.end():close]
            if "visualTransformation" in args or not _field_label_secret(args):
                continue
            yield _hit_at(ctx, path, code, m.start(), "A password or PIN text field has no "
                                                      "`PasswordVisualTransformation`, so it shows what's typed.", blank)
        for m in re.finditer(r"\btextObfuscationMode\s*=\s*TextObfuscationMode\s*\.\s*Visible\b", blank):
            yield _hit_at(ctx, path, code, m.start(), "A `SecureTextField` is set to show its text.", blank)
    for path, code, blank in _files_with(ctx, DART, ("TextField", "TextFormField")):
        for m in DART_FIELD.finditer(blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
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
    for path, code, blank in _files_with(ctx, APPLE, ("SecureTextEntry",)):
        for m in UIKIT_UNMASKED.finditer(blank):
            receiver = m.group(1) or m.group(2)
            if _uikit_field_is_secret(code, blank, m.start(), receiver, path):
                yield _hit_at(ctx, path, code, m.start(), "A password or PIN text field turns off "
                                                          "`isSecureTextEntry`, so it shows what's typed.", blank)
    yield from _js_unmasked_field(ctx)


# ---------------------------------------------------------------------------- XPL-034

_PII_WORDS = {"email", "phone", "msisdn", "username", "fullname", "nationalid", "ssn", "iban", "phonenumber",
              "emailaddress", "mobilenumber", "displayname", "dob", "birthdate", "address",
              # Health data (MASWE-0108): a bare "health" is left out, it names server health checks too.
              "blood", "bloodtype", "diagnosis", "medication", "medical", "pregnancy", "disease", "symptom",
              "symptoms"}
# Event calls whose parameters reach the analytics vendor: Firebase `logEvent("e") { param("k", v) }`,
# `logEvent("e", bundle)`, and Mixpanel/Segment/Amplitude `track("e", properties)`.
ANALYTICS_EVENT = re.compile(r"\b(?:logEvent|trackEvent|track|logCustomEvent|recordEvent)\s*\(")
_EVENT_KEY = re.compile(r"\b(?:param|put\w*|setProperty)\s*\(\s*(?:key\s*=\s*)?[\"']([^\"'\n]{1,60})[\"']|"
                        r"[\"']([^\"'\n]{1,60})[\"']\s*(?:\bto\b|:)")
ANALYTICS_ID = re.compile(r"\b(?:setUserId|setUserID|identify|setUserIdentifier|setCustomerUserId)\s*\(")
ANALYTICS_KEYED = re.compile(r"\b(?:setUserProperty|setCustomKey|setCustomValue|setUserProperties|setAttribute)\s*\(\s*"
                             r"(?:forName\s*:\s*|key\s*:\s*|name\s*:\s*)?[\"']\$?(email|phone|msisdn|name|full_?name|"
                             r"user_?name|phone_?number|address|dob|birthday|national_?id|ssn|iban)[\"']",
                             re.IGNORECASE)
_ANALYTICS_FILE = re.compile(r"Analytics|Crashlytics|Amplitude|Mixpanel|Segment|AppsFlyer|Adjust|Braze|Sentry|"
                             r"Bugsnag|Datadog|PostHog|Countly")


_EVENT_CONSTANT = re.compile(r"(?<=[:(,=\s])\.[a-z]\w*\b(?!\s*\()|\b[A-Z]\w*\s*\.\s*[A-Z][A-Z0-9_]+\b(?!\s*\()")


def _event_pii(code: str, blank: str, open_paren: int, path: str) -> List[str]:
    """PII words in an analytics event's parameter keys and values: the call's arguments, a trailing
    `{ param(...) }` block, and the `put…("key", …)` calls on a bundle or map variable it passes."""
    close = bracket_match(blank, open_paren, "(", ")")
    if close - open_paren > 1500:
        return []
    end = close + 1
    after = re.match(r"\s*\{", blank[end:end + 40])
    if after:
        brace = end + after.end() - 1
        end = min(bracket_match(blank, brace, "{", "}"), brace + 1500)
    args = _args_of(blank, open_paren)
    if len(args) < 2 and not after:
        return []                             # an event name alone carries no user data
    region_code, region_blank = code[open_paren:end], blank[open_paren:end]
    keys = [k1 or k2 for k1, k2 in _EVENT_KEY.findall(region_code)]
    var = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", blank[args[-1][0]:args[-1][1]]) if len(args) >= 2 else None
    if var:
        start = max(_enclosing_function(blank, open_paren, path)[0], open_paren - 4000)
        put = re.compile(r"\b" + re.escape(var.group(1)) + r"\s*(?:\.\s*put\w*\s*\(|\[)\s*[\"']([^\"'\n]{1,60})[\"']")
        keys += put.findall(code, start, open_paren)
    # Enum cases and constants name the event (`object: .addressAutofillPromptShown`, `Events.EMAIL_OPENED`);
    # they carry no user data, so their words don't count.
    region_blank = _EVENT_CONSTANT.sub(" ", region_blank)
    words = _words_of(" ".join(keys)) | _words_of(region_blank)
    return sorted(words & _PII_WORDS)


@detector("xpl_analytics_pii")
def analytics_pii(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("setUserId", "setUserID", "identify", "setUserProperty",
                                                    "setCustomKey", "setCustomValue", "setAttribute",
                                                    "setUserIdentifier", "setCustomerUserId", "logEvent",
                                                    "trackEvent", "track(", "logCustomEvent", "recordEvent")):
        if not _ANALYTICS_FILE.search(code):
            continue
        seen: Set[int] = set()
        for m in ANALYTICS_ID.finditer(blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
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
        for m in ANALYTICS_EVENT.finditer(blank):
            line = ctx.line_of(code, m.start())
            found = _event_pii(code, blank, m.end() - 1, path)
            if found and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"An analytics event sends the user's `{found[0]}`.", blank)
    yield from _js_analytics_pii(ctx)


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
        if (scope_of(path) in ("test", "build-script", "debug") or _has_test_import(code)
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
    yield from _js_nonprod_endpoint(ctx)


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
    yield from _js_oauth_flow(ctx)


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
        if re.fullmatch(r"[A-Za-z_]\w*", piece) and _named_constant(code, piece):
            continue
        return False
    return True


def _named_constant(code: str, name: str) -> bool:
    """`name` is a string constant or a list of string literals defined in this file."""
    return text_memo(code, ("named_constant", name), lambda: bool(_string_constant(code, name) or re.search(
        r"\b" + re.escape(name) + r"\s*=\s*(?:arrayOf|listOf)\s*\(\s*(?:\"[^\"\n]*\"\s*,?\s*)*\)", code)))


def _elements(code: str, blank: str, span: Tuple[int, int]) -> Optional[List[str]]:
    """Elements of a list or array literal argument, or None when the argument is something else."""
    m = _LIST_LIT.match(blank[span[0]:span[1]])
    if not m:
        return None
    open_at = span[0] + max(m.start(g) for g in (1, 2, 3) if m.group(g))
    closer = {"(": ")", "{": "}", "[": "]"}[blank[open_at]]
    close = bracket_match(blank, open_at, blank[open_at], closer)
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
    # Runtime.exec(String) splits the string on spaces and runs the first word, with no shell: like the
    # argument array above, a value in it can add arguments but not commands, unless that program is a shell
    # (`su -c `, `sh -c `). A bare variable passed through from a parameter is judged at the caller.
    expr = texts[0]
    name = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", expr)
    if name:
        return False
    program = re.match(r'\s*@?"\s*([^\s"$\\]+)', expr)
    if program and program.group(1) not in _SHELLS:
        return False
    return not _constant_piece(code, expr) and bool(re.search(r"\+|\$\{?[A-Za-z_]", expr))


@detector("xpl_shell_command")
def shell_command(ctx: Context, rule: Rule) -> Iterable[Hit]:
    msg = "A shell command is built from a variable; if any part comes from input, it can run other commands."
    for path, code, blank in _files_with(ctx, JVM + NATIVE + DART, ("exec", "ProcessBuilder", "system", "popen",
                                                                   "Process.")):
        if scope_of(path) == "build-script":
            continue                      # a developer's build tool: its input isn't the app's attacker's
        is_c, is_dart = path.endswith(NATIVE), path.endswith(".dart")
        for m in finditer_lit(SHELL_EXEC, blank, ("Runtime", "Process", "system", "popen")):
            call = m.group(0)
            if is_c != call.startswith(("system", "popen")) or is_dart != bool(re.match(r"Process\s*\.", call)):
                continue
            args = _args_of(blank, m.end() - 1)
            if args and _shell_risk(code, blank, path, call, m.start(), args):
                yield _hit_at(ctx, path, code, m.start(), msg, blank)


# ---------------------------------------------------------------------------- XPL-043

# `password.equals("…")`, `"…".equals(username)`, `hckey.getText().toString().equals("…")`, `pin == "…"`.
# Each pattern anchors on the comparison; the operand before it is read from a short window.
_EQ_CALL = re.compile(r"\.\s*(?:equals|equalsIgnoreCase|contentEquals)\s*\(\s*\"([^\"\n]*)\"\s*\)")
_EQ_OP = re.compile(r"(?<![!<>=])===?\s*@?\"([^\"\n]*)\"")
_OPERAND = r"((?:[A-Za-z_]\w*(?:\(\s*\))?[?!]?\s*\.\s*)*[A-Za-z_]\w*(?:\(\s*\))?[?!]?)"
_OPERAND_BEFORE = re.compile(_OPERAND + r"\s*$")
_EQ_CALL_REV = re.compile(r"\"([^\"\n]*)\"\s*\.\s*(?:equals|equalsIgnoreCase)\s*\(\s*" + _OPERAND + r"\s*\)")
_EQ_OP_REV = re.compile(r"@?\"([^\"\n]*)\"\s*===?\s*" + _OPERAND + r"(?![\w(])")
# The compared value names a credential; input-field wrappers (`text`, `getText().toString()`) are dropped first.
_CRED_NAMES = {"password", "passwd", "pwd", "passcode", "pin", "pincode", "passphrase", "secret", "otp", "username",
               "credential", "credentials", "hckey", "vendorkey", "secretkey", "licensekey", "masterkey"}
_INPUT_WRAPPERS = re.compile(r"(?:\s*\.\s*(?:getText|toString|text|trim|trimmed|lowercase|uppercase|toLowerCase|"
                             r"toUpperCase|stringValue|getValue|orEmpty)\b(?:\s*\(\s*\))?[?!]?)+$")
_FIELD_SUFFIX = re.compile(r"(?:TextField|Field|EditText|Input|Text|Txt|Tf|Et|Box|Entry)$")
# A literal that names a field or a state, not a credential value.
_NOT_CRED_VALUE = {"null", "nil", "true", "false", "none", "undefined", "password", "username", "user", "pin",
                   "passcode", "login", "secret", "otp"}


def _credential_operand(expr: str) -> str:
    """The credential a compared expression names (`password` from `passwordTextField.text`), or "" when
    its last name is something else (`user.role`, `field.type`)."""
    base = _INPUT_WRAPPERS.sub("", expr.strip().rstrip("?!"))
    parts = [re.sub(r"\(\s*\)$", "", p.strip()) for p in re.split(r"[.?!]", base) if p.strip()]
    if not parts or (len(parts) > 1 and _identifier_words(parts[-2]) & {"url", "uri", "components", "link"}):
        return ""                             # `proxyUrl.user` is part of an address
    stem = _FIELD_SUFFIX.sub("", parts[-1]) or parts[-1]
    # The name must end with the credential: `passwordField` yes, `showUsernamePreference` no.
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", stem)
    joined = stem.lower().replace("_", "")
    tail = words[-1].lower() if words else ""
    for cred in sorted(_CRED_NAMES):
        if tail == cred or (joined.endswith(cred) and (len(words) < 2 or words[-1].lower() in cred)):
            return cred
    return ""


# Every name in _CRED_NAMES contains one of these (lower case), so an operand with none of them can't match.
# Plain substring tests: a case-insensitive alternation over every file is several times slower.
_CRED_HINTS = ("pass", "pwd", "pin", "secret", "otp", "username", "credential", "hckey", "vendorkey", "licensekey",
               "masterkey")


def _has_cred_hint(text: str) -> bool:
    low = text.lower()
    return any(h in low for h in _CRED_HINTS)


def _credential_compares(code: str, blank: str) -> Iterator[Tuple[int, str]]:
    """(offset, credential) of each comparison of a credential-named value with a literal."""
    found: List[Tuple[int, str, str]] = []            # (operand offset, operand, literal)
    for regex in (_EQ_CALL, _EQ_OP):
        for m in regex.finditer(code):
            window = code[max(0, m.start() - 150):m.start()]
            if not _has_cred_hint(window):
                continue                      # no credential word in the operand's window
            before = _OPERAND_BEFORE.search(window)
            if before:
                found.append((m.start() - len(before.group(0)), before.group(1), m.group(1)))
    for regex in (_EQ_CALL_REV, _EQ_OP_REV):
        for m in regex.finditer(code):
            found.append((m.start(2), m.group(2), m.group(1)))
    for at, expr, value in sorted(found):
        if blank[at:at + len(expr)] != expr:
            continue                          # the operand sits inside a string literal
        v = value.strip()
        if len(v) < 3 or v.lower() in _NOT_CRED_VALUE or "\\(" in v or re.search(r"\$[A-Za-z_{]", v):
            continue                          # empty, a type name, or an interpolated string
        cred = _credential_operand(expr)
        if cred:
            yield at, cred


@detector("xpl_hardcoded_credential_check")
def hardcoded_credential_check(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("equals", "==")):
        if scope_of(path) == "test" or not _has_cred_hint(code) or _test_file(ctx, path):
            continue                          # tests compare against fixed values on purpose
        seen: Set[int] = set()
        for at, cred in _credential_compares(code, blank):
            line = ctx.line_of(code, at)
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, at, f"The `{cred}` is checked against a value written in the code; "
                                                   "anyone who unpacks the app can read it.", blank, mask=True)
    yield from _js_credential_check(ctx)


# ---------------------------------------------------------------------------- XPL-045

# Readings of the clock. Each one starts with one of _CLOCK_STARTS.
CLOCK = re.compile(r"\bSystem\s*\.\s*(?:currentTimeMillis|nanoTime)\s*\(\s*\)|\bSystemClock\s*\.\s*\w+\s*\(\s*\)|"
                   r"\b(?:new\s+)?Date\s*\(\s*\)\s*\.\s*(?:time\b|getTime\s*\(\s*\)|timeIntervalSince1970\b)|"
                   r"\bNSDate\s*\(\s*\)\s*\.\s*timeIntervalSince1970\b|\[\s*(?:\[\s*NSDate\s+date\s*\]|NSDate\s+date)\s+"
                   r"timeIntervalSince1970\s*\]|\bCalendar\s*\.\s*(?:getInstance\s*\(\s*\)\s*\.\s*(?:timeInMillis|"
                   r"getTimeInMillis\s*\(\s*\))|MILLISECOND\b)|\bInstant\s*\.\s*now\s*\(\s*\)\s*\.\s*(?:toEpochMilli|"
                   r"epochSecond|getEpochSecond)\b|\bDateTime\s*\.\s*now\s*\(\s*\)\s*\.\s*(?:millisecondsSinceEpoch|"
                   r"microsecondsSinceEpoch)\b|\bCFAbsoluteTimeGetCurrent\s*\(\s*\)")
_CLOCK_STARTS = ("System", "SystemClock", "Date", "new", "NSDate", "[", "Calendar", "Instant", "DateTime",
                 "CFAbsoluteTimeGetCurrent")
# The assigned name says the value must be unguessable.
_UNGUESSABLE = {"token", "nonce", "otp", "secret", "salt", "iv", "csrf", "xsrf", "verifier", "password", "passcode",
                "sessionid", "sessiontoken", "sessionkey", "random", "rand", "rnd", "challenge", "pin"}
# ...unless it names a time: an expiry, a creation date, a cache stamp.
_TIME_NAME = {"expiry", "expires", "expiration", "expire", "expired", "time", "timestamp", "ts", "date", "created",
              "updated", "issued", "ttl", "age", "last", "at", "since", "until", "duration", "elapsed", "start", "end",
              "deadline", "millis", "ms", "seconds", "valid", "validity", "lifetime", "now", "seed", "refreshed",
              "fetched", "saved", "stored", "request", "requested", "sent", "received"}
_ASSIGNED_NAME = re.compile(r"(?:\b(?:val|var|let|final|String|long|Long|int|Int|double|NSString\s*\*|NSTimeInterval|"
                            r"TimeInterval)\s+)?\b([A-Za-z_]\w*)\s*(?::\s*[\w.?]+)?\s*=(?!=)[^=;\n]*$")


def _named_enclosing_call(blank: str, idx: int) -> str:
    """_enclosing_call, stepping out of grouping parentheses: `getOtp((now / 1000) + offset)` -> getOtp."""
    for _ in range(8):
        depth, i = 0, idx - 1
        while i >= max(0, idx - 400):
            c = blank[i]
            if c == ")":
                depth += 1
            elif c == "(":
                if not depth:
                    break
                depth -= 1
            elif c in "{};" and depth == 0:
                return ""
            i -= 1
        else:
            return ""
        if i < max(0, idx - 400):
            return ""
        name = re.search(r"([A-Za-z_]\w*)\s*$", blank[max(0, i - 80):i])
        if name:
            return name.group(1)
        idx = i                                   # a grouping parenthesis: look further out
    return ""


# Calls that pass the time through unchanged as text or a number: `String.valueOf(now)` is still the clock.
_TIME_AS_TEXT = re.compile(r"(?:get|valueOf|toString|format|String|Long|Integer|Int|toHexString|toLong|toInt|abs|floor"
                           r"|round|div|times|plus|minus|parse\w*|encode\w*"
                           # A hash of the time is as guessable as the time: md5(now), sha256(now), hash(now).
                           r"|(?i:\w*(?:hash|md5|sha1|sha256|sha512|sha|digest|base64)\w*))$")


@detector("xpl_time_based_token")
def time_based_token(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, CODE, ("currentTimeMillis", "nanoTime", "SystemClock", "Date", "Calendar",
                                                    "Instant", "CFAbsoluteTimeGetCurrent")):
        if scope_of(path) == "test" or _test_file(ctx, path):
            continue
        seen: Set[int] = set()
        for m in finditer_lit(CLOCK, blank, _CLOCK_STARTS):
            s, e = _line_span(blank, m.start())
            target = _ASSIGNED_NAME.search(blank[max(s, m.start() - 200):m.start()])
            if not target:
                continue
            words = _words_of(target.group(1))
            found = sorted(words & _UNGUESSABLE)
            rhs = blank[m.start():e]          # other entropy mixed in (`time + random`) is not this rule's case
            if not found or words & _TIME_NAME or re.search(r"(?i)random|uuid", rhs):
                continue
            call = _named_enclosing_call(blank, m.start())
            if re.search(r"(?i)random|seed|srand", call):
                continue                      # a generator seeded with the time: XPL-008's case
            if call and not _TIME_AS_TEXT.match(call):
                continue                      # the time goes into a function (getOtp(now), hmac(key, now)), not out as-is
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"`{target.group(1)}` comes from the clock, so anyone who "
                                                          "knows roughly when it was made can guess it.", blank)
    yield from _js_time_based_token(ctx)


# ---------------------------------------------------------------------------- XPL-047

C_SUFFIXES = (".c", ".cc", ".cpp", ".cxx")
# Unbounded copies into a buffer: the destination is the first argument.
UNBOUNDED_COPY = re.compile(r"(?<![\w.>])(strcpy|strcat|sprintf|vsprintf|gets|wcscpy|wcscat)\s*\(")
# Java strings and arrays handed to native code through JNI.
_JNI_INPUT = re.compile(r"\b(\w+)\s*=\s*(?:\([^()]*\)\s*)?(?:\(\s*\*\s*env\s*\)\s*->|env\s*->)\s*"
                        r"(?:GetStringUTFChars|GetStringChars|GetByteArrayElements|GetStringCritical|"
                        r"GetPrimitiveArrayCritical)\s*\(")


@detector("xpl_native_buffer_overflow")
def native_buffer_overflow(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, C_SUFFIXES, ("strcpy", "strcat", "sprintf", "gets", "wcscpy",
                                                          "wcscat")):
        for m in UNBOUNDED_COPY.finditer(blank):
            args = _args_of(blank, m.end() - 1)
            if not args:
                continue
            start, end, _head = _enclosing_function(blank, m.start(), path)
            body = blank[start:end]
            dest = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", blank[args[0][0]:args[0][1]])
            arrays = text_memo(blank, ("char_arrays", start, end), lambda b=body: set(
                re.findall(r"\bchar\s+([A-Za-z_]\w*)\s*\[\s*[\w+*\s-]+\]", b)))
            if not dest or dest.group(1) not in arrays:
                continue                      # not a fixed-size array declared in this function
            fn = m.group(1)
            if fn == "gets":
                tainted = ["stdin"]
            else:
                inputs = text_memo(blank, ("jni_inputs", start, end), lambda b=body: set(_JNI_INPUT.findall(b)))
                sources = " ".join(blank[s:e] for s, e in args[1:])
                tainted = sorted(inputs & set(re.findall(r"[A-Za-z_]\w*", sources)))
            if tainted:
                yield _hit_at(ctx, path, code, m.start(), f"`{fn}` copies `{tainted[0]}`, a value of any length "
                                                          f"from Java or input, into the fixed buffer "
                                                          f"`{dest.group(1)}`.", blank)



# ---------------------------------------------------------------------------- XPL-046

# Page-controlled values: the URL's query and fragment, the referrer, the window name.
_JS_SOURCE = r"(?:location\s*\.\s*(?:search|hash|href)\b|\bURLSearchParams\b|document\s*\.\s*(?:URL|documentURI|referrer|" \
             r"baseURI)\b|window\s*\.\s*name\b)"
_JS_TAINT = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,300})")
# HTML sinks: assigning markup, writing the document, inserting markup.
_JS_SINK = re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)\s*([^;\n]{1,300})|\bdocument\s*\.\s*write(?:ln)?\s*\("
                      r"([^;\n]{1,300})|\binsertAdjacentHTML\s*\(\s*[^,\n]{1,40},([^;\n]{1,300})")
_SAFE_JS = re.compile(r"\b(?:DOMPurify\s*\.\s*sanitize|escapeHtml|escapeHTML|encodeURIComponent|sanitize\w*)\s*\(")
_BUNDLED_WEB = (".html", ".htm", ".js")
_NOT_BUNDLED = re.compile(r"(?i)(?:^|/)(?:docs?|website|site|fastlane|scripts?|tools?|\.github|node_modules|"
                          r"benchmarks?|e2e|cypress|playwright|coverage|vendor|third[_-]?party)/")
# Native HTML loads: iOS `loadHTMLString("…\(name)…")`, Android `loadData`/`loadDataWithBaseURL(…, "…" + name, …)`.
NATIVE_HTML_LOAD = re.compile(r"\bloadHTMLString\s*\(|\bloadData(?:WithBaseURL)?\s*\(")


def _dom_xss(text: str, in_string: Callable[[int], bool]) -> Iterator[Tuple[int, str]]:
    """(offset, source) of each HTML sink fed by the page URL, directly or through up to two variables."""
    source = re.compile(_JS_SOURCE)
    tainted: Dict[str, str] = {}
    for _ in range(2):                         # `params = new URLSearchParams(…)`, then `name = params.get(…)`
        for m in _JS_TAINT.finditer(text):
            rhs = m.group(2)
            if _SAFE_JS.search(rhs):
                continue                      # escaped or sanitized on the way in
            hit = source.search(rhs)
            if hit:
                tainted.setdefault(m.group(1), hit.group(0))
            else:
                for name in re.findall(r"[A-Za-z_$][\w$]*", rhs):
                    if name in tainted:
                        tainted.setdefault(m.group(1), tainted[name])
                        break
    for m in _JS_SINK.finditer(text):
        if not in_string(m.start()):
            continue
        rhs = next(g for g in m.groups() if g is not None)
        if _SAFE_JS.search(rhs):
            continue
        direct = source.search(rhs)
        if direct:
            yield m.start(), direct.group(0)
            continue
        names = [n for n in re.findall(r"[A-Za-z_$][\w$]*", rhs) if n in tainted]
        if names:
            yield m.start(), tainted[names[0]]


def _input_interpolated(code: str, blank: str, args_code: str, idx: int, path: str) -> str:
    """A value typed by the user (`field.text`, `getText()`) placed into an HTML string, or ""."""
    exprs = [next(x for x in g.groups() if x is not None) for g in INTERP.finditer(args_code)]
    exprs += re.findall(r"\+\s*([A-Za-z_][\w.()]*)", args_code)
    start, _end, _head = _enclosing_function(blank, idx, path)
    for expr in exprs:
        if re.search(r"\.\s*(?:text|getText\s*\(\s*\))\b", expr):
            return expr.strip()
        name = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*", expr)
        if name and re.search(r"\b" + re.escape(name.group(1)) + r"\s*(?::\s*[\w?]+)?\s*=\s*[\w.?]+\s*\.\s*"
                              r"(?:text|getText\s*\(\s*\))\b", code[max(start, idx - 3000):idx]):
            return name.group(1)
    return ""


@detector("xpl_dom_injection")
def dom_injection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*_BUNDLED_WEB):
        if _NOT_BUNDLED.search(path) or scope_of(path) == "test" or path.endswith(".min.js"):
            continue
        if not holds_any(ctx, path, ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML")):
            continue
        text = ctx.text(path) or ""
        for at, src in _dom_xss(text, lambda _i: True):
            line = ctx.line_of(text, at)
            yield Hit(path, line, ctx.snippet(path, line), f"Markup built from `{src}` is written into the page, so a "
                                                           "crafted link runs its own script.")
    for path, code, blank in _files_with(ctx, CODE, ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML")):
        # HTML and scripts kept in string literals of the app's code.
        for at, src in _dom_xss(code, lambda i, c=code, b=blank: c[i] != b[i]):
            yield _hit_at(ctx, path, code, at, f"A bundled page writes markup built from `{src}` into the DOM, so a "
                                               "crafted link runs its own script.", blank)
    for path, code, blank in _files_with(ctx, CODE, ("loadHTMLString", "loadData")):
        for m in NATIVE_HTML_LOAD.finditer(blank):
            args = _args_of(blank, m.end() - 1)
            if not args:
                continue
            html = args[0] if m.group(0).startswith("loadHTMLString") or "WithBaseURL" not in m.group(0) else \
                (args[1] if len(args) > 1 else args[0])
            value = _input_interpolated(code, blank, code[html[0]:html[1]], m.start(), path)
            if value:
                yield _hit_at(ctx, path, code, m.start(), f"Text the user typed (`{value}`) is placed into HTML "
                                                          "without escaping, so it can add its own script.", blank)
    yield from _js_dom_injection(ctx)


# ---------------------------------------------------------------------------- XPL-044

_FILE_SECRET_WORDS = _SECRET_WORDS | {"pwd", "credential", "credentials", "creds"}
# Opening a file for writing in the JVM; the writes that follow go to that file.
_JVM_FILE_OPEN = re.compile(r"\b(?:FileWriter|FileOutputStream|PrintWriter|BufferedWriter|OutputStreamWriter|"
                            r"RandomAccessFile)\s*\(|\bopenFileOutput\s*\(")
_JVM_FILE_WRITE = re.compile(r"\.\s*(?:write|append|print|println)\s*\(|\.\s*(?:writeText|writeBytes|appendText)\s*\(|"
                             r"\bFiles\s*\.\s*(?:write|writeString)\s*\(")
# Kotlin and java.nio writes that name their file themselves: `File(dir, "x").writeText(token)`.
_JVM_DIRECT_WRITE = re.compile(r"\.\s*(?:writeText|writeBytes|appendText)\s*\(|\bFiles\s*\.\s*(?:write|writeString)\s*\(")
# Apple: a plist, data, or string written to a path; Yap and Couchbase documents; cookies.
_APPLE_FILE_WRITE = re.compile(r"\.\s*write\s*\(\s*to(?:File)?\s*:|\bwriteToFile\s*:|\bwriteToURL\s*:|"
                               r"\bcreateFile\s*\(\s*atPath\s*:|\bputProperties\s*\(|\bHTTPCookie\s*\(\s*properties\s*:|"
                               r"\bsetObject\s*\([^;\n]{0,120}\binCollection\s*:")
_DART_FILE_WRITE = re.compile(r"\.\s*writeAs(?:String|Bytes)(?:Sync)?\s*\(")
# The value is protected first, or the "secret" is about it rather than it.
_FILE_PROTECTED = re.compile(r"(?i)encrypt|cipher|\bseal|aead|tink|EncryptedFile|keystore|keychain|hash|digest|sha\d|"
                             r"\bmac\b|wrap")
_NOT_A_FILE_WRITE = re.compile(r"UserDefaults|SharedPreferences|\bprefs?\b|\bLog\b|\bSystem\s*\.\s*out|\bresponse\b|"
                               r"\bsocket\b|\bhttp|\bconnection\b|\boutputStream\s*\(\s*\)|\bconsole\b")


def _key_literals(text: str) -> str:
    """Dictionary keys and names given as literals: `forKey: "password"`, `"password": x`, `.name: "token"`."""
    keys = re.findall(r"forKey\s*:\s*@?\"([^\"\n]{1,60})\"|@?\"([^\"\n]{1,60})\"\s*:|\.name\s*:\s*\"([^\"\n]{1,60})\"|"
                      r"\[\s*\"([^\"\n]{1,60})\"\s*\]\s*=", text)
    return " ".join(k for group in keys for k in group if k)


def _file_secret(ctx: Context, path: str, code: str, blank: str, idx: int, call_end: int) -> List[str]:
    """Secret words in what a file write stores: its arguments and receiver, the keys set on the receiver in
    the same function, or the file's own name (`File(dir, "secret.txt")`)."""
    start, end, _head = _enclosing_function(blank, idx, path)
    start = max(start, idx - 3000)
    line_s, _line_e = _line_span(blank, idx)
    stmt_blank = blank[line_s:call_end]
    if _FILE_PROTECTED.search(blank[start:min(end, idx + 600)]) or _NOT_A_FILE_WRITE.search(stmt_blank):
        return []
    found = set(_words_of(stmt_blank)) & _FILE_SECRET_WORDS
    recv = re.search(r"([A-Za-z_]\w*)\s*\??\s*\.\s*\w+\s*\($|([A-Za-z_]\w*)\s*$", blank[line_s:idx].rstrip(" ."))
    names = [n for n in (recv.groups() if recv else ()) if n]
    args_names = re.findall(r"[A-Za-z_]\w*", blank[idx:call_end])
    scope = code[start:idx]
    for name in set(names + args_names):
        # Keys stored on the object (`data.setValue(password, forKey: "password")`), or the literal it holds.
        for m in re.finditer(r"\b" + re.escape(name) + r"\b[^\n]{0,200}", scope):
            if re.match(re.escape(name) + r"\s*(?:\??\.\s*(?:setValue|setObject|set|put\w*)\s*\(|\[|:\s*\[|=\s*\[|"
                        r"(?::\s*[\w\[\]: ?]+)?\s*=\s*\[)", m.group(0)):
                found |= _words_of(_key_literals(m.group(0))) & _FILE_SECRET_WORDS
    for lit in re.findall(r"\b(?:File|openFileOutput|appendingPathComponent|appendingFormat|appending)\s*\([^;\n]{0,120}?"
                          r"\"([^\"\n]{1,60})\"", scope):
        found |= _words_of(lit) & _FILE_SECRET_WORDS
    return sorted(found)


@detector("xpl_plaintext_secret_file")
def plaintext_secret_file(ctx: Context, rule: Rule) -> Iterable[Hit]:
    # Each language needs its own literal before its write regex can match: a JVM file must open a file.
    candidates = itertools.chain(
        _files_with(ctx, JVM, ("FileWriter", "FileOutputStream", "PrintWriter", "BufferedWriter",
                               "OutputStreamWriter", "RandomAccessFile", "openFileOutput", "writeText", "writeBytes",
                               "appendText", "Files")),
        _files_with(ctx, APPLE, ("write", "createFile", "putProperties", "HTTPCookie", "inCollection")),
        _files_with(ctx, DART, ("writeAs",)))
    for path, code, blank in candidates:
        if scope_of(path) == "test" or _test_file(ctx, path):
            continue
        if path.endswith(JVM):
            if not (_JVM_FILE_OPEN.search(blank) or _JVM_DIRECT_WRITE.search(blank)):
                continue
            regex = _JVM_FILE_WRITE
        elif path.endswith(".dart"):
            regex = _DART_FILE_WRITE
        else:
            regex = _APPLE_FILE_WRITE
        seen: Set[int] = set()
        for m in regex.finditer(blank):
            if path.endswith(JVM) and not re.search(r"writeText|writeBytes|appendText|Files", m.group(0)):
                start = _enclosing_function(blank, m.start(), path)[0]
                if not _JVM_FILE_OPEN.search(blank, max(start, m.start() - 3000), m.start()):
                    continue                  # a write to something other than a file opened here
            open_paren = blank.find("(", m.start())
            call_end = bracket_match(blank, open_paren, "(", ")") if open_paren >= 0 else m.end()
            found = _file_secret(ctx, path, code, blank, m.start(), min(call_end, m.start() + 600))
            line = ctx.line_of(code, m.start())
            if found and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), f"A `{found[0]}` is written to a file in plain text.", blank)
    yield from _js_plaintext_secret_file(ctx)


# ---------------------------------------------------------------------------- XPL-048

SWIFT_EVAL_JS = re.compile(r"\b(?:evaluateJavaScript|callAsyncJavaScript)\s*\(")
# A script that reads the page: a DOM lookup whose text or value is taken, not set.
_DOM_READ = re.compile(r"(?:querySelector(?:All)?|getElementById|getElementsBy\w+)\s*\([^()]*\)\s*(?:\[\s*\d+\s*\]\s*)?"
                       r"\.\s*(?:textContent|innerText|innerHTML|value|getAttribute\s*\([^()]*\))(?!\s*\+?=(?!=))")
_DOM_READ_SENSITIVE = {"account", "accountnumber", "balance", "amount", "iban", "recipient", "payee", "card",
                       "cardnumber", "otp", "token", "password", "passcode", "pin", "total", "price", "beneficiary"}


@detector("xpl_webview_page_world_read")
def webview_page_world_read(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _files_with(ctx, (".swift",), ("evaluateJavaScript", "callAsyncJavaScript")):
        for m in SWIFT_EVAL_JS.finditer(blank):
            args = _args_of(blank, m.end() - 1)
            if not args:
                continue
            script = code[args[0][0]:args[0][1]]
            read = _DOM_READ.search(script)
            if not read:
                continue
            rest = blank[args[0][1]:bracket_match(blank, m.end() - 1, "(", ")") + 1]
            if re.search(r"\bin\s*:\s*(?!nil\b)|\bcontentWorld\s*:|\.defaultClient\b|WKContentWorld\s*\.\s*world", rest):
                if not re.search(r"\.page\b", rest):
                    continue                  # run in an isolated content world
            words = _words_of(" ".join(re.findall(r"['\"]([^'\"\n]{1,80})['\"]", script)) + " " + read.group(0))
            found = sorted(words & _DOM_READ_SENSITIVE)
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"The app reads a `{found[0]}` from the page in the page's "
                                                          "own JavaScript world, where the page can fake the answer.",
                              blank)


# ============================================================================ React Native (JavaScript, TypeScript)
#
# The XPL rules read an RN app's JavaScript and TypeScript only when the project is a React Native app,
# so native projects that carry stray .js files (WebView assets, build scripts) scan as before.

def _last_match(rx: Pattern[str], text: str, start: int, end: int) -> Optional["re.Match[str]"]:
    """The last match of rx in text[start:end] (the nearest one before `end`)."""
    last = None
    for last in rx.finditer(text, start, end):  # noqa: B007
        pass
    return last


def _minified(code: str) -> bool:
    """A bundled or minified file (vendored into the app): few, very long lines."""
    return len(code) > 20_000 and code.count("\n") * 400 < len(code)


def _js_files_with(ctx: Context, needles: Sequence[str]) -> Iterable[Tuple[str, str, str]]:
    """(path, code, blank) of the RN app's JS/TS files holding a needle; none outside RN projects."""
    if not rn.is_react_native(ctx):
        return
    for path, code, blank in _files_with(ctx, JS, needles):
        if path.endswith(".d.ts") or ".min." in path.rsplit("/", 1)[-1] or _minified(code):
            continue
        yield path, code, blank


def _rn_evidence(ctx: Context, key: str, deps: Optional[Pattern[str]], js: Pattern[str],
                 needles: Sequence[str], fold: bool = False) -> bool:
    """Whether an RN app has the protection: a dependency that provides it, or a call to it in JS (in the
    lower-cased code with `fold`). RN libraries are autolinked from node_modules, so they never show up in
    the Podfile or Gradle files."""
    if not rn.is_react_native(ctx):
        return False

    def build() -> bool:
        if deps is not None and any(deps.search(name) for name in rn.package_deps(ctx)):
            return True
        for path, code, _blank in _js_files_with(ctx, needles):
            if scope_of(path) != "test" and js.search(code.lower() if fold else code):
                return True
        return False
    return bool(rn.memo(ctx, "xpl:evidence:" + key, build))


_RN_RASP_DEPS = r"freerasp|talsec|approov|appdome|promon|zimperium|guardsquare|ixguard|dexguard"
RN_ROOT_DEPS = re.compile(_RN_RASP_DEPS + r"|jail-?monkey|root-?detect|jailbreak|rootbeer|is-?device-?rooted|"
                          r"^@react-native-firebase/app-check$|^react-native-attestation|^react-native-device-attest$|"
                          r"play-?integrity")
RN_ROOT_JS = re.compile(r"\bisJailBroken\s*\(|\bisJailbroken\s*\(|\bisRooted\s*\(|\bisDeviceRooted\s*\(|"
                        r"\bJailMonkey\s*\.")
RN_DEBUGGER_DEPS = re.compile(_RN_RASP_DEPS)
RN_DEBUGGER_JS = re.compile(r"\bisDebuggedMode\s*\(|\bisDebuggerAttached\s*\(|\bisDebuggerConnected\s*\(")
RN_EMULATOR_DEPS = re.compile(_RN_RASP_DEPS)
# isEmulator() and Device.isDevice also gate push registration and device labels; only a call near a
# security word (root, tamper, integrity, block) counts as emulator detection.
RN_EMULATOR_JS = re.compile(r"(?i)\b(?:isEmulator(?:Sync)?\s*\(|Device\s*\.\s*isDevice\b|isRealDevice\b)"
                            r"(?=[^;]{0,300}?\b(?:root\w{0,20}|jail\w{0,20}|tamper\w{0,20}|integrity|compromised|security|"
                            r"fraud|rasp|block\w{0,20})\b)|"
                            r"\b(?:root\w{0,20}|jail\w{0,20}|tamper\w{0,20}|integrity|compromised|security|fraud|rasp)\b"
                            r"[^;]{0,300}?\b(?:isEmulator(?:Sync)?\s*\(|Device\s*\.\s*isDevice\b|isRealDevice\b)")
RN_HOOK_DEPS = re.compile(_RN_RASP_DEPS)
RN_HOOK_JS = re.compile(r"\bhookDetected\s*\(|\bisHooked\s*\(|\bisFridaDetected\s*\(")
RN_UPDATE_DEPS = re.compile(r"react-native-version-check|in-app-updates?$|react-native-store-version|"
                            r"react-native-update-check|react-native-force-update|^siren$")
# Matched against lower-cased code (`fold`), so each branch can start with its literal, which the regex
# engine finds much faster than `(?i)\bmin...`; `min(?<!\wmin)` is `\bmin`.
RN_UPDATE_JS = re.compile(r"min(?<!\wmin)(?:imum)?_?(?:supported_?|required_?)?app_?version\b"
                          r"|force(?<!\wforce)_?update_?(?:required|version|app|message|screen)\b"
                          r"|required(?<!\wrequired)_?app_?version\b"
                          r"|app(?<!\wapp)_?version_?(?:expired|unsupported|deprecated)\b"
                          r"|isclientdeprecated(?<!\wisclientdeprecated)\b|itunes\.apple\.com/lookup"
                          # useAppVersionBlockCheck, AppVersionBlocker: a screen that blocks an outdated version
                          r"|version_?block(?:er|ed|check|_?check)")


# Bundled config next to the JS: react-native-config and react-native-dotenv compile `.env` into the app,
# and Expo reads app.json, app.config.json, and eas.json at build time. Example and local-only files don't ship.
_RN_ENV_FILE = re.compile(r"^\.env(?:\.(?!example|sample|template|dist|test|local|development|dev\b)[\w.-]+)?$")
_RN_CONFIG_JSON = {"app.json", "app.config.json", "eas.json"}


# Test files that detect.scope_of doesn't name: url/test.ts, isMarketingURL.tests.ts.
_JS_TEST_NAME = re.compile(r"(?:^|[./])tests?\.[cm]?[jt]sx?$")


def _js_test_path(path: str) -> bool:
    return scope_of(path) == "test" or bool(_JS_TEST_NAME.search(path.rsplit("/", 1)[-1]))


def _rn_js_set(ctx: Context) -> Set[str]:
    """The RN app's JS/TS files that aren't type declarations or minified bundles."""
    def build() -> Set[str]:
        out = set()
        for path in rn.js_files(ctx):
            if path.endswith(".d.ts") or ".min." in path.rsplit("/", 1)[-1] or scope_of(path) == "ci":
                continue                      # GitHub Actions bundles are CI code, not the app
            text = ctx.text(path)
            if text is not None and not _minified(text):
                out.add(path)
        return out
    return rn.memo(ctx, "xpl:jsset", build) if rn.is_react_native(ctx) else set()


def _rn_secret_files(ctx: Context, config: bool = False) -> List[str]:
    """JS/TS files of an RN app, plus (with config) its .env and Expo config files; [] elsewhere."""
    if not rn.is_react_native(ctx):
        return []
    out = sorted(p for p in _rn_js_set(ctx) if not _js_test_path(p))
    if config:
        for path in ctx.files():
            base = path.rsplit("/", 1)[-1]
            if (base in _RN_CONFIG_JSON or _RN_ENV_FILE.match(base)) and scope_of(path) != "test" \
                    and "/node_modules/" not in "/" + path:
                out.append(path)
    return out


# ---------------------------------------------------------------------------- XPL-003 (JS)

# `const API_SECRET = '…'`, `apiKey: "…"`, `this.password = '…'`, `PRIVATE_KEY: string = '…'`. The name
# says the value is a secret; the value must look random (letters and digits, no spaces, long enough).
# A secret-named key or variable set to a literal: `apiSecret = '…'`, `"API_KEY": "…"`. Every name the rule wants ends
# in one of _JS_SECRET_SUFFIX, so matching starts there and walks back to the name (a pattern starting at every
# identifier made this rule the slowest on large apps).
_JS_SECRET_SUFFIX = re.compile(r"(?i)(?:secret|key|token|passwd|password)(?![\w$])")
_JS_ASSIGN_LITERAL = re.compile(r"['\"]?\s*(?::\s*string\s*)?(?<![=!<>])[:=](?!=)\s*(['\"`])([^'\"`\\\n$]{16,200})\1"
                                r"(?!\s*[+\[.])")


# _JS_SECRET_SUFFIX on lower-cased code, literal first, kept only where an assignment of a string follows:
# far fewer matches to check one by one, and the regex engine finds a leading literal much faster.
_JS_SECRET_CANDIDATE = re.compile(r"(?:secret|key|token|passw(?:or)?d)(?![\w$])"
                                  r"(?=['\"]?\s*(?::\s*string\s*)?[:=](?!=)\s*['\"`])")


def _js_named_secrets(code: str, low: Optional[str] = None) -> Iterator[Tuple[int, str, str]]:
    """(name offset, name, value) for each `name = 'literal'` / `name: 'literal'` whose name ends in a secret
    word. `low` is code.lower() when the caller has it."""
    low = code.lower() if low is None else low
    matches = (_JS_SECRET_CANDIDATE.finditer(low) if len(low) == len(code)   # offsets agree (ASCII lower-casing)
               else _JS_SECRET_SUFFIX.finditer(code))
    for m in matches:
        start = m.start()
        lo = max(0, m.end() - 61)
        while start > lo and (code[start - 1].isalnum() or code[start - 1] in "_$"):
            start -= 1
        if start > 0 and (code[start - 1].isalnum() or code[start - 1] in "_$"):
            continue                          # a longer name than any the rule wants
        if m.end() - start < 3 or not (code[start].isalpha() or code[start] in "_$"):
            continue
        a = _JS_ASSIGN_LITERAL.match(code, m.end())
        if a:
            yield start, code[start:m.end()], a.group(2)
_JS_SECRET_NAME = re.compile(r"(?:client|api|app|consumer|private|signing|jwt|hmac|master|encryption)?secret(?:key)?$|"
                             r"(?:api|private|secret|signing|master|admin)key$|(?:access|auth|api|bearer|admin)token$|"
                             r"password$|passwd$")
_JS_NOT_SECRET_NAME = re.compile(r"public|publishable|placeholder|label|title|hint|message|text|field|name$|"
                                 r"storage|header|param|url|endpoint|route|path|type|regex|pattern|error|"
                                 r"prefix|format|selector|test|example|sample|mock|dummy")
# A value that names a thing rather than holding a secret: a public key prefix, a URL, a path, an
# i18n key, a storage key.
_JS_PUBLIC_VALUE = re.compile(r"^(?:pk_|pk\.|AIza|https?://|/|\.|[\w-]+\.[\w.-]+$)|\s")
# JWT libraries whose sign/verify take the shared secret as the second argument.
JWT_LITERAL = re.compile(r"\b(?:jwt|jsonwebtoken|JWT|jws|KJUR\.jws\.JWS)\s*\.\s*(sign|verify|encode|decode)\s*\("
                         r"[^;]{0,300}?,\s*(['\"`])([^'\"`\\\n$]{6,200})\2")
JWT_ENCODED_KEY = re.compile(r"\bnew\s+TextEncoder\s*\(\s*\)\s*\.\s*encode\s*\(\s*(['\"`])([^'\"`\\\n$]{6,200})\1")
# `https://user:pass@host` and base64 of a literal `user:pass` (an HTTP Basic credential).
USERINFO_URL = re.compile(r"(['\"`])(?:https?|wss?|ftp)://([^\s:/@'\"`${}]{1,64}):([^\s:/@'\"`${}]{3,64})@[\w.-]+")
BASIC_LITERAL = re.compile(r"\b(?:btoa|base64\s*\.\s*encode|Base64\s*\.\s*encode|encodeBase64)\s*\(\s*(['\"`])"
                           r"([^'\"`\\\n:$]{1,64}):([^'\"`\\\n$]{3,64})\1\s*\)|"
                           r"\bBuffer\s*\.\s*from\s*\(\s*(['\"`])([^'\"`\\\n:$]{1,64}):([^'\"`\\\n$]{3,64})\4"
                           r"[^;\n]{0,40}?\.\s*toString\s*\(\s*['\"]base64['\"]")
_JS_FAKE_CRED = re.compile(r"(?i)^(?:user(?:name)?|pass(?:word)?|login|admin|test\w*|demo|foo|bar|x+|\*+|"
                           r"<[^>]*>|\.\.\.|anonymous|guest|secret|changeme|example)$")


def _looks_random(value: str) -> bool:
    """Letters and digits mixed, no spaces, not a word or a key name: what a generated secret looks like."""
    v = value.strip()
    if len(v) < 16 or _JS_PUBLIC_VALUE.search(v) or not _real_secret_value(v):
        return False
    if not v.isascii() or not any(re.search(r"[A-Za-z]", run) and re.search(r"\d", run)
                                  for run in re.findall(r"[A-Za-z0-9]{12,}", v)):
        return False                                # words joined by `_` or `-` (a storage key, an event name)
    return len(set(v)) >= 10


def _js_secret_assignment(ctx: Context) -> Iterable[Hit]:
    for path in sorted(_rn_js_set(ctx)):
        if _js_test_path(path) or _test_file(ctx, path):
            continue                          # tests sign in with fixed values on purpose
        if not holds_any(ctx, path, ("ecret", "ECRET", "Key", "KEY", "key", "oken", "OKEN", "assw", "ASSW", "://",
                                     "btoa", "ncode", "Buffer")):
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        low = code.lower()
        found: List[Tuple[int, str, str]] = []                    # (offset, value, message)

        # Each pattern runs only when the code holds a word every match of it contains.
        for m in SECRET_ASSIGN.finditer(code) if "secret" in low else ():
            value = m.group(2) or m.group(3)
            if blank[m.start(1)] == " " or not _real_secret_value(value, m.group(1)) \
                    or re.search(r"\s", value) or not value.isascii() or re.fullmatch(r"[A-Z]?[a-z]+", value) \
                    or _inside_json_literal(code, blank, m.start(1)):
                continue
            found.append((m.start(), value, f"`{m.group(1)}` is set to a literal value, so it ships inside the app."))
        for start, name, value in _js_named_secrets(code, low):
            key = name.lower().replace("_", "")
            if blank[start] == " " or not _JS_SECRET_NAME.search(key) or _JS_NOT_SECRET_NAME.search(key) \
                    or not _looks_random(value):
                continue
            found.append((start, value, f"`{name}` is set to a literal value, so it ships inside the app."))
        for m in JWT_LITERAL.finditer(code) if "jw" in low or "jsonwebtoken" in code else ():
            value = m.group(3)
            if blank[m.start()] == " " or not _real_secret_value(value) or _JS_FAKE_CRED.match(value):
                continue
            found.append((m.start(), value, f"`{m.group(1)}` uses a JWT signing secret written in the code; anyone "
                                             "who unpacks the app can forge tokens."))
        for m in JWT_ENCODED_KEY.finditer(code) if "SignJWT" in code or "jwtVerify" in code else ():
            value = m.group(2)
            if blank[m.start()] == " " or not _real_secret_value(value):
                continue
            found.append((m.start(), value, "A JWT signing secret is written in the code; anyone who unpacks the "
                                             "app can forge tokens."))
        for m in USERINFO_URL.finditer(code) if "://" in code and "@" in code else ():
            user, password = m.group(2), m.group(3)
            if _JS_FAKE_CRED.match(password) or _JS_FAKE_CRED.match(user) and _JS_FAKE_CRED.match(password):
                continue
            found.append((m.start(), password, "A URL carries a user name and password, so they ship inside the app."))
        for m in BASIC_LITERAL.finditer(code) if "btoa" in code or "ncode" in code or "Buffer" in code else ():
            user, password = (m.group(2), m.group(3)) if m.group(2) else (m.group(5), m.group(6))
            if blank[m.start()] == " " or _JS_FAKE_CRED.match(password):
                continue
            found.append((m.start(), password, "An HTTP Basic credential (`user:password`) is written in the code."))
        seen: Set[int] = set()
        for at, value, message in found:
            line = ctx.line_of(code, at)
            if line not in seen:
                seen.add(line)
                yield Hit(path, line, _mask_in(ctx.snippet(path, line), value), message, _hit_scope(ctx, path, at, blank))


# ---------------------------------------------------------------------------- XPL-043 (JS)

_JS_OPERAND = re.compile(r"[A-Za-z_$][\w$]*(?:\(\s*\))?(?:\??\s*\.\s*[A-Za-z_$][\w$]*(?:\(\s*\))?){0,8}")
_JS_EQ = re.compile(r"(?<![!<>=])===?(?!=)")
_JS_LITERAL_AT = re.compile(r"\s*(['\"`])([^'\"`\\\n$]{0,100})\1")
_JS_NAME_AT = re.compile(r"\s*([A-Za-z_$][\w$]*)(?![\w$(.])")
_JS_OPERAND_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.()? \t")
JS_STRING_CONST = re.compile(r"(?:\b(?:const|let|var)\s+|,\s*)([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*"
                             r"(['\"])([^'\"\\\n]{1,100})\2\s*(?=[,;\n])")
_JS_CRED_TAIL = {"pass", "pw"}
_JS_NOT_CRED_VALUE = {"string", "number", "boolean", "object", "function", "symbol", "bigint", "include", "omit",
                      "same-origin"}


def _js_credential(expr: str) -> str:
    cred = _credential_operand(expr)
    if cred:
        return cred
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", expr.rsplit(".", 1)[-1])
    return "password" if words and words[-1].lower() in _JS_CRED_TAIL else ""


def _js_credential_check(ctx: Context) -> Iterable[Hit]:
    for path in sorted(_rn_js_set(ctx)):
        if _js_test_path(path) or _test_file(ctx, path) or not holds_any(ctx, path, ("==",)):
            continue
        code = ctx.code(path) or ""
        if not _has_cred_hint(code):
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        consts = {m.group(1): m.group(3) for m in JS_STRING_CONST.finditer(code) if blank[m.start(1)] != " "}
        found: List[Tuple[int, str, str]] = []                    # (offset, credential, value)
        for eq in _JS_EQ.finditer(blank):
            left, right = _js_operand_before(code, eq.start()), eq.end()
            lit = _JS_LITERAL_AT.match(code, right)
            name = None if lit else _JS_NAME_AT.match(code, right)
            if left is not None:
                at, expr = left
                if lit:
                    found.append((at, _js_credential(expr), lit.group(2)))
                elif name and name.group(1) in consts:
                    found.append((at, _js_credential(expr) or _js_credential(name.group(1)), consts[name.group(1)]))
            rev = _js_literal_before(code, eq.start())
            if rev is not None:
                op = _JS_OPERAND.match(code, right + len(code[right:right + 20]) - len(code[right:right + 20].lstrip()))
                if op and not re.match(r"[\w$(.]", code[op.end():op.end() + 1]):
                    found.append((op.start(), _js_credential(op.group(0)), rev))
        seen: Set[int] = set()
        for at, cred, value in sorted(found):
            v = value.strip()
            if not cred or blank[at] == " " or len(v) < 3 or v.lower() in _NOT_CRED_VALUE | _JS_NOT_CRED_VALUE \
                    or re.search(r"\btypeof\s*$", blank[max(0, at - 20):at]):
                continue                      # `typeof password === 'string'`, fetch's `credentials: 'include'`
            line = ctx.line_of(code, at)
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, at, f"The `{cred}` is checked against a value written in the code; "
                                                   "anyone who unpacks the app can read it.", blank, mask=True)


def _js_operand_before(code: str, idx: int) -> Optional[Tuple[int, str]]:
    """(offset, text) of the member chain that ends just before idx (`this.state.password`), or None."""
    j = idx
    while j > 0 and code[j - 1] in " \t":
        j -= 1
    i = j
    while i > 0 and j - i < 150 and code[i - 1] in _JS_OPERAND_CHARS:
        i -= 1
    while i < j:
        m = _JS_OPERAND.match(code, i)
        if m and m.end() == j:
            return i, m.group(0)
        i += 1
        while i < j and not (code[i].isalpha() or code[i] in "_$") or (i < j and (code[i - 1].isalnum() or code[i - 1] in "_$")):
            i += 1
    return None


def _js_literal_before(code: str, idx: int) -> Optional[str]:
    """The text of the string literal that ends just before idx (`'x' === value`), or None."""
    j = idx
    while j > 0 and code[j - 1] in " \t":
        j -= 1
    if j == 0 or code[j - 1] not in "'\"`":
        return None
    start = code.rfind(code[j - 1], max(0, j - 102), j - 1)
    if start < 0:
        return None
    text = code[start + 1:j - 1]
    return None if any(c in text for c in "\n\\$'\"`") else text


# ---------------------------------------------------------------------------- XPL-009 (JS)

# 'http://host', "ws://host", `http://${host}/api`: fetch, axios, WebSocket and socket.io take plain URLs.
JS_HTTP_URL = re.compile(r"(['\"`])(http|ws)://([^'\"`\s/?#]*)")
# react-native-app-auth: lets the OAuth requests go over plain HTTP.
JS_INSECURE_AUTH = re.compile(r"\bdangerouslyAllowInsecureHttpRequests\s*:\s*true\b")


def _js_http_url(ctx: Context) -> Iterable[Hit]:
    for path in sorted(_rn_js_set(ctx)):
        if scope_of(path) in ("test", "build-script") or _js_test_path(path) or _test_file(ctx, path) \
                or not holds_any(ctx, path, ("http://", "ws://", "dangerouslyAllowInsecureHttpRequests")):
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        seen: Set[int] = set()
        for m in JS_HTTP_URL.finditer(code):
            if blank[m.start()] != m.group(1):
                continue                     # inside another string (a quoted URL in prose)
            host, scheme = m.group(3), m.group(2)
            # `http://${host}` mostly completes an address the user typed; 'http://' + host is a builder.
            built = not host and bool(re.match(r"['\"]\s*\+", code[m.end():m.end() + 6]))
            if not built and (not host or host.startswith(("%", "$", "[")) or host.endswith(".") or "*" in host
                              or SAFE_HOSTS.match(host) or PLACEHOLDER_HOST.match(host) or PRIVATE_IP.match(host)):
                continue
            line_start, line_end = _line_span(code, m.start())
            if _identifier_words(blank[line_start:line_end]) & _NOT_A_FETCH:
                continue
            if re.search(r"\bnew\s+URL\s*\([^()]*,\s*$", blank[line_start:m.start()]):
                continue                     # new URL(path, 'http://base'): a base for parsing a path
            line = ctx.line_of(code, m.start())
            if line in seen:
                continue
            seen.add(line)
            what = "WebSocket" if scheme == "ws" else "HTTP"
            msg = (f"A URL is built on `{scheme}://`, so the request goes out in plain {what}." if built
                   else f"A plain-{what} URL to `{host}`.")
            hit = Hit(path, line, ctx.snippet(path, line), msg, _hit_scope(ctx, path, m.start(), blank))
            prev_start = code.rfind("\n", 0, max(0, line_start - 1)) + 1
            if _BROWSER_OPEN.search(blank[prev_start:line_end]):
                hit.severity = "low"
                hit.message += " It's opened in the browser rather than fetched by the app; still link to https."
            yield hit
        for m in JS_INSECURE_AUTH.finditer(blank):
            line = ctx.line_of(code, m.start())
            if line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, m.start(), "`dangerouslyAllowInsecureHttpRequests: true` lets the "
                                                          "OAuth sign-in requests go over plain HTTP.", blank)


# ---------------------------------------------------------------------------- XPL-010 (JS)

JS_CONSOLE = re.compile(r"(?<![\w$.])console\s*\.\s*(log|info|debug|warn|error|trace)\s*\(")
# A string argument that labels the next argument as a secret: console.log('auth token =', t).
JS_LABEL_THEN_VALUE = re.compile(r"(['\"`])([^'\"`\n]{0,80})\1\s*,\s*([A-Za-z_$][\w$.]*)")
_JS_LABEL_SECRET = re.compile(r"(?i)\b(?:token|password|passwd|secret|bearer|authorization|api[ _-]?key)\s*[:=]?\s*$")
_JS_DERIVED_BEFORE = re.compile(r"(?:!|\btypeof\s+|\bBoolean\s*\(\s*)(?:[A-Za-z_$][\w$]*\s*(?:\?\.|\.)\s*){0,6}$")
_BABEL_FILES = re.compile(r"^(?:babel\.config\.[cm]?js|\.babelrc(?:\.js)?|babel\.config\.json)$")


def _console_stripped(ctx: Context) -> Set[str]:
    """console methods the release bundle removes: babel-plugin-transform-remove-console (minus its
    `exclude` list) or metro's `drop_console`. Empty when nothing strips them."""
    def build() -> Set[str]:
        methods = {"log", "info", "debug", "warn", "error", "trace"}
        for path in ctx.files():
            base = path.rsplit("/", 1)[-1]
            if "/node_modules/" in "/" + path or scope_of(path) == "test":
                continue
            if _BABEL_FILES.match(base) or base == "package.json":
                text = (ctx.code(path) if base.endswith("js") else ctx.text(path)) or ""
                if base == "package.json" and '"babel"' not in text:
                    continue
                # One entry per babel env; the strictest one (fewest exclusions) is taken as production's.
                stripped: Set[str] = set()
                for at in (m.start() for m in re.finditer("transform-remove-console", text)):
                    options = text[at:at + 300].split("]", 1)[0]
                    kept = set(re.findall(r"['\"](error|warn|info|log|debug|trace)['\"]", options)) \
                        if "exclude" in options else set()
                    stripped |= methods - kept
                if stripped:
                    return stripped
            elif re.match(r"metro\.config\.[cm]?js$", base):
                if re.search(r"\bdrop_console\s*:\s*true", ctx.code(path) or ""):
                    return methods
        return set()
    return rn.memo(ctx, "xpl:console-stripped", build) if rn.is_react_native(ctx) else set()


def _js_sensitive_log(ctx: Context) -> Iterable[Hit]:
    stripped = _console_stripped(ctx)
    for path in sorted(_rn_js_set(ctx)):
        if _js_test_path(path) or scope_of(path) == "build-script" or not holds_any(ctx, path, ("console",)):
            continue
        low = ctx.lower(path) or ""
        if not any(w in low for w in ("token", "passw", "secret", "authorization", "bearer", "card", "cvv", "cvc",
                                      "api_key", "apikey", "api key")) or _test_file(ctx, path):
            continue
        bare = ctx.code(path, keep_strings=False) or ""
        full = ctx.code(path) or ""
        seen: Set[int] = set()
        lexical: Optional[bool] = None
        calls = list(JS_CONSOLE.finditer(bare))
        for k, m in enumerate(calls):
            if m.group(1) in stripped:
                continue                      # the release bundle drops this call
            line = ctx.line_of(bare, m.start())
            if line in seen:
                continue                      # this line is already reported
            open_at = m.end() - 1
            close = _close_paren(bare, open_at)
            if bare[close:close + 1] != ")" and k + 1 < len(calls):
                close = min(close, calls[k + 1].start())    # unclosed: its arguments end where the next call starts
            args_code, args_text = bare[open_at:close], full[open_at:close]
            names: List[str] = []
            for w in re.finditer(r"[A-Za-z_$][\w$]*", args_code):
                if not SENSITIVE_WORD.search(w.group(0)):
                    continue
                rest = args_code[w.start():]
                expr = re.match(r"[\w$.]+(?:\(\s*\))?(?:\.[\w$]+(?:\(\s*\d*\s*\))?)*(?:\s*[!=]==?\s*\w+)?", rest)
                text = expr.group(0) if expr else w.group(0)
                if _JS_DERIVED_BEFORE.search(args_code[max(0, w.start() - 80):w.start()]):
                    continue                  # !!token, typeof token, Boolean(token): not the value
                if _secret_expr(text, args_code[:w.start()]):
                    names.append(w.group(0))
            for g in INTERP.finditer(args_text):
                expr = next(x for x in g.groups() if x is not None)
                if SENSITIVE_WORD.search(expr) and _secret_expr(expr, "") \
                        and not expr.strip().startswith(("!", "typeof", "Boolean")):
                    names.append(expr.strip())
            for lab in JS_LABEL_THEN_VALUE.finditer(args_text):
                value = lab.group(3)
                if _JS_LABEL_SECRET.search(lab.group(2)) and not _SAFE_SUFFIX.search(value) \
                        and not _NON_SECRET_ANYWHERE.search(value) and value not in ("undefined", "null"):
                    names.append(value)
            if names and all(n in ("token", "tokens") for n in names):
                if lexical is None:
                    lexical = bool(_LEXICAL_TOKEN_FILE.search(bare))
                if lexical:
                    continue
            if not names:
                continue
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), f"`{names[0]}` is written to the log with "
                      f"`console.{m.group(1)}`, which release builds keep.", _hit_scope(ctx, path, m.start(), bare))


# ---------------------------------------------------------------------------- XPL-012 (JS)

# @react-native-clipboard/clipboard and react-native's old Clipboard: setString; expo-clipboard: setStringAsync.
JS_CLIP = re.compile(r"(?<![\w$])(?:[A-Za-z_$][\w$]*\s*\.\s*)?(setString|setStringAsync)\s*\(")
_JS_DECL = r"(?:const|let|var)\s+{name}\s*(?::\s*[\w<>\[\]| ]{{1,40}})?=\s*([^;\n]{{1,200}})"


def _js_clipboard_secret(ctx: Context) -> Iterable[Hit]:
    for path in sorted(_rn_js_set(ctx)):
        if _js_test_path(path) or _test_file(ctx, path) or not holds_any(ctx, path, ("setString",)):
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        clip = set(rn.names_from(code, "@react-native-clipboard/clipboard", "expo-clipboard", "react-native",
                                 imported=("default", "*", "Clipboard", "setString", "setStringAsync")))
        if not clip:
            continue
        seen: Set[int] = set()
        for m in JS_CLIP.finditer(blank):
            receiver = re.match(r"([A-Za-z_$][\w$]*)\s*\.", m.group(0))
            if (receiver.group(1) if receiver else m.group(1)) not in clip:
                continue
            open_paren = m.end() - 1
            close = bracket_match(blank, open_paren, "(", ")")
            if close - open_paren > 2000:
                continue
            args_blank, args_code = blank[open_paren:close], code[open_paren:close]
            found = _secret_words(args_blank) or _secret_words(" ".join(re.findall(r"['\"`]([^'\"`\n]{1,60})['\"`]",
                                                                                     args_code)))
            arg = re.fullmatch(r"\(\s*([A-Za-z_$][\w$]*)\s*(?:\|\||\?\?)?\s*(?:''|\"\")?\s*", args_code)
            if not found and arg:
                # `Clipboard.setString(t)` after `const t = await AsyncStorage.getItem('@auth_token')`.
                decl = _last_match(re.compile(_JS_DECL.format(name=re.escape(arg.group(1)))), code,
                                   max(0, m.start() - 2000), m.start())
                if decl is not None:
                    # Names in the initializer, and the key a getter reads (`getItem('@auth_token')`), not
                    # words in a message the code builds.
                    keys = re.findall(r"\bget\w*\s*\(\s*['\"`]([^'\"`\n]{1,60})['\"`]", decl.group(1))
                    found = _secret_words(blank[decl.start(1):decl.end(1)]) or _secret_words(" ".join(keys))
            line = ctx.line_of(code, m.start())
            if not found or line in seen or _NON_SECRET_ANYWHERE.search(args_blank):
                continue                      # a push or FCM token identifies a device; it isn't a secret
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), f"A `{found[0]}` is copied to the clipboard, where other apps "
                                                      "and clipboard history can read it; clear it after a short time.",
                          blank)


# ---------------------------------------------------------------------------- JS crypto (XPL-004/006/007/008/011/
#                                                                              013/014/015/016/045)
#
# crypto-js, node-forge, react-native-quick-crypto (and other Node `crypto` shims), and react-native-mmkv.

_JS_CRYPTO_NEEDLES = ("CryptoJS", "crypto-js", "forge", "createCipher", "createDecipher", "createHash", "pbkdf2",
                      "PBKDF2", "MMKV", "generateKeyPair", "generateKeys", "Math.random", "Date.now", "getTime")
_JS_ENC_PARSE = r"(?:[A-Za-z_$][\w$]*\s*\.\s*)*enc\s*\.\s*(?:Utf8|Hex|Latin1|Base64|Utf16)\s*\.\s*parse\s*\(\s*"
_JS_LIT = r"(['\"`])([^'\"`\\\n$]{1,200})"
# A JS function head: `function name(`, `name = (…) =>`, `name: function`, a method `name(…) {`.
_JS_FUNC_HEAD = re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?"
                           r"(?:function\b|\([^()\n]{0,200}\)\s*(?::\s*[\w<>\[\]| ]{1,60})?\s*=>|[A-Za-z_$][\w$]*\s*=>)|"
                           r"^[ \t]*(?:async\s+|static\s+|public\s+|private\s+)*([A-Za-z_$][\w$]*)\s*\([^()\n]{0,200}\)"
                           r"\s*(?::\s*[\w<>\[\]| ]{1,60})?\s*\{", re.MULTILINE)


def _js_context_words(blank: str, idx: int) -> Set[str]:
    """Words of the statement around idx and of the name of the nearest function declared before it."""
    s, e = _line_span(blank, idx)
    words = _identifier_words(blank[s:e])
    head = _last_match(_JS_FUNC_HEAD, blank, max(0, idx - 1500), s)
    if head is not None:
        words |= _identifier_words(next(g for g in head.groups() if g))
    return words


def _js_crypto_sources(ctx: Context) -> List[Tuple[str, str, str]]:
    """(path, code, blank) of the RN app's non-test JS files that may use crypto; computed once."""
    def build() -> List[Tuple[str, str, str]]:
        out = []
        for path in sorted(_rn_js_set(ctx)):
            if _js_test_path(path) or scope_of(path) == "build-script" or not holds_any(ctx, path, _JS_CRYPTO_NEEDLES):
                continue
            if _test_file(ctx, path):
                continue
            out.append((path, ctx.code(path) or "", ctx.code(path, keep_strings=False) or ""))
        return out
    return rn.memo(ctx, "xpl:jscrypto", build) if rn.is_react_native(ctx) else []


def _js_hits(ctx: Context, items: Iterable[Tuple[str, str, str, int, str]], mask: bool = False) -> Iterable[Hit]:
    """One hit per line from (path, code, blank, offset, message)."""
    seen: Set[Tuple[str, int]] = set()
    for path, code, blank, at, msg in items:
        if blank[at:at + 1] == " " and code[at:at + 1] != " ":
            continue                          # inside a string literal
        line = ctx.line_of(code, at)
        if (path, line) not in seen:
            seen.add((path, line))
            yield _hit_at(ctx, path, code, at, msg, blank, mask=mask)


JS_ECB = re.compile(r"\bmode\s*\.\s*ECB\b|(['\"])(?i:aes-(?:128|192|256)-ecb|aes-ecb)\1|(['\"])crypto-js/mode-ecb\2")


def _js_ecb(ctx: Context) -> Iterable[Hit]:
    yield from _js_hits(ctx, ((p, c, b, m.start(), "AES in ECB mode: identical blocks give identical ciphertext.")
                              for p, c, b in _js_crypto_sources(ctx) for m in JS_ECB.finditer(c)))


JS_BROKEN_CIPHER = re.compile(
    r"\b(?:CryptoJS|crypto_?js)\s*\.\s*(DES|TripleDES|RC4|RC4Drop|Blowfish)\s*\.\s*(?:encrypt|decrypt)\s*\(|"
    r"\bcreate(?:De)?[Cc]ipher(?:iv)?\s*\(\s*['\"](des[\w-]*|rc4[\w-]*|rc2[\w-]*|bf[\w-]*|blowfish[\w-]*)['\"]|"
    r"\bcipher\s*\.\s*create(?:De)?[Cc]ipher\s*\(\s*['\"]((?:3DES|DES|RC2)-\w+)['\"]|"
    r"(['\"])crypto-js/(tripledes|rc4|blowfish)\4")


def _js_broken_cipher(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for m in JS_BROKEN_CIPHER.finditer(c):
                algo = next(g for g in (m.group(1), m.group(2), m.group(3), m.group(5)) if g)
                yield p, c, b, m.start(), f"{algo} is a broken or retired cipher."
    yield from _js_hits(ctx, items())


JS_IV_INLINE = re.compile(r"\biv\s*:\s*(?:" + _JS_ENC_PARSE + r"|Buffer\s*\.\s*from\s*\(\s*|forge\s*\.\s*util\s*\."
                          r"createBuffer\s*\(\s*)?(['\"`])[^'\"`\\\n$]{1,200}\1")
JS_IV_ZERO = re.compile(r"\biv\s*:\s*(?:Buffer\s*\.\s*alloc|new\s+Uint8Array)\s*\(\s*\d+\s*\)")
JS_IV_DECL = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$]*(?:iv|IV|Iv|nonce|Nonce|NONCE))\s*(?::\s*[\w.]+\s*)?=\s*"
                        r"(?:" + _JS_ENC_PARSE + r"(['\"`])|Buffer\s*\.\s*(?:from\s*\(\s*(['\"`])|alloc\s*\(\s*\d)|"
                        r"new\s+Uint8Array\s*\(\s*(?:\d|\[)|(['\"`])[^'\"`\n$]{4,})")
JS_CIPHERIV_LITERAL_IV = re.compile(r"\bcreate(?:De)?[Cc]ipheriv\s*\(\s*[^,()]+,\s*[^,]+,\s*(?:Buffer\s*\.\s*"
                                    r"(?:alloc\s*\(\s*\d|from\s*\(\s*['\"`])|['\"`])")


def _js_static_iv(ctx: Context) -> Iterable[Hit]:
    msg = "The IV is a fixed value, so equal messages encrypt to equal ciphertext."

    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for rx in (JS_IV_INLINE, JS_IV_ZERO, JS_CIPHERIV_LITERAL_IV):
                for m in rx.finditer(c):
                    yield p, c, b, m.start(), msg
            used: Optional[Set[str]] = None
            for m in JS_IV_DECL.finditer(c):
                if used is None:              # names passed as an IV anywhere in the file, found once
                    used = set(re.findall(r"\biv\s*:\s*([A-Za-z_$][\w$]*)", b))
                    used |= {a.group(1) for a in re.finditer(r"\bcreate(?:De)?[Cc]ipheriv\s*\([^;()]{0,200}?,[^;()]{0,200}?,"
                                                              r"\s*([A-Za-z_$][\w$]*)", b)}
                    if re.search(r"[{,]\s*iv\s*[,}]", b):
                        used.add("iv")
                if m.group(1) in used:
                    yield p, c, b, m.start(), msg
    yield from _js_hits(ctx, items())


JS_KEY_LITERAL_CALL = re.compile(r"\b(?:AES|DES|TripleDES|Rabbit|RC4|Blowfish)\s*\.\s*(?:encrypt|decrypt)\s*\(\s*"
                                 r"[^,;]{1,200},\s*(?:" + _JS_ENC_PARSE + r")?" + _JS_LIT + r"\1")
JS_KEY_NAME_CALL = re.compile(r"\b(?:AES|DES|TripleDES|Rabbit|RC4|Blowfish)\s*\.\s*(?:encrypt|decrypt)\s*\(\s*"
                              r"[^,;]{1,200},\s*([A-Za-z_$][\w$]*)\s*[,)]")
JS_KEY_DECL = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$]*(?:[Kk]ey|KEY|[Ss]ecret|SECRET|[Pp]assphrase))\s*"
                         r"(?::\s*[\w.]+\s*)?=\s*" + _JS_ENC_PARSE + _JS_LIT + r"\2")
JS_CIPHERIV_LITERAL_KEY = re.compile(r"\bcreate(?:De)?[Cc]ipheriv\s*\(\s*[^,()]+,\s*(?:Buffer\s*\.\s*from\s*\(\s*)?"
                                     + _JS_LIT + r"\1")
JS_MMKV_KEY = re.compile(r"\bencryptionKey\s*:\s*" + _JS_LIT + r"\1")


def _js_hardcoded_key(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for rx in (JS_KEY_LITERAL_CALL, JS_KEY_DECL, JS_CIPHERIV_LITERAL_KEY):
                for m in rx.finditer(c):
                    if not _FAKE_VALUE.match(m.group(rx.groups)):
                        yield p, c, b, m.start(), _KEY_MSG
            if "MMKV" in c:
                for m in JS_MMKV_KEY.finditer(c):
                    if re.search(r"\b(?:new\s+MMKV|createMMKV)\s*\(\s*\{[^}]{0,400}$", b[max(0, m.start() - 400):m.start()]):
                        yield p, c, b, m.start(), ("The MMKV encryption key is written in the code, so anyone who "
                                                   "unpacks the app can decrypt the store.")
            consts = None
            for m in JS_KEY_NAME_CALL.finditer(c):
                if consts is None:
                    consts = {d.group(1): d.group(3) for d in JS_STRING_CONST.finditer(c) if b[d.start(1)] != " "}
                if m.group(1) in consts and not _FAKE_VALUE.match(consts[m.group(1)]):
                    yield p, c, b, m.start(), _KEY_MSG
    yield from _js_hits(ctx, items(), mask=True)


JS_WEAK_HASH = re.compile(r"\b(?:CryptoJS\s*\.\s*)?(MD5|SHA1)\s*\(|\bcreateHash\s*\(\s*['\"](md5|sha1)['\"]|"
                          r"\bmd\s*\.\s*(md5|sha1)\s*\.\s*create\s*\(")


def _js_weak_hash(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            hashers = set(rn.names_from(c, "crypto-js/md5", "crypto-js/sha1")) | {"CryptoJS"}
            for m in JS_WEAK_HASH.finditer(c):
                if m.group(1):
                    recv = re.search(r"([A-Za-z_$][\w$]*)\s*\.\s*$", b[max(0, m.start(1) - 40):m.start(1)])
                    name = recv.group(1) if recv else m.group(1)
                    if name not in hashers and not (recv is None and m.group(1) in hashers):
                        continue
                words = _js_context_words(b, m.start())
                hits = sorted(words & _HASH_SECURITY)
                if hits and not words & _HASH_PROTOCOL:
                    algo = (m.group(1) or m.group(2) or m.group(3)).upper().replace("SHA1", "SHA-1")
                    yield p, c, b, m.start(), f"{algo}, in code that handles `{hits[0]}`."
    yield from _js_hits(ctx, items())


JS_RSA_BITS = re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*(?:\{[^}]{0,200}?\bbits\s*:\s*(\d+)|(\d+))|"
                         r"\bmodulusLength\s*:\s*(\d+)|\bRSA\s*\.\s*generateKeys?\s*\(\s*(\d+)")


def _js_small_key(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for m in JS_RSA_BITS.finditer(c):
                bits = safety.small_int(next(g for g in m.groups() if g))
                if bits is not None and bits < 2048:
                    yield p, c, b, m.start(), f"A {bits}-bit RSA key; use at least 2048 bits (3072 for new keys)."
    yield from _js_hits(ctx, items())


# CryptoJS.PBKDF2(password, salt, { keySize, iterations, hasher }); pbkdf2Sync(password, salt, n, len, digest);
# forge.pkcs5.pbkdf2(password, salt, n, len, md).
JS_PBKDF2 = re.compile(r"\b(?:CryptoJS\s*\.\s*)?PBKDF2\s*\(|\bpbkdf2(?:Sync)?\s*\(")


def _js_kdf_calls(ctx: Context) -> Iterable[Tuple[str, str, str, int, str, Optional[int], str, Optional[str]]]:
    """(path, code, blank, offset, salt text, iterations or None, prf, how the count was set)."""
    deps = rn.package_deps(ctx)
    old_cryptojs = not re.search(r"(?:^|[^\d.])(?:4\.(?:[2-9]|\d\d)|[5-9]\.)", deps.get("crypto-js", ""))
    for p, c, b in _js_crypto_sources(ctx):
        consts = None
        for m in JS_PBKDF2.finditer(b):
            if bracket_match(b, m.end() - 1, "(", ")") - m.end() > 2000:
                continue                      # unclosed, or too long to be one call
            args = rn.call_args(b, m.end() - 1)
            if len(args) < 2:
                continue
            salt = c[args[1][0]:args[1][1]]
            if "PBKDF2" in m.group(0):                        # crypto-js
                opts = c[args[2][0]:args[2][1]] if len(args) > 2 else ""
                it = re.search(r"\biterations\s*:\s*([\w$.]+)", opts)
                hasher = re.search(r"\bhasher\s*:\s*[\w$.]*?(SHA1|SHA256|SHA512|SHA224|SHA384|MD5)\b", opts)
                prf = hasher.group(1).lower() if hasher else ("sha1" if old_cryptojs else "sha256")
                if it is None:
                    yield p, c, b, m.start(), salt, (1 if old_cryptojs else 250_000), prf, "default"
                    continue
                expr = it.group(1)
            else:
                if len(args) < 3:
                    continue
                expr = c[args[2][0]:args[2][1]].strip()
                digest = c[args[4][0]:args[4][1]] if len(args) > 4 else ""
                d = re.search(r"(?i)sha-?(1|256|512)\b", digest)
                prf = "sha" + d.group(1) if d else "sha512"     # unknown: the most lenient floor
            n = safety.small_int(expr.replace("_", ""))
            if n is None and re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
                if consts is None:
                    consts = {d.group(1): d.group(2) for d in
                              re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*number\s*)?=\s*"
                                          r"([\d_]{1,12})\s*[;\n,]", c)}
                n = safety.small_int(consts.get(expr, "").replace("_", ""))
            yield p, c, b, m.start(), salt, n, prf, "explicit"


def _js_pbkdf2_iterations(ctx: Context) -> Iterable[Hit]:
    for p, c, b, at, _salt, n, prf, how in _js_kdf_calls(ctx):
        floor = _PBKDF2_MIN.get(prf, 600_000)
        if n is None or n >= floor:
            continue
        if how == "default" and n == 1:
            msg = ("CryptoJS.PBKDF2 without `iterations` runs a single iteration in crypto-js before 4.2 "
                   f"(CVE-2023-46233); set `iterations` to at least {floor:,}.")
        elif how == "default":
            msg = f"CryptoJS.PBKDF2 without `iterations` runs {n:,}; OWASP's minimum for {prf.upper()} is {floor:,}."
        else:
            msg = f"PBKDF2-HMAC-{prf.upper()} with {n:,} iterations; OWASP's minimum is {floor:,}."
        hit = _hit_at(ctx, p, c, at, msg, b)
        if n >= 100_000:
            hit.severity = "medium"
        yield hit


_JS_LITERAL_VALUE = r"(?:" + _JS_ENC_PARSE + r"|Buffer\s*\.\s*from\s*\(\s*)?['\"`][^'\"`$\n]*['\"`]"
_JS_LITERAL_DECL = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.]+\s*)?=\s*" + _JS_LITERAL_VALUE)


def _js_fixed_salt(ctx: Context) -> Iterable[Hit]:
    literal_names: Dict[str, Set[str]] = {}       # path -> names declared as a literal, found once per file
    for p, c, b, at, salt, _n, _prf, _how in _js_kdf_calls(ctx):
        s = salt.strip()
        literal = bool(re.match(_JS_LITERAL_VALUE, s))
        if not literal and re.fullmatch(r"[A-Za-z_$][\w$]*", s):
            if p not in literal_names:
                literal_names[p] = {d.group(1) for d in _JS_LITERAL_DECL.finditer(c)}
            literal = s in literal_names[p]
        if literal:
            yield _hit_at(ctx, p, c, at, "The password-hashing salt is a fixed value in the code, so every user's "
                                         "derived key can be attacked at once.", b, mask=True)


JS_MATH_RANDOM = re.compile(r"\bMath\s*\.\s*random\s*\(\s*\)")
JS_CLOCK = re.compile(r"\bDate\s*\.\s*now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)\s*\.\s*getTime\s*\(\s*\)")
# Calls that pass a value through: `Math.floor(Math.random() * n)` is still the random value.
_JS_PASS_THROUGH = re.compile(r"(?:\bMath\s*\.\s*(?:floor|round|ceil|trunc|abs)|\bString|\bNumber|\bparseInt|\bBigInt|"
                              r"\bencodeURIComponent)\s*$")


def _js_target(blank: str, idx: int) -> Optional[str]:
    """Where the expression at idx goes: the variable or object key it's assigned to (`const nonce = …`,
    `{ createdAt: … }`), "<return>" when a function returns it, None for a call argument or anything else."""
    depth, i, lo = 0, idx - 1, max(0, idx - 300)
    while i >= lo:
        ch = blank[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth > 0:
                depth -= 1
            elif ch == "(" and (_JS_PASS_THROUGH.search(blank, max(0, i - 40), i) or not re.search(
                    r"[\w$\]).]\s*$", blank[max(0, i - 40):i])):
                pass                          # a pass-through call or a parenthesised expression
            else:
                return None                   # an argument or an element, not an assignment
        elif depth == 0 and ch in ";,\n":
            return None
        elif depth == 0 and ch in ":=":
            prev, nxt = blank[i - 1:i], blank[i + 1:i + 2]
            if ch == "=" and nxt == ">":
                return "<return>"             # an arrow function's expression body
            if not (ch == "=" and (nxt == "=" or prev in ("=", "!", "<", ">"))) and not (ch == ":" and nxt == ":"):
                m = re.search(r"([A-Za-z_$][\w$]*)['\"]?\s*(?::\s*[\w<>\[\]| ]{1,40})?\s*$", blank[max(0, i - 100):i])
                return m.group(1) if m else None
        elif depth == 0 and blank.startswith("return", i) and not re.match(r"[\w$]", blank[i + 6:i + 7]) \
                and not re.match(r"[\w$]", blank[i - 1:i]):
            return "<return>"
        i -= 1
    return None


def _js_random_words(blank: str, idx: int) -> Tuple[Set[str], str]:
    """(security-relevant words, the name) of where a random or clock value goes: its variable or key,
    else the function that returns it."""
    s, e = _line_span(blank, idx)
    name = _js_target(blank, idx)
    if name == "<return>" and re.search(r"[<>]|==|!=|&&|\|\|", blank[s:e].replace("=>", "")):
        return set(), ""                      # the function returns a comparison, not the value
    if name == "<return>":
        head = _last_match(_JS_FUNC_HEAD, blank, max(0, idx - 1500), idx)
        name = next(g for g in head.groups() if g) if head is not None else None
    if not name:
        return set(), ""
    return _identifier_words(name) | {name.lower()}, name


def _js_insecure_random(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for m in JS_MATH_RANDOM.finditer(b):
                words, name = _js_random_words(b, m.start())
                strong = sorted(words & RNG_STRONG)
                if strong and not words & RNG_NON_SECURITY:
                    yield p, c, b, m.start(), (f"`Math.random()` makes `{name}`, a {strong[0]}; it's predictable. "
                                               "Use crypto.getRandomValues or expo-crypto.")
    yield from _js_hits(ctx, items())


def _js_time_based_token(ctx: Context) -> Iterable[Hit]:
    def items():
        for p, c, b in _js_crypto_sources(ctx):
            for m in JS_CLOCK.finditer(b):
                words, name = _js_random_words(b, m.start())
                if words & _UNGUESSABLE and not words & _TIME_NAME:
                    yield p, c, b, m.start(), f"`{name}` is taken from the clock, which an attacker can guess."
    yield from _js_hits(ctx, items())


def _js_sources(ctx: Context, needles: Sequence[str]) -> Iterable[Tuple[str, str, str]]:
    """(path, code, blank) of the RN app's non-test, non-tooling JS files holding a needle."""
    for path in sorted(_rn_js_set(ctx)):
        if _js_test_path(path) or scope_of(path) == "build-script" or not holds_any(ctx, path, needles) \
                or _test_file(ctx, path):
            continue
        yield path, ctx.code(path) or "", ctx.code(path, keep_strings=False) or ""


def _js_literals(text: str) -> str:
    return " ".join(re.findall(r"['\"`]([^'\"`\n]{1,80})['\"`]", text))


# ---------------------------------------------------------------------------- XPL-033 (JSX)

_JSX_SECRET_TYPE = re.compile(r"^(?:password|newPassword|current-password|new-password|oneTimeCode)$")
_JSX_LABEL_BEFORE = re.compile(r">\s*(?:[^<>{}\n]{0,30}\s)?(?:Password|PIN|Passcode|password|passcode)\s*:?\s*<")


def _js_wrapper_masks(ctx: Context, path: str, module: str) -> Optional[bool]:
    """For a project component that wraps TextInput (imported from `module`, a relative path): whether its
    source mentions secureTextEntry. None when it isn't such a wrapper."""
    if not module.startswith("."):
        return None
    folder = path.rsplit("/", 1)[0] if "/" in path else ""
    parts = [p for p in (folder + "/" + module).split("/") if p and p != "."]
    norm: List[str] = []
    for p in parts:
        if p == "..":
            if norm:
                norm.pop()
        else:
            norm.append(p)
    base = "/".join(norm)
    for cand in [base + ext for ext in rn.JS] + [base + "/index" + ext for ext in rn.JS]:
        text = ctx.code(cand) if cand in _rn_js_set(ctx) else None
        if text is not None:
            return None if "<TextInput" not in text else "secureTextEntry" in text
    return None


def _js_unmasked_field(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("TextInput", "Input")):
        if not _FIELD_SECRET.search(code):
            continue
        local = {n: module for n, (module, _imp) in rn.imports(code).items()
                 if module.startswith(".") and n[:1].isupper()}
        names = sorted({"TextInput"} | set(local))
        for el in rn.jsx_elements(code, blank, names):
            if el.spread or "secureTextEntry" in el.props:
                continue
            props = el.props
            texts = [props[k].text(code) for k in ("placeholder", "label", "accessibilityLabel", "testID", "nativeID")
                     if k in props]
            kinds = [props[k].text(code).strip("{}'\" ") for k in ("textContentType", "autoComplete")
                     if k in props]
            values = [props[k].text(code) for k in ("value", "onChangeText") if k in props and props[k].kind == "expr"]
            secret = any(_JSX_SECRET_TYPE.match(k) for k in kinds) \
                or any(_FIELD_SECRET.search(t) for t in texts) \
                or any(_FIELD_SECRET.search(v) for v in values) \
                or bool(_JSX_LABEL_BEFORE.search(code[max(0, el.start - 200):el.start]))
            if not secret or any(re.fullmatch(r"(?i)(?:username|email|text|none|oneTimeCode)", k) for k in kinds):
                continue
            if el.name != "TextInput":
                masks = _js_wrapper_masks(ctx, path, local.get(el.name, ""))
                if masks is None or masks:
                    continue                  # a library input, or a wrapper that handles masking
            yield _hit_at(ctx, path, code, el.start, "A password or PIN `TextInput` has no `secureTextEntry`, so it "
                                                     "shows what's typed.", blank)


# ---------------------------------------------------------------------------- XPL-046 (JSX)

_SANITIZED = re.compile(r"(?i)sanitiz|purify|xss\s*\(|escape\w*\s*\(|encodeHTML|he\s*\.\s*encode")


def _js_dom_injection(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("dangerouslySetInnerHTML", "html")):
        for m in re.finditer(r"\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*", blank):
            expr = code[m.end():m.end() + 300].split("}}", 1)[0]
            if rn.literal(expr) is not rn.UNKNOWN or _SANITIZED.search(expr) or not expr.strip():
                continue
            yield _hit_at(ctx, path, code, m.start(), "`dangerouslySetInnerHTML` inserts a value as markup; "
                                                      "sanitize it or render it as text.", blank)
        for el in rn.jsx_elements(code, blank, ["WebView"]):
            src = el.props.get("source")
            if src is None or src.kind != "expr":
                continue
            html = re.search(r"\bhtml\s*:\s*", blank[src.start:src.end])
            if not html:
                continue
            start = src.start + html.end()
            expr = code[start:src.end]
            dynamic = re.search(r"`[^`]*\$\{", expr) or re.match(r"\s*['\"`][^'\"`]*['\"`]\s*\+", expr)
            if dynamic and not _SANITIZED.search(expr):
                yield _hit_at(ctx, path, code, el.start, "The WebView's HTML is built from variables; a value that "
                                                         "holds markup or script runs in the page.", blank)


# ---------------------------------------------------------------------------- XPL-029 (JS)

_JS_WEBVIEW_SECRET = {"token", "password", "passwd", "secret", "session", "sessionid", "jwt", "accesstoken",
                      "authtoken", "refreshtoken", "cookie", "credentials", "apikey"}


def _js_webview_dom_secret(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("injectedJavaScript", "injectJavaScript")):
        spans: List[Tuple[int, int]] = []
        for el in rn.jsx_elements(code, blank, ["WebView"]):
            for name in ("injectedJavaScript", "injectedJavaScriptBeforeContentLoaded"):
                prop = el.props.get(name)
                if prop is not None and prop.kind == "expr":
                    spans.append((prop.start, prop.end))
        for m in re.finditer(r"\binjectJavaScript\s*\(", blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
            spans.append((m.end(), min(close, m.end() + 3000)))
        for m in re.finditer(r"\b(?:const|let|var)\s+(\w*(?:[Ss]cript|JS|Js))\s*=\s*", blank):
            if re.search(r"\b(?:injectedJavaScript\w*\s*=\s*\{\s*|injectJavaScript\s*\(\s*)" + re.escape(m.group(1))
                         + r"\b", blank):
                end = blank.find(";", m.end(), m.end() + 3000)
                spans.append((m.end(), end if end > 0 else min(len(blank), m.end() + 3000)))
        seen: Set[int] = set()
        for start, end in spans:
            region = code[start:end]
            exprs = " ".join(next(x for x in g.groups() if x is not None) for g in INTERP.finditer(region))
            exprs += " " + " ".join(re.findall(r"\+\s*([A-Za-z_$][\w$.]*)", blank[start:end]))
            found = sorted(_words_of(exprs) & _JS_WEBVIEW_SECRET)
            line = ctx.line_of(code, start)
            if found and line not in seen:
                seen.add(line)
                yield _hit_at(ctx, path, code, start, f"`{found[0]}` is written into the WebView's page script, "
                                                      "where any script on the page can read it.", blank)


# ---------------------------------------------------------------------------- XPL-032 (JS)

_JS_NOTIF_CALL = re.compile(r"\b(?:displayNotification|scheduleNotificationAsync|presentNotificationAsync|"
                            r"createTriggerNotification|localNotification|presentLocalNotification)\s*\(")
_JS_NOTIF_PRIVATE = re.compile(r"\bvisibility\s*:\s*(?:[\w.]*\.)?(?:PRIVATE|SECRET)\b|"
                               r"lockscreenVisibility\s*:\s*(?:[\w.]*\.)?(?:PRIVATE|SECRET)\b")


def _js_notification_secret(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("Notification",)):
        for m in _JS_NOTIF_CALL.finditer(blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
            if close - m.end() > 3000:
                continue
            region_code, region_blank = code[m.end():close], blank[m.end():close]
            if _JS_NOTIF_PRIVATE.search(region_blank):
                continue
            texts = []
            for k in re.finditer(r"\b(?:body|title|subtitle|message|bigText)\s*:\s*", region_blank):
                stop = re.search(r",\s*[A-Za-z_$][\w$]*\s*:|\}", region_blank[k.end():])
                end = k.end() + (stop.start() if stop else 200)
                texts.append((region_code[k.end():end], region_blank[k.end():end]))
            found = sorted(set().union(*(_notif_found(c, b) for c, b in texts)) if texts else set())
            if found:
                yield _hit_at(ctx, path, code, m.start(), f"A notification shows `{found[0]}`, which appears on the "
                                                          "lock screen; set its visibility to private.", blank)


# ---------------------------------------------------------------------------- XPL-034 (JS)

_JS_ANALYTICS_CALL = re.compile(r"\b(?:setUserId|setUserID|setUserProperties|setUserProperty|identify|setUser|"
                                r"setAttributes?|setCustomKey|setPeople|registerSuperProperties)\s*\(")
_JS_ANALYTICS_SDK = ("@react-native-firebase/analytics", "@react-native-firebase/crashlytics", "@segment/analytics-react-native",
                     "@sentry/react-native", "mixpanel-react-native", "@amplitude/analytics-react-native",
                     "@amplitude/react-native", "react-native-appsflyer", "@bugsnag/react-native", "@datadog/mobile-react-native",
                     "posthog-react-native", "@braze/react-native-sdk", "react-native-clevertap", "@intercom/intercom-react-native",
                     "@microsoft/react-native-clarity", "@react-native-firebase/app")


def _js_analytics_pii(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("setUser", "identify", "setAttribute", "setCustomKey", "setPeople",
                                               "registerSuperProperties")):
        if not any(mod in code for mod in _JS_ANALYTICS_SDK):
            continue                          # the call must belong to an analytics or crash SDK
        for m in _JS_ANALYTICS_CALL.finditer(blank):
            close = bracket_match(blank, m.end() - 1, "(", ")")
            if close - m.end() > 1500:
                continue
            args_blank = blank[m.end():close]
            keys = re.findall(r"([A-Za-z_$][\w$]*)\s*[:,}]", args_blank) + re.findall(
                r"['\"]([^'\"\n]{1,40})['\"]\s*[:,]", code[m.end():close])
            words = (_words_of(args_blank) | _words_of(" ".join(keys))) & _PII_WORDS
            if words and not re.search(r"(?i)hash|sha\d*|digest|anonymi|pseudonym", args_blank):
                yield _hit_at(ctx, path, code, m.start(), f"The analytics SDK receives `{sorted(words)[0]}`, which "
                                                          "identifies the user.", blank)


# ---------------------------------------------------------------------------- XPL-036 (JS)

# An environment switch (`staging: 'https://…'`, `isStaging ? … : …`) picks the host at run time; the
# release build uses the production entry.
_JS_ENV_WORDS = {"staging", "stage", "stg", "dev", "develop", "development", "qa", "uat", "sandbox", "test", "testing",
                 "preprod", "local", "env", "environment", "environments", "e2e", "debug", "mock"}
JS_URL_HOST = re.compile(r"['\"`]https?://([A-Za-z0-9.-]+)(?::\d+)?(?=[/'\"`?#:])")
JS_DEBUG_PATH = re.compile(r"['\"`](?:https?://[^'\"`\s/]{1,100}(?:/[\w.-]{1,60}){0,6}|/api(?:/[\w.-]{1,60}){0,6})"
                           r"/(?:__debug\w{0,20}|debug|admin/debug)(?:/|['\"`?])")


def _js_nonprod_endpoint(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("http", "debug")):
        if scope_of(path) == "debug" or re.match(r"app\.config\.", path.rsplit("/", 1)[-1]):
            continue                          # app.config.js runs at build time
        seen: Set[int] = set()
        for m in JS_URL_HOST.finditer(code):
            host = m.group(1).lower().rstrip(".")
            if host in ("10.0.2.2", "10.0.3.2"):
                why = "the Android emulator's host address"
            elif _PRIVATE_HOST.match(host):
                why = "a private network address"
            else:
                continue                      # staging host names sit in build-time environment maps in RN apps
            line = ctx.line_of(code, m.start())
            if line in seen or blank[m.start()] not in "'\"`" or js_dev_guarded(code, blank, m.start()):
                continue
            ls, le = _line_span(blank, m.start())
            words = _identifier_words(blank[ls:le]) | _identifier_words(blank[max(0, ls - 120):ls])
            if words & (_JS_ENV_WORDS | _NOT_A_FETCH):
                continue                      # one entry of an environment switch, or a placeholder
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), f"`{host}` is {why}, in code that ships.", blank)
        for m in JS_DEBUG_PATH.finditer(code):
            line = ctx.line_of(code, m.start())
            if line in seen or blank[m.start()] not in "'\"`" or js_dev_guarded(code, blank, m.start()):
                continue
            seen.add(line)
            yield _hit_at(ctx, path, code, m.start(), "A debug endpoint is called from code that ships.", blank)


# ---------------------------------------------------------------------------- XPL-037 (JS)

JS_OAUTH_BAD: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\busePKCE\s*:\s*false\b"), "an authorization request without PKCE (`usePKCE: false`)"),
    (re.compile(r"\bresponseType\s*:\s*(?:[\w.]*ResponseType\s*\.\s*Token\b|['\"](?:id_token )?token['\"])"),
     "the implicit flow (`responseType: token`)"),
    (re.compile(r"response_type=(?:id_token(?:\+|%20| ))?token\b(?![-_])"), "the implicit flow (`response_type=token`)"),
    (re.compile(r"\bgrant_type\s*[:=]\s*['\"]?password\b|grant_type=password\b"), "the password grant"),
]


def _js_oauth_flow(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("usePKCE", "responseType", "response_type", "grant_type")):
        seen: Set[int] = set()
        for regex, what in JS_OAUTH_BAD:
            for m in regex.finditer(code):
                line = ctx.line_of(code, m.start())
                if "PKCE" in what and re.search(r"code_?[Cc]hallenge", blank[max(0, m.start() - 1500):m.start()]):
                    continue                  # the app sends its own PKCE challenge (through `state`)
                if line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), f"OAuth sign-in uses {what}, which RFC 8252 rules out "
                                                              "for native apps.", blank)


# ---------------------------------------------------------------------------- XPL-044 (JS)

_JS_FILE_WRITE = re.compile(r"\b(?:RNFS|FileSystem|RNFetchBlob\s*\.\s*fs|ReactNativeBlobUtil\s*\.\s*fs|fs)\s*\.\s*"
                            r"(writeFile|appendFile|writeAsStringAsync|write)\s*\(|\bnew\s+File\s*\([^)]{0,200}\)\s*\.\s*"
                            r"(write)\s*\(")
_FILE_SECRET = {"password", "passwd", "passcode", "token", "secret", "mnemonic", "seedphrase", "privatekey",
                "accesstoken", "refreshtoken", "apikey", "credentials", "pin"}


def _js_plaintext_secret_file(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("writeFile", "appendFile", "writeAsStringAsync", ".write(")):
        if not any(mod in code for mod in ("react-native-fs", "expo-file-system", "rn-fetch-blob",
                                           "react-native-blob-util")):
            continue
        for m in _JS_FILE_WRITE.finditer(blank):
            paren = blank.find("(", m.end() - 1)
            if bracket_match(blank, paren, "(", ")") - paren > 2000:
                continue
            args = rn.call_args(blank, paren)
            if not args:
                continue
            region_blank = blank[args[0][0]:args[-1][1]]
            found = sorted((_words_of(region_blank) | _words_of(_js_literals(code[args[0][0]:args[0][1]])))
                           & _FILE_SECRET)
            if not found or re.search(r"(?i)encrypt|cipher|seal", region_blank):
                continue
            yield _hit_at(ctx, path, code, m.start(), f"A `{found[0]}` is written to a file in plain text.", blank)


# ---------------------------------------------------------------------------- XPL-031 (JS)

JS_REALM_SCHEMA_PROP = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*(?:['\"]string\??['\"]|\{\s*type\s*:\s*['\"]string['\"])")
JS_CREATE_TABLE = re.compile(r"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(\w+)[`\"\]]?\s*\(([^;`'\"]{0,2000})\)")
_DB_SECRET_COL = {"password", "passwd", "passcode", "pin", "token", "accesstoken", "refreshtoken", "authtoken",
                  "secret", "privatekey", "mnemonic", "apikey", "sessiontoken", "cvv", "cardnumber"}


def _js_db_plain_credentials(ctx: Context) -> Iterable[Hit]:
    deps = rn.package_deps(ctx)
    encrypted_sqlite = any("sqlcipher" in d for d in deps)
    for path, code, blank in _js_sources(ctx, ("realm", "Realm", "CREATE TABLE", "create table")):
        if "realm" in code and re.search(r"['\"]realm['\"]|@realm/react", code) and "encryptionKey" not in code:
            done = 0                          # end of the text already read (schemas don't nest)
            for m in re.finditer(r"\bproperties\s*:\s*\{", blank):
                close = bracket_match(blank, m.end() - 1, "{", "}")
                start, done = max(m.end(), done), max(done, min(close, m.end() + 3000))
                for p in JS_REALM_SCHEMA_PROP.finditer(code, start, done):
                    name = p.group(1)
                    if (_identifier_words(name) | {name.lower()}) & _DB_SECRET_COL and blank[p.start()] != " ":
                        yield _hit_at(ctx, path, code, p.start(), f"Realm property `{name}` is stored in an "
                                                                  "unencrypted Realm file.", blank)
        if encrypted_sqlite or re.search(r"(?i)PRAGMA\s+key|encryptionKey|SQLCipher", code):
            continue
        if not re.search(r"react-native-sqlite-storage|expo-sqlite|@op-engineering/op-sqlite|react-native-quick-sqlite|"
                         r"react-native-sqlite-2|@nozbe/watermelondb", code):
            continue
        for t in JS_CREATE_TABLE.finditer(code):
            for col in re.split(r",", t.group(2)):
                cm = re.match(r"\s*[`\"\[]?(\w+)[`\"\]]?\s+(?:TEXT|VARCHAR|CHAR|BLOB|STRING)", col, re.IGNORECASE)
                if cm and (_identifier_words(cm.group(1)) | {cm.group(1).lower()}) & _DB_SECRET_COL:
                    yield _hit_at(ctx, path, code, t.start(), f"Column `{cm.group(1)}` of `{t.group(1)}` is stored "
                                                              "in a plain SQLite file.", blank)
                    break


# ---------------------------------------------------------------------------- XPL-018 (JS)

JS_BIO_FALLBACK: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"\bACCESS_CONTROL\s*\.\s*(?:BIOMETRY_ANY_OR_DEVICE_PASSCODE|BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE|"
                r"DEVICE_PASSCODE|USER_PRESENCE)\b"),
     "The Keychain item opens with the device passcode as well as a biometric."),
    (re.compile(r"\ballowDeviceCredentials\s*:\s*true\b"),
     "The biometric prompt accepts the device PIN, pattern, or password instead of a biometric."),
    (re.compile(r"\bdisableDeviceFallback\s*:\s*false\b"),
     "The biometric prompt falls back to the device passcode; for a sensitive action, require biometrics."),
]


def _js_biometric_fallback(ctx: Context) -> Iterable[Hit]:
    for path, code, blank in _js_sources(ctx, ("ACCESS_CONTROL", "allowDeviceCredentials", "disableDeviceFallback")):
        seen: Set[int] = set()
        for regex, what in JS_BIO_FALLBACK:
            for m in regex.finditer(blank):
                line = ctx.line_of(code, m.start())
                if line not in seen:
                    seen.add(line)
                    yield _hit_at(ctx, path, code, m.start(), what, blank)
