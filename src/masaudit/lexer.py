# SPDX-License-Identifier: Apache-2.0
"""Blank out comments (and optionally string contents) so code patterns don't match prose.

Line numbers are preserved: every removed character becomes a space, newlines stay.
Handles nested block comments (Kotlin, Swift, Dart), raw/triple-quoted strings, and char literals, and in
JavaScript/TypeScript template literals with `${...}`, regex literals, and stray quotes in JSX text.
"""

from __future__ import annotations

import re

LANG_BY_SUFFIX = {
    ".kt": "kotlin", ".kts": "kotlin", ".java": "java", ".swift": "swift",
    ".m": "objc", ".mm": "objc", ".h": "objc", ".dart": "dart",
    ".js": "js", ".ts": "js", ".tsx": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".gradle": "groovy",
    ".c": "objc", ".cc": "objc", ".cpp": "objc",
}

NESTED_BLOCK = {"kotlin", "swift", "dart"}


# Characters that can start a comment or a string. Everything else is copied in one slice, which is
# what keeps the lexer fast on large apps (a per-character Python loop took seconds on Signal).
_SPECIAL = {lang: re.compile(r"[/\"'#r]" if lang == "dart" else r"[/\"'#]")
            for lang in set(LANG_BY_SUFFIX.values())}
_SPECIAL_DEFAULT = re.compile(r"[/\"'#]")
_NOT_NEWLINE = re.compile(r"[^\n]")
_BLOCK_MARK = re.compile(r"/\*|\*/")
# A quoted string's body, up to the closing quote or an unescaped newline (a backslash escapes any
# character, newline included).
_STRING_BODY = {q: re.compile(r"(?:[^%s\\\n]|\\.)*" % q, re.DOTALL) for q in ('"', "'")}


def _spaces(segment: str) -> str:
    """Blank a segment, keeping its newlines so line numbers don't move."""
    return _NOT_NEWLINE.sub(" ", segment)


def strip(code: str, lang: str, keep_strings: bool = True) -> str:
    """Return `code` with comments blanked. If keep_strings is False, string contents are blanked too."""
    if lang == "js":
        return _strip_js(code, keep_strings)
    out = []
    i, n = 0, len(code)
    special = _SPECIAL.get(lang, _SPECIAL_DEFAULT)
    nested = lang in NESTED_BLOCK
    while i < n:
        m = special.search(code, i)
        if m is None:
            out.append(code[i:])
            break
        if m.start() > i:
            out.append(code[i:m.start()])
            i = m.start()
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        # Block comment.
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while depth:
                mark = _BLOCK_MARK.search(code, j)
                if mark is None:
                    j = n
                    break
                if mark.group() == "/*":
                    if nested:
                        depth += 1
                    j = mark.start() + (2 if nested else 1)
                    continue
                depth -= 1
                j = mark.end()
            out.append(_spaces(code[i:j]))
            i = j
            continue
        # Line comment.
        if c == "/" and nxt == "/":
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "#" and lang == "groovy" and (i == 0 or code[i - 1] == "\n"):
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        # Dart raw strings r'...', r"...", r'''...''', r"""...""": backslashes don't escape.
        if (lang == "dart" and c == "r" and nxt in ('"', "'")
                and (i == 0 or not (code[i - 1].isalnum() or code[i - 1] in "_$"))):
            quote = nxt * 3 if code.startswith(nxt * 3, i + 1) else nxt
            j = i + 1 + len(quote)
            while j < n and not code.startswith(quote, j) and not (len(quote) == 1 and code[j] == "\n"):
                j += 1
            end = min(j + len(quote), n) if code.startswith(quote, j) else j
            out.append("r" + _blank(code[i + 1:end], keep_strings, len(quote)))
            i = end
            continue
        # Triple-quoted strings (''' too in Dart).
        triple = '"""' if code.startswith('"""', i) else "'''" if lang == "dart" and code.startswith("'''", i) else ""
        if triple:
            end = code.find(triple, i + 3)
            end = n if end == -1 else end + 3
            out.append(_blank(code[i:end], keep_strings, 3))
            i = end
            continue
        # Swift raw strings #"..."#, ##"..."##, #"""..."""# (closing quote + the same number of #).
        if lang == "swift" and c == "#":
            hashes = 1
            while i + hashes < n and code[i + hashes] == "#":
                hashes += 1
            if code.startswith('"', i + hashes):
                quote = '"""' if code.startswith('"""', i + hashes) else '"'
                opener = "#" * hashes + quote
                closer = quote + "#" * hashes
                end = code.find(closer, i + len(opener))
                end = n if end == -1 else end + len(closer)
                segment = code[i:end]
                if keep_strings or len(segment) <= len(opener) + len(closer):
                    out.append(segment)
                else:
                    inner = segment[len(opener):len(segment) - len(closer)]
                    out.append(opener + _spaces(inner) + segment[len(segment) - len(closer):])
                i = end
                continue
            out.append("#" * hashes)              # no quote follows: the whole run is code (one pass, not one per #)
            i += hashes
            continue
        if c in ('"', "'") and not (c == "'" and lang in ("swift",)):
            j = _STRING_BODY[c].match(code, i + 1).end()
            end = min(j + 1, n)
            out.append(_blank(code[i:end], keep_strings, 1))
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _blank(segment: str, keep: bool, quote_len: int) -> str:
    if keep:
        return segment
    if len(segment) <= 2 * quote_len:
        return segment
    return segment[:quote_len] + _spaces(segment[quote_len:-quote_len]) + segment[-quote_len:]


# ---------------------------------------------------------------------------- JavaScript / TypeScript

_SPECIAL_JS = re.compile(r"[/\"'`]")
_SPECIAL_JS_EXPR = re.compile(r"[/\"'`{}]")       # inside a template's ${...}: braces count too
_TEMPLATE_STOP = re.compile(r"[\\`$]")
# A `/` starts a regex literal after these (an operator or an opening bracket), and after these keywords;
# after a name, a number, or a closing bracket it divides.
# Not `<`: in JSX, `</Text>` closes a tag.
_REGEX_AFTER = set("(,=:[!&|?{};+-*%>~^")
_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                   "else", "yield", "await"}
_LOOKBACK = 200             # whitespace skipped to find what comes before a `/`
MAX_REGEX = 512             # a regex literal must close within this many characters, on the same line
MAX_CLASS = 100             # and each [...] class within this many items, so unclosed `/[` can't cost 512 each
_REGEX_BODY = re.compile(r"(?:[^\\/\[\n]|\\.|\[(?:[^\]\\\n]|\\.){0,%d}\])*/" % MAX_CLASS)


def _ident(ch: str) -> bool:
    return ch.isalnum() or ch in "_$"


def _regex_allowed(code: str, i: int) -> bool:
    """Whether the `/` at i starts a regex literal rather than dividing, from what comes before it."""
    j, lo = i - 1, max(0, i - _LOOKBACK)
    while j >= lo and code[j] in " \t\r\n":
        j -= 1
    if j < lo:
        return j < 0                          # the start of the file, or too much whitespace to tell
    p = code[j]
    if p in _REGEX_AFTER:
        return True
    if not _ident(p):
        return False
    k, lo = j, max(0, j - 12)               # keywords are at most 10 characters
    while k >= lo and _ident(code[k]):
        k -= 1
    return code[k + 1:j + 1] in _REGEX_KEYWORDS and not (k >= 0 and _ident(code[k]))


_BODY_STOP = re.compile(r"[/\[\\\n]")
_CLASS_STOP = re.compile(r"[\]\\\n]")


def _regex_end(code: str, i: int) -> int:
    """The index just past the regex literal whose `/` is at i, or -1 when none closes within MAX_REGEX
    characters on the same line (then the `/` is division or stray text). The same answer as matching
    _REGEX_BODY on that window, but it jumps between the characters that matter instead of stepping
    the regex engine through every class item, which made a file of unclosed `/[` slow."""
    limit = min(len(code), i + 1 + MAX_REGEX)
    j = i + 1
    while True:
        m = _BODY_STOP.search(code, j, limit)
        if m is None:
            return -1
        j = m.start()
        c = code[j]
        if c == "/":
            return j + 1 if j > i + 1 else -1           # `//` is a comment, not an empty regex
        if c == "\n":
            return -1
        if c == "\\":
            if j + 1 >= limit or code[j + 1] == "\n":
                return -1
            j += 2
            continue
        # A [...] class of at most MAX_CLASS items, each one character or an escape of two, so its `]`
        # comes within 2 * MAX_CLASS + 1 characters or not at all.
        if code.find("]", j + 1, min(limit, j + 2 + 2 * MAX_CLASS)) < 0:
            return -1
        k, items = j + 1, 0
        while True:
            m = _CLASS_STOP.search(code, k, min(limit, k + 2 * MAX_CLASS + 1))
            if m is None:
                return -1
            p = m.start()
            items += p - k
            if items > MAX_CLASS:
                return -1
            if code[p] == "]":
                j = p + 1
                break
            if code[p] == "\n" or p + 1 >= limit or code[p + 1] == "\n":
                return -1
            items += 1
            k = p + 2


def _template(code: str, i: int, keep: bool, out: list, stack: list) -> int:
    """Copy a template literal's text from i (just past the opening backtick or a closing `}` of `${...}`),
    blanked unless keep, up to its closing backtick or the next `${`. Returns where scanning resumes."""
    start, n = i, len(code)
    while True:
        m = _TEMPLATE_STOP.search(code, i)
        if m is None:
            text = code[start:]
            out.append(text if keep else _spaces(text))
            return n
        k = m.start()
        if code[k] == "\\":
            i = k + 2
            continue
        if code[k] == "`":
            text = code[start:k]
            out.append((text if keep else _spaces(text)) + "`")
            return k + 1
        if code.startswith("${", k):
            text = code[start:k]
            out.append((text if keep else _spaces(text)) + "${")
            stack.append(0)
            return k + 2
        i = k + 1                             # a `$` on its own is text


def _strip_js(code: str, keep: bool) -> str:
    out: list = []
    stack: list = []                          # brace depth inside each open template `${...}`
    # Where the last scan for an unclosed ' or " stopped. A same quote before that point was part of an escape in
    # that scan, so scanning from it would stop at the same place: it is text too (and the line stays linear).
    dead = {'"': -1, "'": -1}
    i, n = 0, len(code)
    while i < n:
        m = (_SPECIAL_JS_EXPR if stack else _SPECIAL_JS).search(code, i)
        if m is None:
            out.append(code[i:])
            break
        if m.start() > i:
            out.append(code[i:m.start()])
            i = m.start()
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if c == "{":
            stack[-1] += 1
            out.append(c)
            i += 1
        elif c == "}":
            out.append(c)
            i += 1
            if stack[-1]:
                stack[-1] -= 1
            else:
                stack.pop()                   # the `}` that closes `${...}`: back to the template's text
                i = _template(code, i, keep, out, stack)
        elif c == "/" and nxt == "*":
            end = code.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append(_spaces(code[i:end]))
            i = end
        elif c == "/" and nxt == "/":
            end = code.find("\n", i)
            end = n if end == -1 else end
            out.append(" " * (end - i))
            i = end
        elif c == "/":
            # `/>` ends a JSX element; otherwise the token before decides between a regex and division.
            end = _regex_end(code, i) if nxt != ">" and _regex_allowed(code, i) else -1
            if end < 0:
                out.append(c)
                i += 1
            else:
                flags = end
                while flags < n and code[flags].isalpha() and code[flags].isascii():
                    flags += 1
                out.append(_blank(code[i:end], keep, 1) + code[end:flags])
                i = flags
        elif c == "`":
            out.append(c)
            i = _template(code, i + 1, keep, out, stack)
        else:                                 # a quote: a string only when it closes on the same line
            j = _STRING_BODY[c].match(code, i + 1).end() if i >= dead[c] else -1
            if 0 <= j < n and code[j] == c:
                out.append(_blank(code[i:j + 1], keep, 1))
                i = j + 1
            else:
                if j >= 0:
                    dead[c] = j
                out.append(c)                 # an apostrophe in JSX text (`Don't`), not a string
                i += 1
    return "".join(out)

