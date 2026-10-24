# SPDX-License-Identifier: Apache-2.0
"""Blank out comments (and optionally string contents) so code patterns don't match prose.

Line numbers are preserved: every removed character becomes a space, newlines stay.
Handles nested block comments (Kotlin, Swift, Dart), raw/triple-quoted strings, and char literals.
"""

from __future__ import annotations

import re

LANG_BY_SUFFIX = {
    ".kt": "kotlin", ".kts": "kotlin", ".java": "java", ".swift": "swift",
    ".m": "objc", ".mm": "objc", ".h": "objc", ".dart": "dart",
    ".js": "js", ".ts": "js", ".tsx": "js", ".gradle": "groovy",
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
