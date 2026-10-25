# SPDX-License-Identifier: Apache-2.0
"""Reference copy of the original character-by-character lexer, kept to prove the fast one
identical (tests/test_lexer.py). Do not use in the scanner.

Blank out comments (and optionally string contents) so code patterns don't match prose.

Line numbers are preserved: every removed character becomes a space, newlines stay.
Handles nested block comments (Kotlin, Swift, Dart), raw/triple-quoted strings, and char literals.
"""

from __future__ import annotations

LANG_BY_SUFFIX = {
    ".kt": "kotlin", ".kts": "kotlin", ".java": "java", ".swift": "swift",
    ".m": "objc", ".mm": "objc", ".h": "objc", ".dart": "dart",
    ".js": "js", ".ts": "js", ".tsx": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".gradle": "groovy",
    ".c": "objc", ".cc": "objc", ".cpp": "objc",
}

NESTED_BLOCK = {"kotlin", "swift", "dart"}


def strip(code: str, lang: str, keep_strings: bool = True) -> str:
    """Return `code` with comments blanked. If keep_strings is False, string contents are blanked too."""
    if lang == "js":
        return _strip_js(code, keep_strings)
    out = []
    i, n = 0, len(code)
    depth = 0
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        # Block comment.
        if c == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth:
                if code[i] == "/" and i + 1 < n and code[i + 1] == "*" and lang in NESTED_BLOCK:
                    depth += 1
                    out.append("  ")
                    i += 2
                    continue
                if code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if code[i] == "\n" else " ")
                i += 1
            continue
        # Line comment.
        if c == "/" and nxt == "/":
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "#" and lang == "groovy" and (i == 0 or code[i - 1] == "\n"):
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
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
                    out.append(opener + "".join("\n" if ch == "\n" else " " for ch in inner)
                               + segment[len(segment) - len(closer):])
                i = end
                continue
        if c in ('"', "'") and not (c == "'" and lang in ("swift",)):
            j = i + 1
            while j < n and code[j] != c and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
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
    inner = "".join("\n" if ch == "\n" else " " for ch in segment[quote_len:-quote_len])
    return segment[:quote_len] + inner + segment[-quote_len:]


# JavaScript / TypeScript, one character at a time: template literals with ${...}, regex literals, and quotes
# that only open a string when they close on the same line.

REGEX_AFTER = "(,=:[!&|?{};+-*%>~^"
REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                  "else", "yield", "await"}
MAX_REGEX = 512
MAX_CLASS = 100


def _is_ident(ch):
    return ch.isalnum() or ch in "_$"


def _text(segment, keep):
    return segment if keep else "".join("\n" if ch == "\n" else " " for ch in segment)


def _regex_allowed(code, i):
    lo = max(0, i - 200)
    j = i - 1
    while j >= lo and code[j] in " \t\r\n":
        j -= 1
    if j < lo:
        return j < 0
    p = code[j]
    if p in REGEX_AFTER:
        return True
    if not _is_ident(p):
        return False
    word = ""
    k = j
    while k >= max(0, j - 12) and _is_ident(code[k]):
        word = code[k] + word
        k -= 1
    return word in REGEX_KEYWORDS and not (k >= 0 and _is_ident(code[k]))


def _regex_end(code, i):
    limit = min(len(code), i + 1 + MAX_REGEX)
    j = i + 1
    while j < limit:
        ch = code[j]
        if ch == "\n":
            return -1
        if ch == "\\":
            if j + 1 >= limit or code[j + 1] == "\n":
                return -1
            j += 2
            continue
        if ch == "[":
            j += 1
            items = 0
            while True:
                if j >= limit or code[j] == "\n":
                    return -1
                if code[j] != "]":
                    items += 1
                    if items > MAX_CLASS:
                        return -1
                if code[j] == "\\":
                    if j + 1 >= limit or code[j + 1] == "\n":
                        return -1
                    j += 2
                    continue
                if code[j] == "]":
                    j += 1
                    break
                j += 1
            continue
        if ch == "/":
            return j + 1 if j > i + 1 else -1
        j += 1
    return -1


def _template(code, i, keep, out, stack):
    start, n = i, len(code)
    while i < n:
        ch = code[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "`":
            out.append(_text(code[start:i], keep) + "`")
            return i + 1
        if ch == "$" and i + 1 < n and code[i + 1] == "{":
            out.append(_text(code[start:i], keep) + "${")
            stack.append(0)
            return i + 2
        i += 1
    out.append(_text(code[start:], keep))
    return n


def _strip_js(code, keep):
    out = []
    stack = []
    dead = {'"': -1, "'": -1}
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if stack and c == "{":
            stack[-1] += 1
            out.append(c)
            i += 1
            continue
        if stack and c == "}":
            out.append(c)
            i += 1
            if stack[-1]:
                stack[-1] -= 1
            else:
                stack.pop()
                i = _template(code, i, keep, out, stack)
            continue
        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n and not (code[i] == "*" and i + 1 < n and code[i + 1] == "/"):
                out.append("\n" if code[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue
        if c == "/" and nxt == "/":
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/":
            end = _regex_end(code, i) if nxt != ">" and _regex_allowed(code, i) else -1
            if end < 0:
                out.append(c)
                i += 1
                continue
            flags = end
            while flags < n and code[flags].isalpha() and code[flags].isascii():
                flags += 1
            out.append(_blank(code[i:end], keep, 1) + code[end:flags])
            i = flags
            continue
        if c == "`":
            out.append(c)
            i = _template(code, i + 1, keep, out, stack)
            continue
        if c in ('"', "'"):
            if i < dead[c]:
                out.append(c)
                i += 1
                continue
            j = i + 1
            while j < n and code[j] != c and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            if j < n and code[j] == c:
                out.append(_blank(code[i:j + 1], keep, 1))
                i = j + 1
            else:
                dead[c] = min(j, n)
                out.append(c)
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)

