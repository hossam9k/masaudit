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
    ".js": "js", ".ts": "js", ".tsx": "js", ".gradle": "groovy",
    ".c": "objc", ".cc": "objc", ".cpp": "objc",
}

NESTED_BLOCK = {"kotlin", "swift", "dart"}


def strip(code: str, lang: str, keep_strings: bool = True) -> str:
    """Return `code` with comments blanked. If keep_strings is False, string contents are blanked too."""
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
