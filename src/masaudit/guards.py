# SPDX-License-Identifier: Apache-2.0
"""Is this spot in code that only runs in debug builds?

Detectors use these to report a hit in debug-only code as debug scope (lowered, never dropped).
Every function takes code with comments and strings blanked, and an index into it.
"""

from __future__ import annotations

import re

_IF = re.compile(r"\bif\s*\(")
_SWIFT_IF = re.compile(r"^[ \t]*#if\b([^\n]*)$|^[ \t]*#(?:else|elseif|endif)\b", re.MULTILINE)
_LOOKBACK = 4000


def match(text: str, i: int, opener: str, closer: str) -> int:
    """Index of the bracket closing the one at `i`, or len(text) if it never closes."""
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def _guarded_by(blank: str, idx: int, is_debug) -> bool:
    for m in _IF.finditer(blank, max(0, idx - _LOOKBACK), idx):
        open_paren = m.end() - 1
        close = match(blank, open_paren, "(", ")")
        if close >= idx or not is_debug(re.sub(r"\s+", "", blank[open_paren + 1:close])):
            continue
        j = close + 1
        while j < len(blank) and blank[j] in " \t\r\n":
            j += 1
        if j < len(blank) and blank[j] == "{":
            if j < idx < match(blank, j, "{", "}"):
                return True
        else:
            between = blank[close + 1:idx]
            if ";" not in between and between.count("\n") <= 1:
                return True
    return False


def _jvm_debug(cond: str) -> bool:
    return bool((re.search(r"(?<!!)BuildConfig\.DEBUG\b", cond) and "!BuildConfig.DEBUG" not in cond)
                or ("FLAG_DEBUGGABLE" in cond and "==0" not in cond))


def jvm_debug_guarded(blank: str, idx: int) -> bool:
    """Under `if (BuildConfig.DEBUG)` or an `if (... FLAG_DEBUGGABLE ...)` check (Kotlin, Java)."""
    return _guarded_by(blank, idx, _jvm_debug)


def dart_debug_guarded(blank: str, idx: int) -> bool:
    """Under `if (kDebugMode)` or `if (kProfileMode)` (Flutter)."""
    return _guarded_by(blank, idx, lambda c: bool(re.search(r"(?<!!)\bk(?:Debug|Profile)Mode\b", c)))


def swift_debug_guarded(blank: str, idx: int) -> bool:
    """Inside an `#if DEBUG` branch (Swift, Objective-C). `#else` and `#elseif` leave the branch."""
    stack = []
    for m in _SWIFT_IF.finditer(blank, 0, idx):
        token = m.group(0).strip()
        if token.startswith("#if"):
            cond = m.group(1) or ""
            stack.append(bool(re.search(r"(?<!!)\bDEBUG\b", cond)) and "&&" not in cond)
        elif token.startswith("#endif"):
            if stack:
                stack.pop()
        elif stack:
            stack[-1] = False
    return any(stack)


def debug_guarded(path: str, blank: str, idx: int) -> bool:
    """Pick the right check from the file type."""
    if path.endswith((".kt", ".kts", ".java")):
        return jvm_debug_guarded(blank, idx)
    if path.endswith((".swift", ".m", ".mm", ".h")):
        return swift_debug_guarded(blank, idx)
    if path.endswith(".dart"):
        return dart_debug_guarded(blank, idx)
    return False
