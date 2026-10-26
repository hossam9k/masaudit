# SPDX-License-Identifier: Apache-2.0
"""Is this spot in code that only runs in debug builds?

Detectors use these to report a hit in debug-only code as debug scope (lowered, never dropped).
Every function takes code with comments and strings blanked, and an index into it.
"""

from __future__ import annotations

import bisect
import re
from typing import Callable, List, Optional, Pattern

from masaudit.textscan import bracket_match, match, matches_in

_IF = re.compile(r"\bif\s*\(")
_SWIFT_IF = re.compile(r"^[ \t]*#if\b([^\n]*)$|^[ \t]*#(?:else|elseif|endif)\b", re.MULTILINE)
_LOOKBACK = 4000


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


def _swift_once(blank: str, idx: int) -> bool:
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


_PREPROCESSOR = re.compile(r"^[ \t]*#[ \t]*(ifdef|ifndef|if|elif|elseif|else|endif)\b([^\n]*)$", re.MULTILINE)


def _preprocessor_once(blank: str, idx: int) -> bool:
    """Inside an `#if DEBUG`, `#if defined(DEBUG)` or `#ifdef DEBUG` branch (Swift, Objective-C, C).
    `#else` and `#elif` leave the branch; a negated or `||` condition isn't debug-only."""
    stack = []
    for m in _PREPROCESSOR.finditer(blank, 0, idx):
        directive, cond = m.group(1), m.group(2)
        if directive == "ifdef":
            stack.append(bool(re.match(r"\s*DEBUG\b", cond)))
        elif directive == "ifndef":
            stack.append(False)
        elif directive == "if":
            stack.append(bool(re.search(r"\bDEBUG\b", cond)) and "!" not in cond and "||" not in cond)
        elif directive == "endif":
            if stack:
                stack.pop()
        elif stack:
            stack[-1] = False
    return any(stack)


# ---------------------------------------------------------------------------- debug guards, per hit

# guards answers "is this offset in debug-only code?" by walking the file: every `#if` from the top for
# Swift and Objective-C, and every `if (` in the 4000 characters before it, each matched forward to its
# closing bracket, for Kotlin, Java, and Dart. Asked once per hit, that was quadratic on a file with
# thousands of hits. These give guards' exact answers: the bracket walks use bracket_match, and the
# #if stack is computed once per file (as a persistent stack after each directive) so a question only
# replays the directive on its own line.


def guarded_by(blank: str, idx: int, is_debug) -> bool:
    """guarded_by (its _guarded_by, step for step), with bracket_match for match, and the `if (` positions
    in the window looked up from one pass per file rather than scanned per hit."""
    for m in matches_in(blank, _IF, max(0, idx - _LOOKBACK), idx):
        open_paren = m.end() - 1
        close = bracket_match(blank, open_paren, "(", ")")
        if close >= idx or not is_debug(re.sub(r"\s+", "", blank[open_paren + 1:close])):
            continue
        j = close + 1
        while j < len(blank) and blank[j] in " \t\r\n":
            j += 1
        if j < len(blank) and blank[j] == "{":
            if j < idx < bracket_match(blank, j, "{", "}"):
                return True
        else:
            between = blank[close + 1:idx]
            if ";" not in between and between.count("\n") <= 1:
                return True
    return False


def dart_debug(cond: str) -> bool:
    """The condition dart_debug_guarded accepts."""
    return bool(re.search(r"(?<!!)\bk(?:Debug|Profile)Mode\b", cond))


def _swift_effect(m: "re.Match[str]") -> tuple:
    """What _swift_once does with one directive."""
    token = m.group(0).strip()
    if token.startswith("#if"):
        cond = m.group(1) or ""
        return ("push", bool(re.search(r"(?<!!)\bDEBUG\b", cond)) and "&&" not in cond)
    if token.startswith("#endif"):
        return ("pop",)
    return ("clear",)


def _preprocessor_effect(m: "re.Match[str]") -> tuple:
    """What _preprocessor_once does with one directive."""
    directive, cond = m.group(1), m.group(2)
    if directive == "ifdef":
        return ("push", bool(re.match(r"\s*DEBUG\b", cond)))
    if directive == "ifndef":
        return ("push", False)
    if directive == "if":
        return ("push", bool(re.search(r"\bDEBUG\b", cond)) and "!" not in cond and "||" not in cond)
    if directive == "endif":
        return ("pop",)
    return ("clear",)


def _apply(node: Optional[tuple], op: tuple) -> Optional[tuple]:
    """One directive on a persistent stack: node = (top value, rest, any value in the stack)."""
    if op[0] == "push":
        return (op[1], node, op[1] or (node is not None and node[2]))
    if node is None:
        return None                               # pop or clear on an empty stack does nothing
    if op[0] == "pop":
        return node[1]
    return (False, node[1], node[1] is not None and node[1][2])


class _Directives:
    """The #if stack of one text after each directive. A directive pattern is anchored at a line start
    and never crosses a newline, so the directives guards sees before `idx` are this text's directives on
    earlier lines plus at most one on idx's own line, cut off at idx."""

    def __init__(self, blank: str, rx: Pattern[str], effect: Callable[["re.Match[str]"], tuple]):
        self.rx, self.effect = rx, effect
        self.starts: List[int] = []
        self.states: List[Optional[tuple]] = [None]
        node: Optional[tuple] = None
        for m in rx.finditer(blank):
            node = _apply(node, effect(m))
            self.starts.append(m.start())
            self.states.append(node)

    def guarded(self, blank: str, idx: int) -> bool:
        line_start = blank.rfind("\n", 0, idx) + 1
        node = self.states[bisect.bisect_left(self.starts, line_start)]
        if line_start < idx:
            m = self.rx.match(blank, line_start, idx)
            if m:
                node = _apply(node, self.effect(m))
        return node is not None and node[2]


# Recent texts asked about: [text, kind, _Directives once asked twice].
_DIRECTIVES: List[list] = []


def _directive_guarded(blank: str, idx: int, kind: str) -> bool:
    fallback = _swift_once if kind == "swift" else _preprocessor_once
    if not 0 <= idx <= len(blank):
        return fallback(blank, idx)
    for entry in _DIRECTIVES:
        if entry[0] is blank and entry[1] == kind:
            if entry[2] is None:
                entry[2] = (_Directives(blank, _SWIFT_IF, _swift_effect) if kind == "swift"
                            else _Directives(blank, _PREPROCESSOR, _preprocessor_effect))
            return entry[2].guarded(blank, idx)
    _DIRECTIVES.insert(0, [blank, kind, None])
    del _DIRECTIVES[4:]
    return fallback(blank, idx)


def preprocessor_debug_guarded(blank: str, idx: int) -> bool:
    """_preprocessor_once."""
    return _directive_guarded(blank, idx, "preprocessor")


def debug_guarded(path: str, blank: str, idx: int) -> bool:
    """debug_guarded."""
    if path.endswith((".kt", ".kts", ".java")):
        return guarded_by(blank, idx, _jvm_debug)
    if path.endswith((".swift", ".m", ".mm", ".h")):
        return _directive_guarded(blank, idx, "swift")
    if path.endswith(".dart"):
        return guarded_by(blank, idx, dart_debug)
    return False




def jvm_debug_guarded(blank: str, idx: int) -> bool:
    """Under `if (BuildConfig.DEBUG)` or an `if (... FLAG_DEBUGGABLE ...)` check (Kotlin, Java)."""
    return guarded_by(blank, idx, _jvm_debug)


def dart_debug_guarded(blank: str, idx: int) -> bool:
    """Under `if (kDebugMode)` or `if (kProfileMode)` (Flutter)."""
    return guarded_by(blank, idx, dart_debug)


def swift_debug_guarded(blank: str, idx: int) -> bool:
    """Inside an `#if DEBUG` branch (Swift, Objective-C). `#else` and `#elseif` leave the branch."""
    return _directive_guarded(blank, idx, "swift")
