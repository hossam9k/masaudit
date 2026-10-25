# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the React Native detectors (JavaScript and TypeScript source, package.json, Expo config).

The detectors live in rn_storage.py, rn_network.py, rn_webview.py, rn_platform.py, and rn_build.py; this module
holds what several of them need, so each reads the project the same way:

- js_files(ctx): the app's JavaScript/TypeScript files (node_modules and build output are never walked).
- package_deps(ctx): dependency name -> version range, from every package.json outside tests.
- imports(code): local name -> (module, imported name) for ES imports and require().
- jsx_elements(code, blank, names): `<WebView ... />` and the like, with each prop's value span.
- literal(text): the value of a simple literal (string, number, boolean, null, array of those).
- expo_config(ctx): the parsed `expo` object of app.json (app.config.js is code; read it as text).

Everything here is bounded and linear in the size of the input: the code comes from untrusted repositories.
"""

from __future__ import annotations

import bisect
import json
import re
import weakref
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from masaudit import safety
from masaudit.detect import scope_of
from masaudit.engine import Context
from masaudit.textscan import bracket_match, text_memo

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_CACHES: "weakref.WeakKeyDictionary[Context, dict]" = weakref.WeakKeyDictionary()


def memo(ctx: Context, key: str, fn: Callable[[], object]):
    """Compute a project-wide fact once per scan (several React Native rules share it)."""
    store = _CACHES.setdefault(ctx, {})
    if key not in store:
        store[key] = fn()
    return store[key]


def is_react_native(ctx: Context) -> bool:
    return "react-native" in ctx.project.platforms


# A repository's own backend lives beside the app: server/ or backend/ at the top, or packages/server in a monorepo.
# Deeper folders with those names (app/screens/server) are app code.
_BACKEND = re.compile(r"^(?:(?:packages|apps|services)/)?(?:server|backend|api-server)/")


def js_files(ctx: Context) -> List[str]:
    """The app's JavaScript and TypeScript files, tests included (detectors lower their scope); a backend that
    shares the repository (server/, backend/, packages/server/) isn't app code."""
    return memo(ctx, "rn:js-files", lambda: [p for p in ctx.files(*JS) if not _BACKEND.match(p)])


# ---------------------------------------------------------------------------- package.json

def package_deps(ctx: Context) -> Dict[str, str]:
    """dependency name -> version range from dependencies, devDependencies, and peerDependencies of every
    package.json that isn't test code. A monorepo merges its packages; the first range seen wins."""
    def build() -> Dict[str, str]:
        deps: Dict[str, str] = {}
        for path in ctx.files(name="package.json"):
            if scope_of(path) == "test":
                continue
            data = _json(ctx.text(path))
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                block = data.get(section)
                if isinstance(block, dict):
                    for name, version in block.items():
                        if isinstance(name, str):
                            deps.setdefault(name, version if isinstance(version, str) else "")
        return deps
    return memo(ctx, "rn:deps", build)


def as_list(value: object) -> list:
    """`value` when it is a JSON array, else []: config values come from untrusted files, and a number or an
    object where a list belongs must not stop the scan."""
    return value if isinstance(value, list) else []


def has_dep(ctx: Context, *names: str) -> bool:
    deps = package_deps(ctx)
    return any(n in deps for n in names)


def _json(text: Optional[str]) -> object:
    if not text or len(text) > safety.MAX_FILE_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def expo_config(ctx: Context) -> Dict[str, object]:
    """The `expo` object from app.json (or app.json's top level when it has no `expo` key), {} when absent."""
    def build() -> Dict[str, object]:
        for path in ctx.files(name="app.json"):
            if scope_of(path) == "test":
                continue
            data = _json(ctx.text(path))
            if isinstance(data, dict):
                expo = data.get("expo", data)
                if isinstance(expo, dict):
                    return expo
        return {}
    return memo(ctx, "rn:expo", build)


# ---------------------------------------------------------------------------- imports

# `import X from 'm'`, `import X, { a as b } from 'm'`, `import * as X from 'm'`, `import { a } from "m"`.
# `import(?<!\wimport)` is `\bimport` with the literal first, which the regex engine finds much faster.
# The clause starts and ends on a non-space, so the spaces around it can't be split between `\s+` and the
# clause in many ways (a blanked comment after `import` is a long run of spaces).
_IMPORT = re.compile(r"import(?<!\wimport)\s+(?:type\s+)?([^;'\"\s](?:[^;'\"]{0,398}?[^;'\"\s])?)\s+from\s+"
                     r"['\"]([^'\"\n]{1,200})['\"]")
# `const X = require('m')`, `const { a, b: c } = require('m')`, `const X = require('m').default`.
_REQUIRE = re.compile(r"(?:const(?<!\wconst)|let(?<!\wlet)|var(?<!\wvar))\s+(\{[^}]{0,400}\}|[A-Za-z_$][\w$]*)\s*=\s*"
                      r"require\s*\(\s*['\"]([^'\"\n]{1,200})['\"]\s*\)")
_NAME = re.compile(r"[A-Za-z_$][\w$]*")


def imports(code: str) -> Dict[str, Tuple[str, str]]:
    """local name -> (module, imported name). A default import maps to "default", a namespace import to "*".
    Parsed once per text: several rules ask about the same file. Treat the result as read-only."""
    return text_memo(code, ("rn:imports",), lambda: _parse_imports(code))


def _parse_imports(code: str) -> Dict[str, Tuple[str, str]]:
    out: Dict[str, Tuple[str, str]] = {}
    for m in _IMPORT.finditer(code):
        _bind(out, m.group(1), m.group(2))
    for m in _REQUIRE.finditer(code):
        target, module = m.group(1), m.group(2)
        if target.startswith("{"):
            _bind_braces(out, target[1:-1], module, ":")
        else:
            out[target] = (module, "default")
    return out


def _bind(out: Dict[str, Tuple[str, str]], clause: str, module: str) -> None:
    clause = clause.strip()
    brace = clause.find("{")
    if brace >= 0:
        close = clause.find("}", brace)
        _bind_braces(out, clause[brace + 1:close if close > brace else len(clause)], module, " as ")
        clause = clause[:brace]
    for part in clause.split(","):
        part = part.strip()
        star = re.fullmatch(r"\*\s+as\s+([A-Za-z_$][\w$]*)", part)
        if star:
            out[star.group(1)] = (module, "*")
        elif _NAME.fullmatch(part):
            out[part] = (module, "default")


def _bind_braces(out: Dict[str, Tuple[str, str]], inner: str, module: str, rename: str) -> None:
    for item in inner.split(","):
        item = item.strip()
        if item.startswith("type "):
            item = item[5:].strip()
        if not item:
            continue
        if rename in item:
            imported, local = (x.strip() for x in item.split(rename, 1))
        else:
            imported = local = item
        if _NAME.fullmatch(local) and _NAME.fullmatch(imported):
            out[local] = (module, imported)


def names_from(code: str, *modules: str, imported: Sequence[str] = ()) -> List[str]:
    """Local names bound to anything from these modules (or only to these imported names)."""
    return [local for local, (module, name) in imports(code).items()
            if module in modules and (not imported or name in imported)]


# ---------------------------------------------------------------------------- JSX

MAX_TAG = 20_000                    # an element's opening tag, props included; longer ones are skipped


@dataclass
class Prop:
    name: str
    kind: str                         # "string", "expr", or "true" (a bare prop such as `allowFileAccess`)
    start: int                        # value span in the source (inside the quotes or the braces)
    end: int

    def text(self, code: str) -> str:
        return code[self.start:self.end]


@dataclass
class Element:
    name: str
    start: int                        # offset of the `<`
    end: int                          # offset just past the `>` of the opening tag
    props: Dict[str, Prop] = field(default_factory=dict)
    spread: bool = False              # `{...props}`: other props may come from elsewhere


def jsx_elements(code: str, blank: str, names: Sequence[str]) -> Iterator[Element]:
    """Opening tags of the named JSX elements. `code` keeps string contents (for values) and `blank` has
    them blanked (to find braces and the tag's end), as ctx.code(path) and ctx.code(path, False) give."""
    if not names:
        return
    pattern = re.compile(r"<\s*(" + "|".join(re.escape(n) for n in names) + r")(?![\w$.])")
    for m in pattern.finditer(blank):
        if not _starts_jsx(blank, m.start()):
            continue                          # `Array<WebView>` or `a < WebView`: a type or a comparison
        el = _parse_tag(code, blank, m.group(1), m.start(), m.end())
        if el is not None:
            yield el


_ATTR = re.compile(r"[A-Za-z_$][\w$:.-]*")
_JSX_AFTER_WORD = {"return", "yield", "default", "await", "case"}


def _starts_jsx(blank: str, lt: int) -> bool:
    """Whether the `<` at lt can open a JSX element: not right after a name (a generic type, unless the
    name is `return` and the like), a closing bracket, or a number (a comparison)."""
    j = lt - 1
    lo = max(0, lt - 200)
    while j >= lo and blank[j] in " \t\r\n":
        j -= 1
    if j < lo:
        return True
    p = blank[j]
    if p in ")]":
        return False
    if p.isalnum() or p in "_$":
        k = j
        while k >= max(0, j - 10) and (blank[k].isalnum() or blank[k] in "_$"):
            k -= 1
        return blank[k + 1:j + 1] in _JSX_AFTER_WORD
    return True


def _parse_tag(code: str, blank: str, name: str, start: int, i: int) -> Optional[Element]:
    el = Element(name, start, start)
    limit = min(len(blank), start + MAX_TAG)
    while i < limit:
        c = blank[i]
        if c in " \t\r\n":
            i += 1
        elif c == ">" or blank.startswith("/>", i):
            el.end = i + (1 if c == ">" else 2)
            return el
        elif c == "{":
            close = bracket_match(blank, i, "{", "}")
            if close >= limit:
                return None
            if blank[i + 1:close].lstrip().startswith("..."):
                el.spread = True
            i = close + 1
        else:
            a = _ATTR.match(blank, i)
            if not a:
                return None                   # not JSX after all (a comparison, a generic type)
            prop = a.group(0)
            j = a.end()
            while j < limit and blank[j] in " \t\r\n":
                j += 1
            if j < limit and blank[j] == "=":
                j += 1
                while j < limit and blank[j] in " \t\r\n":
                    j += 1
                if j < limit and blank[j] in "\"'":
                    close = blank.find(blank[j], j + 1, limit)
                    if close < 0:
                        return None
                    el.props[prop] = Prop(prop, "string", j + 1, close)
                    i = close + 1
                elif j < limit and blank[j] == "{":
                    close = bracket_match(blank, j, "{", "}")
                    if close >= limit:
                        return None
                    el.props[prop] = Prop(prop, "expr", j + 1, close)
                    i = close + 1
                else:
                    return None
            else:
                el.props[prop] = Prop(prop, "true", a.start(), a.end())
                i = j
    return None


# ---------------------------------------------------------------------------- literals

_STRING = re.compile(r"\s*(?:'([^'\\\n]*)'|\"([^\"\\\n]*)\"|`([^`\\$]*)`)\s*")
_NUMBER = re.compile(r"\s*(-?\d{1,15}(?:\.\d{1,15})?)\s*")


_MAX_NESTING = 8                          # arrays inside arrays: deeper is crafted, not configuration


def literal(text: str, depth: int = 0):
    """The value of a simple literal: a string, a number, true/false/null/undefined, or an array of
    those. A sentinel `UNKNOWN` for anything else (a variable, a call, an expression), and for arrays
    nested deeper than _MAX_NESTING."""
    t = text.strip()
    if len(t) > 2000 or depth > _MAX_NESTING:
        return UNKNOWN
    s = _STRING.fullmatch(t)
    if s:
        return next(g for g in s.groups() if g is not None)
    n = _NUMBER.fullmatch(t)
    if n:
        return float(n.group(1)) if "." in n.group(1) else int(n.group(1))
    if t in ("true", "false"):
        return t == "true"
    if t in ("null", "undefined"):
        return None
    if t.startswith("[") and t.endswith("]"):
        items = [x for x in _split_top(t[1:-1]) if x.strip()]
        values = [literal(x, depth + 1) for x in items]
        return UNKNOWN if any(v is UNKNOWN for v in values) else values
    return UNKNOWN


class _Unknown:
    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN = _Unknown()


def _split_top(text: str) -> List[str]:
    """Split on commas outside brackets and quotes (array items, call arguments)."""
    parts, depth, quote, start = [], 0, "", 0
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def call_args(blank: str, paren: int) -> List[Tuple[int, int]]:
    """Spans of the top-level arguments of the call whose `(` is at `paren`, in `blank` coordinates."""
    close = bracket_match(blank, paren, "(", ")")
    if close >= len(blank):
        return []
    spans, depth, start = [], 0, paren + 1
    for k in range(paren + 1, close):
        c = blank[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, k))
            start = k + 1
    if blank[start:close].strip() or spans:
        spans.append((start, close))
    return spans


# ---------------------------------------------------------------------------- __DEV__ guards

# A debug-only flag. __DEV__ is React Native's own; the others are the usual names apps give their own flag.
_DEV_NAME = r"(?:__DEV__|isDev|IS_DEV|isDevelopment|IS_DEVELOPMENT|isDebug|IS_DEBUG|isDevMode)"
_DEV_POSITIVE = re.compile(r"(?<![\w$!.])(?:[\w$]+\.)?" + _DEV_NAME + r"(?![\w$])"
                           r"|NODE_ENV(?:!==?|!=)['\"]production['\"]|NODE_ENV===?['\"](?:development|test)['\"]")
_DEV_NEGATIVE = re.compile(r"!(?:[\w$]+\.)?" + _DEV_NAME + r"|(?:[\w$]+\.)?" + _DEV_NAME + r"(?:===?false|!==?true)"
                           r"|\(?process\.env\.NODE_ENV===?['\"]production['\"]\)?")
_DEV_FALSE = re.compile(_DEV_NAME + r"(?:===?false|!==?true)")
_DEV_PREFILTER = ("__DEV__", "NODE_ENV", "isDev", "IS_DEV", "isDebug", "IS_DEBUG")
# Condition rewrites before the checks above (spaces already removed): `(__DEV__)` -> `__DEV__`, so
# `!(__DEV__)` reads as negative; `!!__DEV__` -> `__DEV__`; `false===__DEV__` -> `__DEV__===false`.
_DEV_PARENS = re.compile(r"\(((?:[\w$]+\.)?" + _DEV_NAME + r"|process\.env\.NODE_ENV)\)")
_DEV_YODA = re.compile(r"(false|true|'\w+'|\"\w+\")(===?|!==?)((?:[\w$]+\.)?" + _DEV_NAME
                       + r"|process\.env\.NODE_ENV)(?![\w$.])")
_IF = re.compile(r"\bif\s*\(")
_SHORT = re.compile(r"(?<![\w$.!])" + _DEV_NAME + r"\s*(&&|\?)(?![?.])"
                    r"|\bprocess\.env\.NODE_ENV\s*(?:!==?\s*['\"]production['\"]|===?\s*['\"]development['\"])\s*(&&|\?)(?![?.])")
_EXPR_STOP = re.compile(r"[()\[\]{};,:\n]")
_MAX_COND = 600
_MAX_SHORT = 2000


def _dev_condition(cond: str) -> str:
    """`cond` (no spaces) with parentheses around a dev flag dropped, `!!` removed, and constant-first
    comparisons turned around, so the regexes above see one spelling of each condition."""
    for _ in range(8):                             # `((__DEV__))`: one pair per pass
        out = _DEV_PARENS.sub(r"\1", cond)
        if out == cond:
            break
        cond = out
    return _DEV_YODA.sub(r"\3\2\1", cond.replace("!!", ""))


def _compared(keep: str, i: int) -> bool:
    """Whether the dev flag at offset `i` is negated (`! __DEV__`) or the right side of `==`, `===`, `!=`,
    or `!==`."""
    j = i - 1
    while j >= 0 and keep[j] in " \t\r\n":
        j -= 1
    return j >= 0 and (keep[j] == "!" or (keep[j] == "=" and j >= 1 and keep[j - 1] in "=!"))


class DevGuard:
    """Offsets of a JS file that run only in development builds: `if (__DEV__) {...}`, the single statement
    after `if (__DEV__)`, `__DEV__ && expr`, the `?` branch of `__DEV__ ? a : b`, the `else` of
    `if (!__DEV__)`, and the rest of the block after `if (!__DEV__) return`. NODE_ENV comparisons count too.
    Built once per file; asking about an offset is a binary search."""

    def __init__(self, keep: str, blank: str):
        self.starts: List[int] = []
        self.ends: List[int] = []
        if not any(w in blank for w in _DEV_PREFILTER):
            return
        ranges: List[Tuple[int, int]] = []
        early: List[int] = []                      # offsets of `if (!__DEV__) return` ends
        n = len(blank)
        covered = -1                               # end of the furthest __DEV__ `if` body so far
        for m in _IF.finditer(blank):
            if m.start() < covered:
                continue                            # nested in a __DEV__ `if` body: decided by that `if`
            op = m.end() - 1
            close = bracket_match(blank, op, "(", ")")
            if close >= n or close - op > _MAX_COND:
                continue
            cond = _dev_condition(re.sub(r"\s+", "", keep[op + 1:close]))
            if not any(w in cond for w in _DEV_PREFILTER):
                continue
            body_start, body_end = _statement(blank, close + 1)
            if body_start < 0:
                continue
            if ("||" not in cond and "!(" not in cond and _DEV_POSITIVE.search(cond) and not _DEV_FALSE.search(cond)
                    and not _DEV_NEGATIVE.fullmatch(cond)):
                ranges.append((body_start, body_end))
                covered = max(covered, body_end)
            elif _DEV_NEGATIVE.fullmatch(cond):
                covered = max(covered, body_end)
                body = blank[body_start:min(body_end, body_start + 200)].strip().lstrip("{").strip()
                if body_end - body_start < 200 and body.startswith(("return", "throw")) and body.count(";") <= 1:
                    early.append(body_end)
                k = body_end + 1
                while k < n and blank[k] in " \t\r\n":
                    k += 1
                if blank.startswith("else", k) and not re.match(r"else\s+if\b", blank[k:k + 40]):
                    es, ee = _statement(blank, k + 4)
                    if es >= 0:
                        ranges.append((es, ee))
        last_end = -1
        for m in _SHORT.finditer(keep):
            if m.start() < last_end or _compared(keep, m.start()):
                continue                            # inside the previous `__DEV__ &&`, or `false === __DEV__ &&`
            end = _expression_end(blank, m.end(), ":" if "?" in (m.group(1) or m.group(2)) else "")
            ranges.append((m.end(), end))
            last_end = end
        if early:
            ranges.extend(_rest_of_block(blank, early))
        ranges.sort()
        for s, e in ranges:
            if self.ends and s <= self.ends[-1]:
                self.ends[-1] = max(self.ends[-1], e)
            else:
                self.starts.append(s)
                self.ends.append(e)

    def __contains__(self, idx: int) -> bool:
        k = bisect.bisect_right(self.starts, idx) - 1
        return k >= 0 and idx < self.ends[k]


def _statement(blank: str, i: int) -> Tuple[int, int]:
    """The span of the statement starting at or after i: a `{...}` block, or up to `;` or the line end."""
    n = len(blank)
    while i < n and blank[i] in " \t\r\n":
        i += 1
    if i >= n:
        return -1, -1
    if blank[i] == "{":
        return i, min(bracket_match(blank, i, "{", "}"), n)
    end = i
    stop = min(n, i + _MAX_SHORT)
    while end < stop:
        m = _EXPR_STOP.search(blank, end, stop)
        if m is None:
            return i, stop
        c = m.group()
        if c in "([{":
            closer = {"(": ")", "[": "]", "{": "}"}[c]
            end = min(bracket_match(blank, m.start(), c, closer) + 1, n)
        elif c in ";\n" or c in ")]}":
            return i, m.start()
        else:
            end = m.end()
    return i, stop


def _expression_end(blank: str, i: int, extra: str) -> int:
    """Where the operand of `__DEV__ &&` (or the first branch of `__DEV__ ?`) ends."""
    n = len(blank)
    while i < n and blank[i] in " \t\r\n":
        i += 1
    stop = min(n, i + _MAX_SHORT)
    k = i
    while k < stop:
        m = _EXPR_STOP.search(blank, k, stop)
        if m is None:
            return stop
        c = m.group()
        if c in "([{":
            closer = {"(": ")", "[": "]", "{": "}"}[c]
            k = min(bracket_match(blank, m.start(), c, closer) + 1, n)
        elif c in ")]};," or c == "\n" or (c == ":" and extra):
            return m.start()
        else:
            k = m.end()
    return stop


def _rest_of_block(blank: str, offsets: List[int]) -> List[Tuple[int, int]]:
    """For each offset, (offset, end of the innermost block holding it): one walk over the braces."""
    out: List[Tuple[int, int]] = []
    stack: List[int] = []
    events = sorted(offsets)
    e = 0
    for m in re.finditer(r"[{}]", blank):
        while e < len(events) and events[e] < m.start():
            top = stack[-1] if stack else -1
            out.append((events[e], bracket_match(blank, top, "{", "}") if top >= 0 else len(blank)))
            e += 1
        if m.group() == "{":
            stack.append(m.start())
        elif stack:
            stack.pop()
    while e < len(events):
        top = stack[-1] if stack else -1
        out.append((events[e], bracket_match(blank, top, "{", "}") if top >= 0 else len(blank)))
        e += 1
    return out


def dev_guard(code: str, blank: str) -> DevGuard:
    """The DevGuard of a file's text, built once per text (`code` keeps strings, `blank` blanks them)."""
    return text_memo(blank, ("rn:dev_guard",), lambda: DevGuard(code, blank))


def in_dev(code: str, blank: str, idx: int) -> bool:
    """Whether offset idx is in code that runs only in development builds (see DevGuard)."""
    return idx in dev_guard(code, blank)
