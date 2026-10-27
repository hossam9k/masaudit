# SPDX-License-Identifier: Apache-2.0
"""Findings in a function nothing calls.

A Kotlin function, or a private or static Java method, whose name appears nowhere else in the project
doesn't run, so its findings get the scope `unused` (lowered like unshipped code). Every source, resource,
build, and config file is searched, with only comments left out: a name in a string (reflection), a layout
(`android:onClick`), a keep rule, native code (JNI), or another language counts as a call. A name that only
appears in its own declarations and bodies (overloads that call each other, recursion) is not called.

Only functions nothing outside the source can call by name are judged: not an override, operator, or
external function; no annotation except ones that don't make a function an entry point (`@Throws`,
`@Composable`, `@Deprecated`…); and, unless private, only in an Android app module, since apps outside the
repository call a library's public functions. Nothing is lowered when the file listing was cut short.
"""

from __future__ import annotations

import bisect
import os
import re
from typing import Dict, List, Optional, Set

from masaudit import lexer, safety
from masaudit.textscan import bracket_match

# Files that can name a Kotlin or Java function: code in any language (JNI, React Native and Flutter bridges,
# Swift through Kotlin Multiplatform), layouts and manifests, keep rules, build scripts, and config.
_REF_SUFFIXES = (".kt", ".kts", ".java", ".scala", ".groovy", ".gradle", ".xml", ".pro", ".cfg", ".txt", ".c", ".cc",
                 ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm", ".swift", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
                 ".dart", ".json", ".html", ".htm", ".properties", ".yml", ".yaml", ".toml", ".py", ".rs", ".go")
_WORD = re.compile(r"[\w$]+")
_WORD_BYTES = re.compile(rb"[A-Za-z0-9_$]+")
_CHUNK = 1 << 20
_MAX_DEPTH = 64
_MAX_RAW = 64 << 20                     # a larger file than this that can't be read as text stops the check

# Annotations that don't make a function something a framework or generated code calls by name.
_PLAIN_ANNOTATIONS = {
    "Throws", "JvmStatic", "JvmOverloads", "Suppress", "SuppressLint", "SuppressWarnings", "Deprecated",
    "RequiresApi", "TargetApi", "RequiresPermission", "WorkerThread", "MainThread", "UiThread", "AnyThread",
    "BinderThread", "VisibleForTesting", "CheckResult", "Synchronized", "Composable", "ReadOnlyComposable",
    "NonNull", "Nullable", "NotNull", "OptIn", "SafeVarargs", "ChecksSdkIntAtLeast", "IntRange", "Size",
}
_KT_ENTRY = re.compile(r"\b(?:override|operator|external|expect|actual|abstract)\b")
_JAVA_ENTRY = re.compile(r"\b(?:native|abstract)\b")
# Called by the runtime or by language conventions, not by name in the source.
_RUNTIME_NAMES = {"main", "writeObject", "readObject", "readObjectNoData", "writeReplace", "readResolve", "finalize",
                  "toString", "equals", "hashCode", "values", "valueOf", "invoke", "get", "set", "getValue",
                  "setValue", "provideDelegate", "compareTo", "iterator", "next", "hasNext", "contains"}

_KT_FUN = re.compile(r"(?<![\w$])fun\s+(?:<[^<>{}]{0,200}>\s*)?(?:[\w.?<>, ]{1,200}\.)?([A-Za-z_]\w*)\s*\(")
_KT_BODY = re.compile(r"[ \t\n]*(?::[^{=\n]{0,300})?[ \t\n]*([{=])")
# Brackets, line breaks, and the next `fun`: a body never runs into the next function, which also keeps a file
# of unclosed `fun f() = (` linear.
_EXPR_TOKENS = re.compile(r"[(){}\[\]\n]|(?<![\w$])fun(?![\w$])")
_BLANK_RUN = re.compile(r"[ \t\n]*")
_CONTINUES_AFTER = ("=", "(", "[", ",", ".", "+", "-", "*", "/", "%", "?:", "&&", "||", "->", ":", "?", "!")
_CONTINUES_BEFORE = (".", "?.", "?:", "&&", "||", "+", "-", "*", "/", "%", ")", "]", "as ", "as?", "?", ":")


class _Span:
    __slots__ = ("start", "end", "name", "decl")

    def __init__(self, start: int, end: int, name: str, decl: str):
        self.start, self.end, self.name, self.decl = start, end, name, decl


class _Functions:
    """The functions declared in one Kotlin or Java file: their spans, `[start, end)` from the declaration to
    the end of the body (`fun f() = expr` included), and, for any offset, the functions around it."""

    def __init__(self, blank: str, path: str):
        spans = _kotlin_spans(blank) if path.endswith(".kt") else _java_spans(blank)
        spans.sort(key=lambda s: (s.start, -s.end))
        self.spans = spans
        self.starts = [s.start for s in spans]
        self.parent: List[int] = []
        stack: List[int] = []
        for i, s in enumerate(spans):
            while stack and spans[stack[-1]].end <= s.start:
                stack.pop()
            self.parent.append(stack[-1] if stack else -1)
            stack.append(i)

    def around(self, idx: int) -> Optional[List[_Span]]:
        """The functions around `idx`, innermost first; None past _MAX_DEPTH of them, which callers take as
        "can't tell" (crafted nesting would otherwise make every question a walk to the top)."""
        k = bisect.bisect_right(self.starts, idx) - 1
        out: List[_Span] = []
        steps = 0
        while k >= 0:
            steps += 1
            if steps > _MAX_DEPTH:
                return None
            span = self.spans[k]
            if idx < span.end:
                out.append(span)
            k = self.parent[k]
        return out


def _head(blank: str, at: int) -> str:
    head = blank[max(0, at - 400):at]
    cut = max(head.rfind(";"), head.rfind("}"), head.rfind("{"))
    return head[cut + 1:]


def _kotlin_spans(blank: str) -> List[_Span]:
    from masaudit.detectors.cross import _declaration
    out = []
    for m in _KT_FUN.finditer(blank):
        paren = m.end() - 1
        close = bracket_match(blank, paren, "(", ")")
        body = _KT_BODY.match(blank, close + 1) if close < len(blank) else None
        if not body:
            continue                                  # no body: abstract, or an interface's
        at = body.start(1)
        end = bracket_match(blank, at, "{", "}") + 1 if blank[at] == "{" else _expression_end(blank, at)
        decl = _declaration(_head(blank, m.start()) + blank[m.start():paren])
        out.append(_Span(m.start(), min(end, len(blank)), m.group(1), decl))
    return out


def _expression_end(blank: str, eq: int) -> int:
    """The end of `fun f() = expr`: the first line break outside brackets after which the expression doesn't
    go on (the line doesn't end with an operator, the next line doesn't start with one), the `}` that closes
    the block the function is in, or the next `fun` (a local function inside a lambda ends the body early:
    the span is then too short, which only ever keeps a finding open)."""
    depth = 0
    line_start = eq + 1
    seen = False
    skip_to = -1
    for t in _EXPR_TOKENS.finditer(blank, eq + 1):
        c, pos = t.group(), t.start()
        if c == "fun":
            return pos
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return pos
        elif depth == 0 and pos >= skip_to:
            line = blank[line_start:pos].strip()
            line_start = pos + 1
            if not line and not seen:
                continue                              # `=` with the expression on a later line
            if line:
                seen = True
                if line.endswith(_CONTINUES_AFTER):
                    continue
            nxt = _BLANK_RUN.match(blank, pos).end()
            if nxt < len(blank) and blank.startswith(_CONTINUES_BEFORE, nxt):
                skip_to = nxt
                line_start = nxt
                continue
            return pos
        elif c == "\n":
            line_start = pos + 1
    return len(blank)


def _java_spans(blank: str) -> List[_Span]:
    from masaudit.detectors.cross import _CALL_SITE, _JAVA_BODY, _declaration, _declares
    out = []
    for m in _CALL_SITE.finditer(blank):
        if m.start() and blank[m.start() - 1] == ".":
            continue
        paren = m.end() - 1
        if not _declares(blank, m.start(), paren):
            continue
        body = _JAVA_BODY.match(blank, paren)
        if not body:
            continue
        at = body.end() - 1 if blank[body.end() - 1] == "{" else blank.find("{", body.end())
        if at < 0 or ";" in blank[body.end():at]:
            continue
        decl = _declaration(_head(blank, m.start()) + blank[m.start():paren])
        out.append(_Span(m.start(), bracket_match(blank, at, "{", "}") + 1, m.group(1), decl))
    return out


def _judged(span: _Span, path: str, app_module: bool) -> bool:
    """Could nothing but this project's own source call the function, by its name?"""
    if span.name in _RUNTIME_NAMES or re.fullmatch(r"component\d+", span.name):
        return False
    decl = span.decl
    for a in re.findall(r"@([\w.]+)", decl):
        short = a.rsplit(".", 1)[-1]
        if short not in _PLAIN_ANNOTATIONS and not short.startswith("Experimental"):
            return False
    if path.endswith(".kt"):
        if _KT_ENTRY.search(decl):
            return False
        return app_module or bool(re.search(r"\b(?:private|internal)\b", decl))
    if _JAVA_ENTRY.search(decl):
        return False
    if re.search(r"\bprivate\b", decl):
        return True
    return app_module and bool(re.search(r"\bstatic\b", decl))


def lower(ctx, findings: list) -> None:
    """Give findings in a function nothing calls the scope "unused"."""
    candidates = [f for f in findings if f.scope == "main" and f.rule.kind != "hardening" and f.location.line > 0
                  and f.location.path.endswith((".kt", ".java"))]
    if not candidates:
        return
    from masaudit.detectors import android
    funcs: Dict[str, Optional[_Functions]] = {}

    def functions(path: str) -> Optional[_Functions]:
        if path not in funcs:
            blank = ctx.code(path, keep_strings=False)
            funcs[path] = _Functions(blank, path) if blank is not None else None
        return funcs[path]

    # id(finding) -> the judged functions around it: code inside a function nothing calls doesn't run, even in
    # an override of an object that function creates.
    owners: Dict[int, List[_Span]] = {}
    for f in candidates:
        fn = functions(f.location.path)
        if fn is None:
            continue
        blank = ctx.code(f.location.path, keep_strings=False) or ""
        idx = _line_offset(blank, f.location.line)
        if idx is None:
            continue
        app = android.in_app_module(ctx, f.location.path)
        judged = [s for s in fn.around(idx) or () if _judged(s, f.location.path, app)]
        if judged:
            owners[id(f)] = judged
    if not owners:
        return
    called = _called(ctx, {s.name for spans in owners.values() for s in spans}, functions)
    if called is None:
        return
    for f in candidates:
        if any(s.name not in called for s in owners.get(id(f), ())):
            f.scope = "unused"


def _line_offset(text: str, line: int) -> Optional[int]:
    """Offset of the first non-blank character on 1-based `line`."""
    from masaudit.textscan import text_memo
    starts = text_memo(text, ("line_starts",), lambda: [0] + [m.end() for m in re.finditer("\n", text)])
    if line > len(starts):
        return None
    i = starts[line - 1]
    while i < len(text) and text[i] in " \t":
        i += 1
    return i


def _called(ctx, names: Set[str], functions) -> Optional[Set[str]]:
    """The names in `names` that something calls, or None when the project couldn't be searched in full."""
    paths = [p for p in ctx.all_names(excluded=True) if p.endswith(_REF_SUFFIXES)]
    if not ctx.names_complete:
        return None
    scanned = set(ctx.project.files)
    called: Set[str] = set()
    pattern = r"(?<![\w$])(?:" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + r")(?![\w$])"
    # One regex of a few names finds the files that mention any; with many names, matching the alternation at
    # every position costs more than looking each word up.
    regex = re.compile(pattern) if len(names) <= 64 else None
    for path in paths:
        if called >= names:
            break
        if path in scanned:
            code = ctx.code(path)
        else:
            text = safety.read_text(ctx.root, path)
            if text is None:
                raw = _raw_mentions(ctx.root, path, names)
                if raw is None:
                    return None                       # can't be read and too big to search: can't tell
                called |= raw
                continue
            lang = lexer.LANG_BY_SUFFIX.get(os.path.splitext(path)[1])
            code = lexer.strip(text, lang, True) if lang else text
        if not code or (regex is not None and not regex.search(code)):
            continue
        own = path.endswith((".kt", ".java")) and path in scanned
        blank = ctx.code(path, keep_strings=False) if own else None
        fn = functions(path) if own else None
        for m in _WORD.finditer(code):
            name = m.group()
            if name not in names or name in called:
                continue
            if fn is None or blank is None or blank[m.start():m.end()] != name:
                called.add(name)                      # another language, or inside a string
            else:
                around = fn.around(m.start())
                if around is None or not any(s.name == name for s in around):
                    called.add(name)
    return called


def _raw_mentions(root: str, rel: str, names: Set[str]) -> Optional[Set[str]]:
    """The names a file too large (or not text) mentions, searched as bytes; None if it can't be read."""
    full = os.path.join(root, rel)
    if not safety.is_within(root, full) or safety._is_hard_link(full) or not os.path.isfile(full):
        return None
    try:
        if os.path.getsize(full) > _MAX_RAW:
            return None
        wanted = {n.encode() for n in names}
        found: Set[str] = set()
        tail = b""
        with open(full, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                data = tail + chunk
                found.update(w.decode() for w in _WORD_BYTES.findall(data) if w in wanted)
                tail = data[-256:]
        return found
    except OSError:
        return None

