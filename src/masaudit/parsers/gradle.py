# SPDX-License-Identifier: Apache-2.0
"""Just enough Gradle (Groovy and Kotlin DSL) and version-catalog parsing for masaudit.

We never evaluate a build script. We find named blocks by brace matching on code whose comments
and string contents are blanked (same length as the original, so offsets line up), and read
literal values. Anything that isn't a literal is reported as "unknown" by the caller.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from masaudit import safety

# `release {`, `getByName("release") {`, `named("release") {`, `create("staging") {`
_HEADER = re.compile(
    # The second \s* sits inside the optional group, so two \s* never split one run of spaces between them.
    r"(?<![\w.])(?P<fn>[A-Za-z_]\w*)\s*(?:\(\s*[\"'](?P<arg>[\w.-]+)[\"']\s*\)\s*)?\{"
)
_NAMED_FNS = {"getByName", "named", "create", "maybeCreate", "register"}


@dataclass
class Block:
    name: str        # "release", "buildTypes", ...
    start: int       # index of the block's name
    body_start: int  # index just after "{"
    body_end: int    # index of the matching "}"


def match_brace(code: str, open_index: int) -> int:
    """Index of the "}" matching the "{" at open_index, or len(code) if unbalanced.

    `code` must have string contents blanked, so braces inside strings don't count.
    """
    depth = 0
    for i in range(open_index, len(code)):
        c = code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code)


def blocks(code: str, blank: str, start: int = 0, end: Optional[int] = None) -> List[Block]:
    """Every `name {` / `fn("name") {` block whose header lies in [start, end).

    `code` keeps strings (to read names); `blank` is the same text with strings blanked.
    """
    end = len(code) if end is None else end
    out: List[Block] = []
    for m in _HEADER.finditer(code, start, end):
        brace = m.end() - 1
        if blank[brace] != "{":
            continue
        fn, arg = m.group("fn"), m.group("arg")
        name = arg if (arg and fn in _NAMED_FNS) else fn
        out.append(Block(name, m.start(), brace + 1, _brace_pairs(blank).get(brace, len(blank))))
    return out


@functools.lru_cache(maxsize=32)
def _brace_pairs(blank: str) -> Dict[int, int]:
    """Every "{" index -> its matching "}" (one pass; unmatched braces are left out)."""
    pairs: Dict[int, int] = {}
    stack: List[int] = []
    for i, c in enumerate(blank):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs[stack.pop()] = i
    return pairs


# A crafted script of thousands of nested (or unclosed) blocks made every helper below rescan the rest of
# the file for each block, cubic in its size. The blocks of a script are found once instead (_index) and
# the helpers read them from there. That is exact for a range that is a block's body: a header never
# contains a brace except its last character, so no header match crosses the `{` before a body or the `}`
# after it, and the headers matched inside a body are the whole script's headers that start there.


class _Index:
    """Every block of one script, in order, by name, and by the block whose body directly holds it."""

    def __init__(self, code: str, blank: str):
        self.blocks = blocks(code, blank)
        self.starts = [b.start for b in self.blocks]
        self.by_name: Dict[str, Tuple[List[int], List[Block]]] = {}
        self.children: Dict[Optional[int], List[Block]] = {}     # holder's start (None: top level) -> blocks
        open_blocks: List[Block] = []
        for b in self.blocks:
            starts, named = self.by_name.setdefault(b.name, ([], []))
            starts.append(b.start)
            named.append(b)
            # Bodies nest or are disjoint (they come from one brace pairing), and a header starts after
            # the previous header ends, so the innermost open block whose body holds b.start holds b.
            while open_blocks and open_blocks[-1].body_end <= b.start:
                open_blocks.pop()
            self.children.setdefault(open_blocks[-1].start if open_blocks else None, []).append(b)
            open_blocks.append(b)
        self.by_start = {b.start: b for b in self.blocks}

    def owns(self, parent: Block) -> bool:
        """`parent` is one of this script's blocks (so its range is a body)."""
        b = self.by_start.get(parent.start)
        return b is not None and b.body_start == parent.body_start and b.body_end == parent.body_end


@functools.lru_cache(maxsize=8)
def _index(code: str, blank: str) -> _Index:
    return _Index(code, blank)


def child_blocks(code: str, blank: str, parent: Block, name: str) -> List[Block]:
    index = _index(code, blank)
    if not index.owns(parent):
        return [b for b in blocks(code, blank, parent.body_start, parent.body_end) if b.name == name]
    starts, named = index.by_name.get(name, ([], []))
    return named[bisect.bisect_left(starts, parent.body_start):bisect.bisect_left(starts, parent.body_end)]


def named_blocks(code: str, blank: str, name: str) -> List[Block]:
    return list(_index(code, blank).by_name.get(name, ([], []))[1])


def blocks_named_within(code: str, blank: str, outer: str, name: str) -> List[Block]:
    """The distinct blocks of build_type_blocks(code, blank, name) with outer = "buildTypes", in the order
    each first appears there (by position: `outer` blocks nest or are disjoint and are taken in order)."""
    index = _index(code, blank)
    starts, named = index.by_name.get(name, ([], []))
    out: List[Block] = []
    reach = -1                                   # end of the last outermost `outer` body taken
    for o in named_blocks(code, blank, outer):
        if o.start < reach:
            continue                             # inside an earlier one: nothing new
        reach = o.body_end
        out.extend(named[bisect.bisect_left(starts, o.body_start):bisect.bisect_left(starts, o.body_end)])
    return out


def build_type_blocks(code: str, blank: str, build_type: str) -> List[Block]:
    """Blocks configuring one build type, e.g. `buildTypes { release { ... } }`."""
    out: List[Block] = []
    for bt in named_blocks(code, blank, "buildTypes"):
        out.extend(child_blocks(code, blank, bt, build_type))
    return out


def setting(key_alternation: str) -> "re.Pattern[str]":
    """Regex for `key = v`, `key v` and `key(v)` (Groovy and Kotlin DSL). Include `setKey` yourself."""
    return re.compile(
        r"(?<![\w.])(?:" + key_alternation + r")[ \t]*(?:=\s*|\(\s*|[ \t]+)(?P<val>[^\s,}]+)"
    )


def find_settings(code: str, pattern: "re.Pattern[str]", start: int = 0,
                  end: Optional[int] = None) -> Iterator[Tuple[int, str]]:
    first, lo, hi = settings_in(code, pattern, start, end)
    yield from first
    for idx, _end, val in settings_list(code, pattern)[lo:hi]:
        yield idx, val


def _setting_value(val: str) -> str:
    while val.endswith(")") and val.count("(") < val.count(")"):
        val = val[:-1]
    return val.rstrip(";").strip("\"'")


@functools.lru_cache(maxsize=32)
def settings_list(code: str, pattern: "re.Pattern[str]") -> List[Tuple[int, int, str]]:
    """(start, end, value) of every match of a setting() pattern in the whole script."""
    return [(m.start(), m.end(), _setting_value(m.group("val"))) for m in pattern.finditer(code)]


def settings_in(code: str, pattern: "re.Pattern[str]", start: int = 0,
                end: Optional[int] = None) -> Tuple[List[Tuple[int, str]], int, int]:
    """find_settings(code, pattern, start, end) as (first, lo, hi): the matches are `first`, then
    settings_list(code, pattern)[lo:hi], so a block's settings needn't be searched for again.

    In a block's body the matches are the script's matches that start there: a match never holds `}` or
    runs past it, and the lookbehind sees the `{` before the body either way. Only a match running into
    the body from before (a value can hold `{`) makes them differ; the body is then searched until a match
    is one of the script's, after which both searches go on from the same place."""
    end = len(code) if end is None else end
    found = settings_list(code, pattern)
    if start == 0 and end == len(code):
        return [], 0, len(found)
    if not (0 < start <= len(code) and code[start - 1] == "{" and (end == len(code) or code[end:end + 1] == "}")):
        return [(m.start(), _setting_value(m.group("val"))) for m in pattern.finditer(code, start, end)], 0, 0
    lo = bisect.bisect_left(found, (start, -1, ""))
    hi = bisect.bisect_left(found, (end, -1, ""))
    if lo == 0 or found[lo - 1][1] <= start:
        return [], lo, hi
    first: List[Tuple[int, str]] = []
    for m in pattern.finditer(code, start, end):
        j = bisect.bisect_left(found, (m.start(), -1, ""))
        if j < len(found) and found[j][0] == m.start() and found[j][1] == m.end():
            return first, j, hi
        first.append((m.start(), _setting_value(m.group("val"))))
    return first, 0, 0


def named_range(code: str, blank: str, name: str, parent: Block) -> Tuple[List[Block], int, int]:
    """child_blocks(code, blank, parent, name) as named_blocks(code, blank, name)[lo:hi] (with that list)."""
    starts, named = _index(code, blank).by_name.get(name, ([], []))
    if not _index(code, blank).owns(parent):
        raise ValueError("not a block of this script")
    return named, bisect.bisect_left(starts, parent.body_start), bisect.bisect_left(starts, parent.body_end)


def inside(index: int, spans: List[Block]) -> bool:
    return any(b.body_start <= index < b.body_end for b in spans)


def int_literal(value: str) -> Optional[int]:
    return safety.small_int(value.strip().strip("\"'"))


# ---------------------------------------------------------------------------- version catalog

_TOML_SECTION = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
_TOML_KV = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*(?P<val>.+?)\s*$")


def toml_versions(text: str) -> Dict[str, Tuple[str, int]]:
    """[versions] entries of a Gradle version catalog: key -> (value, 1-based line)."""
    out: Dict[str, Tuple[str, int]] = {}
    section = ""
    for lineno, raw in enumerate(safety.lines(text), start=1):
        line = _strip_toml_comment(raw)
        sm = _TOML_SECTION.match(line)
        if sm:
            section = sm.group("name").strip()
            continue
        if section != "versions":
            continue
        km = _TOML_KV.match(line)
        if km:
            out[km.group("key")] = (km.group("val").strip().strip("\"'"), lineno)
    return out


def toml_lines(text: str) -> Iterator[Tuple[int, str]]:
    """Non-comment content of each TOML line."""
    for lineno, raw in enumerate(safety.lines(text), start=1):
        yield lineno, _strip_toml_comment(raw)


def _strip_toml_comment(line: str) -> str:
    quote = ""
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = ""
        elif c in ("'", '"'):
            quote = c
        elif c == "#":
            return line[:i]
    return line


def catalog_key(expr: str) -> Optional[str]:
    """`libs.versions.android.targetSdk.get().toInt()` -> "android.targetSdk"."""
    m = re.match(r"libs\.versions\.([\w.]+?)(?:\.get\(\))?(?:\.toInt\(\)|\.toInteger\(\))?\s*$", expr.strip())
    return m.group(1) if m else None


def catalog_lookup(versions: Dict[str, Tuple[str, int]], accessor: str) -> Optional[Tuple[str, int]]:
    """Gradle maps `a-b`, `a_b` and `a.b` catalog keys to the accessor `a.b`."""
    want = accessor.lower()
    for key, val in versions.items():
        if re.sub(r"[-_]", ".", key).lower() == want:
            return val
    return None


# ---------------------------------------------------------------------------- variants and dependencies


def direct_children(code: str, blank: str, parent: Block) -> List[Block]:
    """Blocks directly inside `parent`, not nested deeper (`release { cmake { } }` gives only release)."""
    index = _index(code, blank)
    if index.owns(parent):
        # The blocks the loop below keeps (each not inside an earlier kept one) are those whose innermost
        # holder is `parent`.
        return list(index.children.get(parent.start, []))
    out: List[Block] = []
    for b in blocks(code, blank, parent.body_start, parent.body_end):
        if any(o.body_start <= b.start < o.body_end for o in out):
            continue
        out.append(b)
    return out


@dataclass
class BuildType:
    name: str
    block: Block
    debuggable: Optional[bool]      # an explicit isDebuggable / debuggable value, else None
    init_from: Optional[str]        # initWith(getByName("debug")) -> "debug"
    fallbacks: List[str]            # matchingFallbacks += "debug" -> ["debug"]


_INIT_WITH = re.compile(r"\binitWith\s*\(?\s*(?:buildTypes\s*(?:\.\s*getByName\s*\(|\.|\[)\s*|getByName\s*\(\s*)?"
                        r"[\"']?(?P<name>\w+)")
_FALLBACKS = re.compile(r"\bmatchingFallbacks\b[^\n]{0,200}")
_QUOTED = re.compile(r"[\"']([\w.-]+)[\"']")
_DEBUGGABLE_SETTING = setting(r"isDebuggable|debuggable|setDebuggable")


def build_types(code: str, blank: str) -> Dict[str, BuildType]:
    """Every build type declared in `buildTypes { }` blocks, with what decides whether it ships debuggable."""
    out: Dict[str, BuildType] = {}
    inits, init_starts = _matches(code, _INIT_WITH)
    found = settings_list(code, _DEBUGGABLE_SETTING)
    found_starts = _settings_starts(code, _DEBUGGABLE_SETTING)

    def explicit(i: int) -> bool:
        return found[i][2] in ("true", "false")

    for bt in named_blocks(code, blank, "buildTypes"):
        for b in direct_children(code, blank, bt):
            if b.name in ("all", "configureEach", "forEach", "each", "matching"):
                continue
            nested = direct_children(code, blank, b)
            # The last setting (and initWith) in b's body outside its nested blocks, found from the end.
            first, lo, hi = settings_in(code, _DEBUGGABLE_SETTING, b.body_start, b.body_end)
            hit = _last_outside(found_starts, lo, hi, nested, explicit)
            val = found[hit][2] if hit is not None else next(
                (v for idx, v in reversed(first) if not inside(idx, nested) and v in ("true", "false")), None)
            debuggable: Optional[bool] = None if val is None else val == "true"
            # initWith matches hold no brace, so those in a body are the script's matches that start there.
            lo, hi = bisect.bisect_left(init_starts, b.body_start), bisect.bisect_left(init_starts, b.body_end)
            hit = _last_outside(init_starts, lo, hi, nested, lambda i: True)
            init = inits[hit].group("name") if hit is not None else None
            fallbacks: List[str] = []
            for m in _matches_in(code, _FALLBACKS, b.body_start, b.body_end):
                fallbacks += _QUOTED.findall(m.group(0))
            prev = out.get(b.name)
            if prev is not None:      # `debug {}` configured twice: merge what's explicit
                debuggable = debuggable if debuggable is not None else prev.debuggable
                init = init or prev.init_from
                prev.fallbacks.extend(fallbacks)      # (prev is replaced: extending saves a copy per repeat)
                fallbacks = prev.fallbacks
            out[b.name] = BuildType(b.name, b, debuggable, init, fallbacks)
    return out


@functools.lru_cache(maxsize=32)
def _matches(code: str, rx: "re.Pattern[str]") -> Tuple[List["re.Match[str]"], List[int]]:
    """Every match of rx in the whole script, and their start offsets."""
    found = list(rx.finditer(code))
    return found, [m.start() for m in found]


@functools.lru_cache(maxsize=32)
def _settings_starts(code: str, pattern: "re.Pattern[str]") -> List[int]:
    return [s[0] for s in settings_list(code, pattern)]


def _last_outside(starts: List[int], lo: int, hi: int, nested: List[Block], ok: Callable[[int], bool]) -> Optional[int]:
    """The last index i in [lo, hi) with ok(i) whose offset starts[i] isn't in a body in `nested` (blocks
    side by side, in order), skipping each nested body in one step."""
    bodies = [n.body_start for n in nested]
    i = hi - 1
    while i >= lo:
        k = bisect.bisect_right(bodies, starts[i]) - 1
        if k >= 0 and starts[i] < nested[k].body_end:
            i = bisect.bisect_left(starts, nested[k].body_start, lo, i) - 1    # before that body
            continue
        if ok(i):
            return i
        i -= 1
    return None


def _matches_in(code: str, rx: "re.Pattern[str]", start: int, end: int) -> List["re.Match[str]"]:
    """list(rx.finditer(code, start, end)) for a block body, from the script's matches: those that start
    in the body, except where a match runs into it from before (then the body is searched until a match
    agrees with the script's) or out of it at the end (that one is matched again, cut at the end). For a
    pattern without anchors or lookahead, whose matches are cut only by `end`."""
    if not (0 < start <= len(code) and code[start - 1] == "{" and (end == len(code) or code[end:end + 1] == "}")):
        return list(rx.finditer(code, start, end))
    found, starts = _matches(code, rx)
    lo, hi = bisect.bisect_left(starts, start), bisect.bisect_left(starts, end)
    out: List["re.Match[str]"] = []
    if lo > 0 and found[lo - 1].end() > start:
        for m in rx.finditer(code, start, end):
            j = bisect.bisect_left(starts, m.start())
            if j < len(found) and found[j].start() == m.start() and found[j].end() == m.end():
                lo = j
                break
            out.append(m)
        else:
            return out
    out.extend(found[lo:hi])
    if out and out[-1].end() > end:
        last = rx.match(code, out[-1].start(), end)
        if last is None:
            return list(rx.finditer(code, start, end))
        out[-1] = last
    return out


def product_flavors(code: str, blank: str) -> List[str]:
    out: List[str] = []
    for pf in named_blocks(code, blank, "productFlavors"):
        for b in direct_children(code, blank, pf):
            if b.name not in out and b.name not in ("all", "configureEach", "forEach", "each"):
                out.append(b.name)
    return out


@dataclass
class Dependency:
    config: str          # "implementation", "debugImplementation", "api", ...
    variant: str         # the config's variant prefix: "" for implementation/api, "debug", "internalDebug", ...
    index: int           # offset of the config name
    coords: List[str]    # "group:name" literals
    aliases: List[str]   # version-catalog accessors: libs.leakcanary.android -> "leakcanary.android"
    projects: List[str]  # project(":feature:x") -> ":feature:x"; projects.feature.x -> ":feature:x"


_DEP = re.compile(r"(?<![\w.$])(?P<config>[a-z]\w*?(?:Implementation|Api|CompileOnly|RuntimeOnly)|implementation|api"
                  r"|compileOnly|runtimeOnly)\b[ \t]*\(?[ \t]*(?P<rest>[^\n]{0,300})")
_COORD = re.compile(r"[\"']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+)(?::[^\"'\s]*)?[\"']")
_MAP_COORD = re.compile(r"group\s*[:=]\s*[\"']([\w.-]+)[\"']\s*,\s*name\s*[:=]\s*[\"']([\w.-]+)[\"']")
_ALIAS = re.compile(r"(?<![\w.])libs\.((?:\w+\.)*\w+)")
_PROJECT = re.compile(r"\bproject\s*\(\s*(?:path\s*[:=]\s*)?[\"']([^\"']+)[\"']")
_PROJECTS = re.compile(r"(?<![\w.])projects\.((?:\w+\.)*\w+)")
_SUFFIX = re.compile(r"(?:Implementation|Api|CompileOnly|RuntimeOnly)$")


def dependencies(code: str) -> List[Dependency]:
    """Dependency declarations in a build script (comments must be blanked; strings kept)."""
    out: List[Dependency] = []
    for m in _DEP.finditer(code):
        config, rest = m.group("config"), m.group("rest")
        variant = "" if config in ("implementation", "api", "compileOnly", "runtimeOnly") else _SUFFIX.sub("", config)
        coords = _COORD.findall(rest) + [f"{g}:{n}" for g, n in _MAP_COORD.findall(rest)]
        aliases = [a for a in _ALIAS.findall(rest) if not a.startswith(("versions.", "plugins.", "bundles."))]
        aliases = [re.sub(r"\.get$", "", a) for a in aliases]
        projects = _PROJECT.findall(rest) + [":" + p.replace(".", ":") for p in _PROJECTS.findall(rest)]
        if coords or aliases or projects:
            out.append(Dependency(config, variant, m.start(), coords, aliases, projects))
    return out


_TOML_INLINE_MODULE = re.compile(r"\bmodule\s*=\s*[\"']([\w.-]+:[\w.-]+)[\"']")
_TOML_INLINE_GROUP = re.compile(r"\bgroup\s*=\s*[\"']([\w.-]+)[\"']")
_TOML_INLINE_NAME = re.compile(r"\bname\s*=\s*[\"']([\w.-]+)[\"']")


def toml_libraries(text: str) -> Dict[str, Tuple[str, int]]:
    """[libraries] entries of a version catalog: alias -> ("group:name", 1-based line)."""
    out: Dict[str, Tuple[str, int]] = {}
    section = ""
    for lineno, raw in enumerate(safety.lines(text), start=1):
        line = _strip_toml_comment(raw)
        sm = _TOML_SECTION.match(line)
        if sm:
            section = sm.group("name").strip()
            continue
        if section != "libraries":
            continue
        km = _TOML_KV.match(line)
        if not km:
            continue
        val = km.group("val")
        coord = None
        mm = _TOML_INLINE_MODULE.search(val)
        if mm:
            coord = mm.group(1)
        else:
            g, n = _TOML_INLINE_GROUP.search(val), _TOML_INLINE_NAME.search(val)
            if g and n:
                coord = f"{g.group(1)}:{n.group(1)}"
            else:
                cm = re.match(r"\s*[\"']([\w.-]+:[\w.-]+)(?::[^\"']*)?[\"']", val)
                if cm:
                    coord = cm.group(1)
        if coord:
            out[km.group("key")] = (coord, lineno)
    return out


def alias_key(alias: str) -> str:
    """Gradle maps catalog keys `a-b`, `a_b` and `a.b` to the accessor `a.b`."""
    return re.sub(r"[-_]", ".", alias).lower()
