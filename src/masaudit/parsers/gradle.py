# SPDX-License-Identifier: Apache-2.0
"""Just enough Gradle (Groovy and Kotlin DSL) and version-catalog parsing for masaudit.

We never evaluate a build script. We find named blocks by brace matching on code whose comments
and string contents are blanked (same length as the original, so offsets line up), and read
literal values. Anything that isn't a literal is reported as "unknown" by the caller.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple

# `release {`, `getByName("release") {`, `named("release") {`, `create("staging") {`
_HEADER = re.compile(
    r"(?<![\w.])(?P<fn>[A-Za-z_]\w*)\s*(?:\(\s*[\"'](?P<arg>[\w.-]+)[\"']\s*\))?\s*\{"
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


def child_blocks(code: str, blank: str, parent: Block, name: str) -> List[Block]:
    return [b for b in blocks(code, blank, parent.body_start, parent.body_end) if b.name == name]


def named_blocks(code: str, blank: str, name: str) -> List[Block]:
    return [b for b in blocks(code, blank) if b.name == name]


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
    end = len(code) if end is None else end
    for m in pattern.finditer(code, start, end):
        val = m.group("val")
        while val.endswith(")") and val.count("(") < val.count(")"):
            val = val[:-1]
        yield m.start(), val.rstrip(";").strip("\"'")


def inside(index: int, spans: List[Block]) -> bool:
    return any(b.body_start <= index < b.body_end for b in spans)


def int_literal(value: str) -> Optional[int]:
    v = value.strip().strip("\"'")
    return int(v) if v.isdigit() else None


# ---------------------------------------------------------------------------- version catalog

_TOML_SECTION = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
_TOML_KV = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*=\s*(?P<val>.+?)\s*$")


def toml_versions(text: str) -> Dict[str, Tuple[str, int]]:
    """[versions] entries of a Gradle version catalog: key -> (value, 1-based line)."""
    out: Dict[str, Tuple[str, int]] = {}
    section = ""
    for lineno, raw in enumerate(text.splitlines(), start=1):
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
    for lineno, raw in enumerate(text.splitlines(), start=1):
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
    for bt in named_blocks(code, blank, "buildTypes"):
        for b in direct_children(code, blank, bt):
            if b.name in ("all", "configureEach", "forEach", "each", "matching"):
                continue
            nested = direct_children(code, blank, b)
            debuggable: Optional[bool] = None
            for idx, val in find_settings(code, _DEBUGGABLE_SETTING, b.body_start, b.body_end):
                if not inside(idx, nested) and val in ("true", "false"):
                    debuggable = val == "true"
            init = None
            for m in _INIT_WITH.finditer(code, b.body_start, b.body_end):
                if not inside(m.start(), nested):
                    init = m.group("name")
            fallbacks: List[str] = []
            for m in _FALLBACKS.finditer(code, b.body_start, b.body_end):
                fallbacks += _QUOTED.findall(m.group(0))
            prev = out.get(b.name)
            if prev is not None:      # `debug {}` configured twice: merge what's explicit
                debuggable = debuggable if debuggable is not None else prev.debuggable
                init = init or prev.init_from
                fallbacks = prev.fallbacks + fallbacks
            out[b.name] = BuildType(b.name, b, debuggable, init, fallbacks)
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
    for lineno, raw in enumerate(text.splitlines(), start=1):
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
