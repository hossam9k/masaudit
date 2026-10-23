# SPDX-License-Identifier: Apache-2.0
"""Just enough Gradle (Groovy and Kotlin DSL) and version-catalog parsing for masaudit.

We never evaluate a build script. We find named blocks by brace matching on code whose comments
and string contents are blanked (same length as the original, so offsets line up), and read
literal values. Anything that isn't a literal is reported as "unknown" by the caller.
"""

from __future__ import annotations

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
        out.append(Block(name, m.start(), brace + 1, match_brace(blank, brace)))
    return out


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
        yield m.start(), val.strip("\"'")


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
