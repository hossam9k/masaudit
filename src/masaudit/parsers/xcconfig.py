# SPDX-License-Identifier: Apache-2.0
"""Xcode build configuration files (`.xcconfig`).

    KEY = VALUE                       later assignments win
    KEY[sdk=iphoneos*] = VALUE        conditional: kept under its own key, "KEY[sdk=iphoneos*]"
    #include "Shared.xcconfig"        processed in place, relative to the including file
    #include? "Optional.xcconfig"    the same, but silent if missing
    // comment                        also ends a value: `URL = https://x` reads as `https:`

`$(VAR)` references are left as written: the scanner treats them as unknown, never as a value.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

from masaudit import safety

MAX_INCLUDES = 500                # files resolved per configuration, at most
MAX_LINES = 200_000               # settings and includes applied per configuration, at most
MAX_INCLUDE_DEPTH = 8

_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*((?:\[[^\]]*\]\s*)*)=(.*)$")
_INCLUDE = re.compile(r'^\s*#include(\?)?\s+"([^"]+)"')


@dataclass
class Setting:
    value: str
    path: str          # file that set it (repo-relative)
    line: int


@dataclass
class XCConfig:
    settings: List[Tuple[str, str, int]] = field(default_factory=list)   # (key, value, line) in order
    includes: List[Tuple[str, bool, int]] = field(default_factory=list)  # (path, optional, line)
    order: List[Tuple[str, object]] = field(default_factory=list)        # ("set", idx) | ("include", idx)


def parse(text: str) -> XCConfig:
    cfg = XCConfig()
    for lineno, raw in enumerate(safety.lines(text), start=1):
        m = _INCLUDE.match(raw)
        if m:
            cfg.includes.append((m.group(2), bool(m.group(1)), lineno))
            cfg.order.append(("include", len(cfg.includes) - 1))
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        m = _ASSIGN.match(line)
        if not m:
            continue
        key = m.group(1) + "".join(m.group(2).split())
        cfg.settings.append((key, m.group(3).strip(), lineno))
        cfg.order.append(("set", len(cfg.settings) - 1))
    return cfg


def resolve(root: str, rel: str,
            read: Optional[Callable[[str, str], Optional[str]]] = None,
            unknowns: Optional[List[str]] = None) -> Dict[str, Setting]:
    """Effective settings of an xcconfig and everything it includes (later wins)."""
    read = read or safety.read_text
    out: Dict[str, Setting] = {}
    state = _State(read, unknowns)
    _resolve_into(root, rel, state, out, frozenset(), 0)
    return out


class _State:
    """One resolve: each file's settings are worked out once and reused (a file included many times, at
    many levels, was re-read and re-resolved every time: exponential), and the total work is capped."""

    def __init__(self, read, unknowns: Optional[List[str]]):
        self.read = read
        self.unknowns = unknowns
        # rel -> (settings, height, files): resolved with no cycle or depth cut; `height` is how many include
        # levels sit below it and `files` every file it names, so a reuse is only taken where the same cuts
        # (none) would happen again.
        self.done: Dict[str, Tuple[Dict[str, Setting], int, FrozenSet[str]]] = {}
        self.budget = MAX_INCLUDES
        self.lines = MAX_LINES
        self.parsed: Dict[str, Optional[XCConfig]] = {}   # each file is read and parsed once per resolve

    def note(self, message: str) -> None:
        if self.unknowns is not None and message not in self.unknowns:
            self.unknowns.append(message)


def _resolve_into(root: str, rel: str, state: _State, out: Dict[str, Setting], stack: FrozenSet[str],
                  depth: int) -> Tuple[bool, bool, int, FrozenSet[str]]:
    """Apply `rel` and its includes to `out`. Returns (read ok, pure, height, files): pure when no cycle or
    depth cap cut the expansion; height and files describe the include tree below `rel`."""
    if depth > MAX_INCLUDE_DEPTH or rel in stack:
        state.note(f"xcconfig include chain too deep or circular at {rel}")
        return False, False, 0, frozenset((rel,))
    hit = state.done.get(rel)
    if hit is not None and depth + hit[1] <= MAX_INCLUDE_DEPTH and not (hit[2] & stack):
        out.update(hit[0])
        return True, True, hit[1], hit[2]
    if state.budget <= 0 or state.lines <= 0:
        state.note(f"xcconfig includes stop after {MAX_INCLUDES} files or {MAX_LINES:,} lines, at {rel}")
        return True, False, 0, frozenset((rel,))     # noted once here, not as an unreadable include
    state.budget -= 1
    if rel not in state.parsed:
        text = state.read(root, rel)
        state.parsed[rel] = parse(text) if text is not None else None
    cfg = state.parsed[rel]
    if cfg is None:
        return False, True, 0, frozenset((rel,))
    state.lines -= len(cfg.order)
    stack = stack | {rel}
    local: Dict[str, Setting] = {}
    pure, height, files = True, 0, {rel}
    for kind, idx in cfg.order:
        if kind == "set":
            key, value, line = cfg.settings[idx]       # type: ignore[index]
            local[key] = Setting(value=value, path=rel, line=line)
        else:
            inc, optional, line = cfg.includes[idx]    # type: ignore[index]
            target = include_path(rel, inc)
            if target is None:
                continue
            ok, inner_pure, inner_height, inner_files = _resolve_into(root, target, state, local, stack, depth + 1)
            pure = pure and inner_pure
            height = max(height, inner_height + 1)
            files |= inner_files
            if not ok and not optional:
                state.note(f"Couldn't read {inc}, included from {rel}:{line}")
    out.update(local)
    frozen = frozenset(files)
    if pure:
        state.done[rel] = (local, height, frozen)
    return True, pure, height, frozen


def include_path(from_rel: str, inc: str) -> Optional[str]:
    if inc.startswith("/") or "$(" in inc or "${" in inc:
        return None
    path = posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), inc))
    if path.startswith("../") or path == "..":
        return None
    return path


def is_unresolved(value: str) -> bool:
    return "$(" in value or "${" in value


def is_yes(value: object) -> bool:
    return isinstance(value, str) and value.strip().strip('"').upper() in ("YES", "TRUE", "1")


def is_no(value: object) -> bool:
    return isinstance(value, str) and value.strip().strip('"').upper() in ("NO", "FALSE", "0")


def _strip_comment(line: str) -> str:
    """Drop a `//` comment. Xcode does this even inside a value (the book's §15.8 trap)."""
    idx = line.find("//")
    return line if idx == -1 else line[:idx]
