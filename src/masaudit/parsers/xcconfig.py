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
from typing import Callable, Dict, List, Optional, Tuple

from masaudit import safety

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
    _resolve_into(root, rel, read, out, set(), 0, unknowns)
    return out


def _resolve_into(root: str, rel: str, read, out: Dict[str, Setting], stack: set, depth: int,
                  unknowns: Optional[List[str]]) -> bool:
    if depth > MAX_INCLUDE_DEPTH or rel in stack:
        if unknowns is not None:
            unknowns.append(f"xcconfig include chain too deep or circular at {rel}")
        return False
    text = read(root, rel)
    if text is None:
        return False
    cfg = parse(text)
    stack = stack | {rel}
    for kind, idx in cfg.order:
        if kind == "set":
            key, value, line = cfg.settings[idx]       # type: ignore[index]
            out[key] = Setting(value=value, path=rel, line=line)
        else:
            inc, optional, line = cfg.includes[idx]    # type: ignore[index]
            target = include_path(rel, inc)
            if target is None:
                continue
            ok = _resolve_into(root, target, read, out, stack, depth + 1, unknowns)
            if not ok and not optional and unknowns is not None:
                unknowns.append(f"Couldn't read {inc}, included from {rel}:{line}")
    return True


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
