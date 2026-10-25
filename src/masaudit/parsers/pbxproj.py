# SPDX-License-Identifier: Apache-2.0
"""Xcode `project.pbxproj` files: old-style ASCII property lists.

Grammar (what Xcode writes, plus what people hand-edit):
    value   := dict | array | string | <hex data>
    dict    := "{" (string "=" value ";")* "}"
    array   := "(" (value ("," value)* ","?)? ")"
    string  := "quoted with \\ escapes" | unquoted [A-Za-z0-9_$+/:.\\-@~*?!<>]+
Comments (`/* ... */` and `// ...`) are skipped. Dicts come back as `PDict`, a dict that also
records the line of each key, so findings can point at the exact build setting.

The helpers at the bottom list native targets, their build configurations (Debug, Release,
...), and each configuration's buildSettings and base `.xcconfig`.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MAX_DEPTH = 64


class PDict(dict):
    """A dict that remembers the 1-based line of each key."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: Dict[str, int] = {}


class ParseError(ValueError):
    pass


_UNQUOTED = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$+/:.-@~*?!<>")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
            '"': '"', "\\": "\\", "'": "'"}


class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.line = 1

    # -- low level
    def _advance(self, k: int = 1) -> None:
        end = min(self.i + k, self.n)
        self.line += self.s.count("\n", self.i, end)
        self.i = end

    def _skip(self) -> None:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t\r\n":
                self._advance()
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                if end == -1:
                    raise ParseError(f"unterminated comment at line {self.line}")
                self._advance(end + 2 - self.i)
            elif s.startswith("//", self.i):
                end = s.find("\n", self.i)
                self._advance((n if end == -1 else end) - self.i)
            else:
                break

    def _peek(self) -> str:
        self._skip()
        return self.s[self.i] if self.i < self.n else ""

    def _expect(self, ch: str) -> None:
        if self._peek() != ch:
            raise ParseError(f"expected '{ch}' at line {self.line}")
        self._advance()

    # -- grammar
    def value(self, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        c = self._peek()
        if c == "{":
            return self._dict(depth)
        if c == "(":
            return self._array(depth)
        if c == "<":
            return self._data()
        if c == '"' or c == "'":
            return self._quoted(c)
        if c and c in _UNQUOTED:
            return self._unquoted()
        raise ParseError(f"unexpected {c!r} at line {self.line}")

    def _dict(self, depth: int) -> PDict:
        self._expect("{")
        out = PDict()
        while True:
            c = self._peek()
            if c == "}":
                self._advance()
                return out
            if not c:
                raise ParseError("unterminated dictionary")
            key_line = self.line
            key = self.value(depth + 1)
            if not isinstance(key, str):
                raise ParseError(f"dictionary key must be a string at line {key_line}")
            self._expect("=")
            out[key] = self.value(depth + 1)
            out.lines[key] = key_line
            self._expect(";")

    def _array(self, depth: int) -> List[Any]:
        self._expect("(")
        out: List[Any] = []
        while True:
            c = self._peek()
            if c == ")":
                self._advance()
                return out
            if not c:
                raise ParseError("unterminated array")
            out.append(self.value(depth + 1))
            c = self._peek()
            if c == ",":
                self._advance()
            elif c != ")":
                raise ParseError(f"expected ',' or ')' at line {self.line}")

    def _data(self) -> bytes:
        end = self.s.find(">", self.i)
        if end == -1:
            raise ParseError("unterminated data")
        raw = "".join(self.s[self.i + 1:end].split())
        self._advance(end + 1 - self.i)
        try:
            return bytes.fromhex(raw)
        except ValueError:
            # `<group>` style tokens appear unquoted in some hand-written files; keep as text.
            return raw.encode("ascii", "replace")

    def _quoted(self, q: str) -> str:
        self._advance()  # opening quote
        s, n = self.s, self.n
        out: List[str] = []
        while self.i < n:
            c = s[self.i]
            if c == q:
                self._advance()
                return "".join(out)
            if c == "\\" and self.i + 1 < n:
                e = s[self.i + 1]
                if e in ("U", "u") and self.i + 6 <= n:
                    try:
                        out.append(chr(int(s[self.i + 2:self.i + 6], 16)))
                        self._advance(6)
                        continue
                    except ValueError:
                        pass
                out.append(_ESCAPES.get(e, e))
                self._advance(2)
                continue
            out.append(c)
            self._advance()
        raise ParseError("unterminated string")

    def _unquoted(self) -> str:
        start = self.i
        s, n = self.s, self.n
        while self.i < n and s[self.i] in _UNQUOTED:
            if s.startswith("//", self.i) or s.startswith("/*", self.i):
                break
            self.i += 1
        return s[start:self.i]


def loads(text: str) -> Any:
    """Parse old-style plist text. Raises ParseError on malformed input."""
    if text.startswith("﻿"):
        text = text[1:]
    p = _Parser(text)
    # Xcode writes a `// !$*UTF8*$!` header; _skip treats it as a comment.
    value = p.value()
    if p._peek():
        raise ParseError(f"trailing content at line {p.line}")
    return value


def parse(text: Optional[str]) -> Optional[PDict]:
    """Parse a project.pbxproj. None if it isn't a valid project file."""
    if not text:
        return None
    try:
        value = loads(text)
    except (ParseError, RecursionError):
        return None
    if not isinstance(value, PDict) or not isinstance(value.get("objects"), dict):
        return None
    return value


# ---------------------------------------------------------------------------- project model


@dataclass
class BuildConfig:
    id: str
    name: str                              # "Debug", "Release", ...
    settings: Dict[str, Any]               # buildSettings
    lines: Dict[str, int]                  # setting -> line in the pbxproj
    line: int                              # line of the configuration object
    base_xcconfig: Optional[str] = None    # repo-relative path, best effort


@dataclass
class Target:
    id: str
    name: str
    product_type: str                      # e.g. com.apple.product-type.application
    configs: Dict[str, BuildConfig]
    line: int
    build_phases: List[str] = field(default_factory=list)
    synchronized_groups: List[str] = field(default_factory=list)   # repo-relative folders

    @property
    def is_app(self) -> bool:
        return self.product_type == "com.apple.product-type.application"

    @property
    def is_test(self) -> bool:
        return "test" in self.product_type

    @property
    def is_extension(self) -> bool:
        return "extension" in self.product_type


class Project:
    """A parsed project.pbxproj plus its location, so paths resolve repo-relative."""

    def __init__(self, data: PDict, pbxproj_path: str):
        self.data = data
        self.path = pbxproj_path                                   # .../App.xcodeproj/project.pbxproj
        xcodeproj = posixpath.dirname(pbxproj_path)
        self.source_root = posixpath.dirname(xcodeproj)             # SRCROOT, repo-relative ("" = root)
        self.objects: Dict[str, Any] = data.get("objects", {})
        self._parents: Optional[Dict[str, str]] = None

    def obj(self, oid: Any) -> Dict[str, Any]:
        o = self.objects.get(oid) if isinstance(oid, str) else None
        return o if isinstance(o, dict) else {}

    def objects_of(self, isa: str) -> List[tuple]:
        return [(k, v) for k, v in self.objects.items() if isinstance(v, dict) and v.get("isa") == isa]

    def line_of_object(self, oid: str) -> int:
        lines = getattr(self.objects, "lines", {})
        return lines.get(oid, 0)

    # -- paths
    def _parent_map(self) -> Dict[str, str]:
        if self._parents is None:
            parents: Dict[str, str] = {}
            for oid, o in self.objects.items():
                if isinstance(o, dict):
                    for child in o.get("children", []) or []:
                        if isinstance(child, str):
                            parents.setdefault(child, oid)
            self._parents = parents
        return self._parents

    def file_path(self, oid: str) -> Optional[str]:
        """Repo-relative path of a file reference or group, or None if it can't be resolved."""
        parts: List[str] = []
        cur: Optional[str] = oid
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            o = self.obj(cur)
            if not o:
                return None
            tree = o.get("sourceTree", "<group>")
            p = o.get("path")
            if isinstance(p, str) and p:
                parts.append(p)
            if tree == "SOURCE_ROOT":
                break
            if tree != "<group>":
                return None            # SDKROOT, BUILT_PRODUCTS_DIR, <absolute>: outside the repo
            cur = self._parent_map().get(cur)
        rel = posixpath.join(*reversed(parts)) if parts else ""
        return _join(self.source_root, rel)

    def settings_path(self, value: str) -> Optional[str]:
        """Resolve a path-valued build setting such as INFOPLIST_FILE, repo-relative."""
        v = value.strip().strip('"')
        for prefix in ("$(SRCROOT)/", "${SRCROOT}/", "$(PROJECT_DIR)/", "${PROJECT_DIR}/",
                       "$(SOURCE_ROOT)/", "${SOURCE_ROOT}/"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        if "$(" in v or "${" in v or v.startswith("/"):
            return None
        return _join(self.source_root, v)

    # -- configurations and targets
    def _configs(self, list_id: Any) -> Dict[str, BuildConfig]:
        out: Dict[str, BuildConfig] = {}
        for cid in self.obj(list_id).get("buildConfigurations", []) or []:
            c = self.obj(cid)
            if c.get("isa") != "XCBuildConfiguration":
                continue
            settings = c.get("buildSettings")
            settings = settings if isinstance(settings, dict) else PDict()
            base = None
            ref = c.get("baseConfigurationReference")
            if isinstance(ref, str):
                base = self.file_path(ref)
            anchor = c.get("baseConfigurationReferenceAnchor")
            relp = c.get("baseConfigurationReferenceRelativePath")
            if base is None and isinstance(anchor, str) and isinstance(relp, str):
                folder = self.file_path(anchor)
                base = _join(folder, relp) if folder is not None else None
            name = str(c.get("name", ""))
            out[name] = BuildConfig(
                id=cid, name=name, settings=settings,
                lines=getattr(settings, "lines", {}), line=self.line_of_object(cid),
                base_xcconfig=base,
            )
        return out

    def project_configs(self) -> Dict[str, BuildConfig]:
        for _oid, o in self.objects_of("PBXProject"):
            return self._configs(o.get("buildConfigurationList"))
        return {}

    def targets(self) -> List[Target]:
        out: List[Target] = []
        for oid, o in self.objects_of("PBXNativeTarget"):
            groups = []
            for gid in o.get("fileSystemSynchronizedGroups", []) or []:
                p = self.file_path(gid)
                if p is not None:
                    groups.append(p)
            out.append(Target(
                id=oid, name=str(o.get("name", "")),
                product_type=str(o.get("productType", "")).strip('"'),
                configs=self._configs(o.get("buildConfigurationList")),
                line=self.line_of_object(oid),
                build_phases=[b for b in o.get("buildPhases", []) or [] if isinstance(b, str)],
                synchronized_groups=groups,
            ))
        return out

    def phase_files(self, target: Target, isa: str) -> List[str]:
        """File-reference ids in the target's build phases of type `isa` (e.g. PBXResourcesBuildPhase)."""
        refs: List[str] = []
        for pid in target.build_phases:
            phase = self.obj(pid)
            if phase.get("isa") != isa:
                continue
            for bid in phase.get("files", []) or []:
                ref = self.obj(bid).get("fileRef")
                if isinstance(ref, str):
                    refs.append(ref)
        return refs

    def file_name(self, oid: str) -> str:
        o = self.obj(oid)
        name = o.get("name") or o.get("path") or ""
        return posixpath.basename(str(name))


def is_debug_config(name: str) -> bool:
    """Configurations that never ship to users: Debug, Development, Test, UITests, Profile, ...

    Only a fallback: when a project has shared schemes, the Archive action's configuration
    decides what ships (see xcscheme.py)."""
    low = name.lower().strip()
    if low in ("dev", "development", "profile", "profiling", "local") or low.endswith((" dev", "-dev", "_dev")):
        return True
    # Whole words and CamelCase tokens, not substrings: "Contest", "Latest" and "MASTestApp" (a product
    # name with "Test" in the middle) ship; "Debug-Staging", "StagingDebug", "UITests", "Test-QA" don't.
    for word in _WORD_SPLIT.split(name):
        tokens = [t.lower() for t in _CAMEL_TOKEN.findall(word)]
        if not tokens:
            continue
        if any(t.startswith("debug") for t in tokens):
            return True
        if tokens[0] in _TEST_WORDS or tokens[-1] in _TEST_WORDS or word.lower() in _TEST_WORDS:
            return True
    return False


_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_TOKEN = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_TEST_WORDS = frozenset(("test", "tests", "testing", "uitest", "uitests", "unittest", "unittests"))


def _join(base: Optional[str], rel: str) -> Optional[str]:
    if base is None:
        return None
    path = posixpath.normpath(posixpath.join(base, rel)) if (base or rel) else ""
    if path == ".":
        return ""
    if path.startswith("../") or path == "..":
        return None            # outside the scan root
    return path
