# SPDX-License-Identifier: Apache-2.0
"""A small, indent-aware reader for the YAML that GitHub Actions workflows use. No PyYAML.

It understands block mappings and sequences (including sequences at the same indent as
their key), `- key: value` items, block scalars (`|`, `>`, with chomping and indent
indicators), single-line and multi-line flow collections (`[a, b]`, `{ a: b }`), quoted
strings, comments, and document markers. Anchors and tags are stripped; aliases stay
as plain text. It never raises: a line it can't place is skipped.

Every value carries the 1-based line it came from:
  * Scalar is a `str` with `.line` (for block scalars, `.line` is the key's line and
    `.line_map[i]` is the file line of content line `i`).
  * Map is a `dict` with `.line` and `.key_lines[key]`.
  * Seq is a `list` with `.line`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union


class Scalar(str):
    line: int = 0
    line_map: List[int]

    def __new__(cls, value: str, line: int = 0, line_map: Optional[List[int]] = None):
        obj = super().__new__(cls, value)
        obj.line = line
        obj.line_map = line_map if line_map is not None else [line] * (value.count("\n") + 1)
        return obj


class Map(dict):
    def __init__(self, line: int = 0):
        super().__init__()
        self.line = line
        self.key_lines: Dict[str, int] = {}


class Seq(list):
    def __init__(self, line: int = 0):
        super().__init__()
        self.line = line


Node = Union[Scalar, Map, Seq]


# ---------------------------------------------------------------------------- lexing helpers


def _strip_comment(s: str) -> str:
    """Remove a trailing `# comment` that is outside quotes."""
    quote = ""
    for i, ch in enumerate(s):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"') and (i == 0 or s[i - 1] in " \t:[{,-"):
            quote = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _split_key(content: str) -> Optional[Tuple[str, str]]:
    """Split `key: rest` (key may be quoted). None if the line isn't a mapping entry."""
    if not content or content[0] in "[{|>":
        return None
    if content[0] in ("'", '"'):
        q = content[0]
        end = content.find(q, 1)
        while end != -1 and q == "'" and end + 1 < len(content) and content[end + 1] == "'":
            end = content.find(q, end + 2)
        if end == -1:
            return None
        after = content[end + 1:]
        if after.startswith(":") and (len(after) == 1 or after[1] in " \t"):
            return _unquote(content[: end + 1]), after[1:].strip()
        return None
    for m in re.finditer(r":(?=\s|$)", content):
        key = content[: m.start()].strip()
        if key and not key.startswith(("- ", "#")):
            return key, content[m.end():].strip()
        return None
    return None


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        inner = s[1:-1]
        return re.sub(r'\\(["\\/nt])', lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), inner)
    if len(s) >= 2 and s[0] == s[-1] == "'":
        return s[1:-1].replace("''", "'")
    return s


def _strip_props(s: str) -> str:
    """Drop leading anchors (&a) and tags (!t) from a value."""
    while True:
        m = re.match(r"^(?:&[^\s]+|![^\s]*)(?:\s+|$)", s)
        if not m:
            return s
        s = s[m.end():]


# ---------------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, text: str):
        self.raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.i = 0

    # A "significant" line: not blank, not a comment, not a document marker.
    def _peek(self) -> Optional[Tuple[int, int, str]]:
        while self.i < len(self.raw):
            line = self.raw[self.i]
            body = _strip_comment(line.replace("\t", "  "))
            stripped = body.strip()
            if not stripped or stripped in ("---", "...") or stripped.startswith("%"):
                self.i += 1
                continue
            if stripped.startswith("--- "):
                self.raw[self.i] = stripped[4:]
                continue
            indent = len(body) - len(body.lstrip(" "))
            return self.i, indent, stripped
        return None

    def parse(self) -> Optional[Node]:
        peek = self._peek()
        if peek is None:
            return None
        return self._node(peek[1])

    def _node(self, indent: int) -> Optional[Node]:
        peek = self._peek()
        if peek is None or peek[1] < indent:
            return None
        _, ind, content = peek
        if content == "-" or content.startswith("- "):
            return self._seq(ind)
        if _split_key(content) is None:
            # A bare scalar (or a flow collection) on its own line.
            self.i += 1
            return self._value(content, peek[0] + 1, ind - 1)
        return self._map(ind)

    def _map(self, ind: int, first: Optional[Tuple[str, str, int]] = None) -> Map:
        m = Map(line=(first[2] if first else (self._peek() or (0, 0, ""))[0] + 1))
        if first:
            key, rest, lineno = first
            m.key_lines[key] = lineno
            m[key] = self._value(rest, lineno, ind)
        while True:
            peek = self._peek()
            if peek is None:
                break
            idx, cur, content = peek
            if cur < ind:
                break
            if cur > ind:
                self.i += 1          # stray deeper line (e.g. a plain-scalar continuation)
                continue
            if content == "-" or content.startswith("- "):
                break                # a sequence at this indent belongs to the parent
            kv = _split_key(content)
            self.i += 1
            if kv is None:
                continue
            key, rest = kv
            m.key_lines[key] = idx + 1
            m[key] = self._value(rest, idx + 1, ind)
        return m

    def _seq(self, ind: int) -> Seq:
        s = Seq(line=(self._peek() or (0, 0, ""))[0] + 1)
        while True:
            peek = self._peek()
            if peek is None:
                break
            idx, cur, content = peek
            if cur != ind or not (content == "-" or content.startswith("- ")):
                if cur > ind:
                    self.i += 1
                    continue
                break
            self.i += 1
            rest = content[1:].lstrip(" ")
            item_indent = ind + (len(content) - len(rest))
            rest = _strip_props(rest)
            if not rest:
                item = self._node(ind + 1)
                s.append(item if item is not None else Scalar("", idx + 1))
                continue
            kv = _split_key(rest) if rest[0] not in "[{" else None
            if kv is not None:
                s.append(self._map(item_indent, first=(kv[0], kv[1], idx + 1)))
            else:
                s.append(self._value(rest, idx + 1, ind))
        return s

    def _value(self, rest: str, lineno: int, parent_indent: int) -> Node:
        rest = _strip_props(rest.strip())
        if rest.startswith(("|", ">")) and re.match(r"^[|>][0-9+\-]*$", rest):
            return self._block_scalar(rest, lineno, parent_indent)
        if not rest:
            peek = self._peek()
            if peek is not None:
                _, cur, content = peek
                if cur > parent_indent:
                    node = self._node(cur)
                    return node if node is not None else Scalar("", lineno)
                if cur == parent_indent and (content == "-" or content.startswith("- ")):
                    return self._seq(cur)
            return Scalar("", lineno)
        if rest[0] in "[{":
            text = rest
            while _depth(text) > 0 and self.i < len(self.raw):
                text += " " + _strip_comment(self.raw[self.i]).strip()
                self.i += 1
            node, _ = _flow(text, 0, lineno)
            return node
        if rest.startswith("*"):
            return Scalar(rest, lineno)
        return Scalar(_unquote(rest), lineno)

    def _block_scalar(self, header: str, lineno: int, parent_indent: int) -> Scalar:
        explicit = re.search(r"[1-9]", header)
        lines: List[str] = []
        line_map: List[int] = []
        block_indent = parent_indent + int(explicit.group(0)) if explicit else None
        while self.i < len(self.raw):
            line = self.raw[self.i].replace("\t", "  ")
            if not line.strip():
                lines.append("")
                line_map.append(self.i + 1)
                self.i += 1
                continue
            cur = len(line) - len(line.lstrip(" "))
            if block_indent is None:
                if cur <= parent_indent:
                    break
                block_indent = cur
            if cur < block_indent:
                break
            lines.append(line[block_indent:])
            line_map.append(self.i + 1)
            self.i += 1
        while lines and not lines[-1]:
            lines.pop()
            line_map.pop()
        # Folded (`>`) scalars keep their line breaks here so line numbers stay exact.
        text = "\n".join(lines)
        if not line_map:
            line_map = [lineno]
        return Scalar(text, lineno, line_map)


def _depth(text: str) -> int:
    depth, quote = 0, ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


def _flow(text: str, i: int, lineno: int) -> Tuple[Node, int]:
    """Parse a flow collection or scalar starting at text[i]. Returns (node, next index)."""
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    if i < n and text[i] in "[{":
        is_map = text[i] == "{"
        node: Union[Map, Seq] = Map(lineno) if is_map else Seq(lineno)
        closer = "}" if is_map else "]"
        i += 1
        while i < n:
            while i < n and text[i] in " \t,":
                i += 1
            if i >= n or text[i] == closer:
                return node, i + 1
            if is_map:
                key_node, i = _flow_scalar(text, i, lineno, stop=":,}")
                value: Node = Scalar("", lineno)
                if i < n and text[i] == ":":
                    value, i = _flow(text, i + 1, lineno)
                node[str(key_node)] = value          # type: ignore[index]
                node.key_lines[str(key_node)] = lineno  # type: ignore[union-attr]
            else:
                item, i = _flow(text, i, lineno)
                node.append(item)                    # type: ignore[union-attr]
        return node, i
    return _flow_scalar(text, i, lineno, stop=",]}")


def _flow_scalar(text: str, i: int, lineno: int, stop: str) -> Tuple[Scalar, int]:
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    if i < n and text[i] in ("'", '"'):
        q = text[i]
        j = i + 1
        while j < n:
            if text[j] == "\\" and q == '"':
                j += 2
                continue
            if text[j] == q:
                if q == "'" and j + 1 < n and text[j + 1] == "'":
                    j += 2
                    continue
                break
            j += 1
        return Scalar(_unquote(text[i: j + 1]), lineno), j + 1
    j = i
    while j < n and text[j] not in stop:
        if text[j] == ":" and ":" in stop and (j + 1 >= n or text[j + 1] not in " \t"):
            j += 1                                   # a colon inside a plain value (e.g. a URL)
            continue
        j += 1
    return Scalar(text[i:j].strip(), lineno), j


def load(text: str) -> Optional[Node]:
    """Parse YAML text. Returns None for an empty document. Never raises."""
    try:
        return _Parser(text).parse()
    except (RecursionError, IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------- workflow model


@dataclass
class Step:
    line: int
    uses: Optional[Scalar] = None
    with_: Map = field(default_factory=Map)
    run: Optional[Scalar] = None
    env: Map = field(default_factory=Map)
    name: str = ""


@dataclass
class Job:
    id: str
    line: int
    permissions: Optional[Node] = None
    uses: Optional[Scalar] = None        # reusable workflow call
    steps: List[Step] = field(default_factory=list)


@dataclass
class Workflow:
    doc: Map
    triggers: Dict[str, int]             # trigger name -> line
    permissions: Optional[Node]          # None when the key is absent
    permissions_line: int
    jobs: List[Job]
    jobs_line: int


def _get(m: Map, *names: str) -> Tuple[Optional[Node], int]:
    for name in names:
        if name in m:
            return m[name], m.key_lines.get(name, m.line)
    return None, 0


def parse_workflow(text: str) -> Optional[Workflow]:
    doc = load(text)
    if not isinstance(doc, Map):
        return None
    on, on_line = _get(doc, "on", "true", "True")
    triggers: Dict[str, int] = {}
    if isinstance(on, Scalar) and on:
        triggers[str(on)] = on.line or on_line
    elif isinstance(on, Seq):
        for item in on:
            if isinstance(item, Scalar):
                triggers[str(item)] = item.line or on_line
    elif isinstance(on, Map):
        for key in on:
            triggers[key] = on.key_lines.get(key, on_line)
    perms, perms_line = _get(doc, "permissions")
    jobs_node, jobs_line = _get(doc, "jobs")
    jobs: List[Job] = []
    if isinstance(jobs_node, Map):
        for job_id, body in jobs_node.items():
            job = Job(id=job_id, line=jobs_node.key_lines.get(job_id, 0))
            if isinstance(body, Map):
                job.permissions = body.get("permissions") if "permissions" in body else None
                uses = body.get("uses")
                job.uses = uses if isinstance(uses, Scalar) and uses else None
                steps = body.get("steps")
                if isinstance(steps, Seq):
                    for raw in steps:
                        if isinstance(raw, Map):
                            job.steps.append(_step(raw))
            jobs.append(job)
    return Workflow(doc=doc, triggers=triggers, permissions=perms, permissions_line=perms_line,
                    jobs=jobs, jobs_line=jobs_line)


def _step(raw: Map) -> Step:
    step = Step(line=raw.line)
    uses = raw.get("uses")
    if isinstance(uses, Scalar) and uses:
        step.uses = uses
    run = raw.get("run")
    if isinstance(run, Scalar):
        step.run = run
    w = raw.get("with")
    if isinstance(w, Map):
        step.with_ = w
    env = raw.get("env")
    if isinstance(env, Map):
        step.env = env
    name = raw.get("name")
    step.name = str(name) if isinstance(name, Scalar) else ""
    return step
