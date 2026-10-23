# SPDX-License-Identifier: Apache-2.0
"""Property lists (Info.plist, entitlements, privacy manifests), XML or binary.

Values come from the standard library's plistlib. For XML plists we also record the line of
every key, so a finding can point at `<key>NSAllowsArbitraryLoads</key>` instead of line 0.

Safety: an XML plist may carry Apple's standard DOCTYPE and nothing else. Any other DOCTYPE,
an internal DTD subset, or an `<!ENTITY>` declaration makes us refuse the file.
"""

from __future__ import annotations

import plistlib
import re
import xml.parsers.expat
from typing import Any, Dict, List, Optional, Tuple

from masaudit import safety

KeyPath = Tuple[Any, ...]          # e.g. ("NSAppTransportSecurity", "NSAllowsArbitraryLoads")

_DOCTYPE = re.compile(r"<!DOCTYPE\b[^>]*>", re.IGNORECASE)
# Apple's DTD (and the pre-2006 "Apple Computer" spelling). The system identifier is optional.
_APPLE_DOCTYPE = re.compile(
    r'^<!DOCTYPE\s+plist\s+PUBLIC\s+"-//Apple(?: Computer)?//DTD PLIST 1\.0//EN"'
    r'(?:\s+"https?://www\.apple\.com/DTDs/PropertyList-1\.0\.dtd")?\s*>$'
)
_VALUE_TAGS = {"dict", "array", "string", "integer", "real", "true", "false", "date", "data"}


def is_binary(data: bytes) -> bool:
    return data.startswith(b"bplist")


def safe_xml(text: str) -> bool:
    """True if an XML plist declares no entities and at most Apple's standard DOCTYPE."""
    if "<!ENTITY" in text.upper():
        return False
    doctypes = _DOCTYPE.findall(text)
    if not doctypes:
        return "<!DOCTYPE" not in text.upper()
    if len(doctypes) > 1:
        return False
    return bool(_APPLE_DOCTYPE.match(" ".join(doctypes[0].split())))


def loads(data: bytes) -> Optional[Any]:
    """Parse plist bytes (XML or binary). None if invalid or unsafe."""
    if not data:
        return None
    if not is_binary(data):
        text = _decode(data)
        if text is None or not safe_xml(text):
            return None
    try:
        return plistlib.loads(data)
    except Exception:  # noqa: BLE001  (InvalidFileException, ExpatError, ValueError, RecursionError...)
        return None


def load(root: str, rel: str) -> Optional[Any]:
    data = safety.read_bytes(root, rel)
    return loads(data) if data is not None else None


def key_lines(text: str) -> Dict[KeyPath, int]:
    """Map each key path in an XML plist to the line of its `<key>` (array items: their element).

    Returns {} for binary, invalid, or unsafe input. Paths use dict keys and array indices,
    e.g. ("NSAppTransportSecurity", "NSPinnedDomains", "api.example.com").
    """
    if not text or not safe_xml(text):
        return {}
    parser = xml.parsers.expat.ParserCreate()
    lines: Dict[KeyPath, int] = {}
    # Each frame: [kind, path, pending_key, pending_line, next_index]
    stack: List[list] = []
    state = {"in_key": False, "key": "", "key_line": 0}

    def start(tag: str, _attrs: Dict[str, str]) -> None:
        if tag == "key":
            state.update(in_key=True, key="", key_line=parser.CurrentLineNumber)
            return
        if tag not in _VALUE_TAGS:
            return
        path: Optional[KeyPath] = None
        if stack:
            top = stack[-1]
            if top[0] == "dict" and top[2] is not None:
                path = top[1] + (top[2],)
                lines.setdefault(path, top[3])
                top[2] = None
            elif top[0] == "array":
                path = top[1] + (top[4],)
                lines.setdefault(path, parser.CurrentLineNumber)
                top[4] += 1
        else:
            path = ()
        if tag in ("dict", "array") and path is not None:
            stack.append([tag, path, None, 0, 0])

    def end(tag: str) -> None:
        if tag == "key":
            state["in_key"] = False
            if stack and stack[-1][0] == "dict":
                stack[-1][2] = state["key"]
                stack[-1][3] = state["key_line"]
        elif tag in ("dict", "array") and stack:
            stack.pop()

    def chars(data: str) -> None:
        if state["in_key"]:
            state["key"] += data

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(text, True)
    except xml.parsers.expat.ExpatError:
        return {}
    return lines


def line_of(lines: Dict[KeyPath, int], *path: Any) -> int:
    """Line of the deepest known prefix of `path` (0 if unknown, e.g. a binary plist)."""
    p: KeyPath = tuple(path)
    while p:
        if p in lines:
            return lines[p]
        p = p[:-1]
    return 0


def get(obj: Any, *path: Any) -> Any:
    """Walk dicts/arrays; None if any step is missing."""
    cur = obj
    for step in path:
        if isinstance(cur, dict) and isinstance(step, str):
            cur = cur.get(step)
        elif isinstance(cur, list) and isinstance(step, int) and 0 <= step < len(cur):
            cur = cur[step]
        else:
            return None
        if cur is None:
            return None
    return cur


def truthy(value: Any) -> bool:
    """Plist booleans, plus the string/integer spellings people write by hand."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().upper() in ("YES", "TRUE", "1")
    return False


def _decode(data: bytes) -> Optional[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None
