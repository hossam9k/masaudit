# SPDX-License-Identifier: Apache-2.0
"""Suppressions: inline `masaudit:ignore RULE-ID reason` comments and a baseline file.

Inline: put the comment on the line of the hit or the line above, in any comment syntax
(`//`, `#`, `<!-- -->`, `/* */`). A reason is required; without one the comment is ignored
and the report says so.

Baseline: a JSON file of finding fingerprints that were accepted at some point. Baselined
findings stay in the report (marked) but don't count toward --fail-on.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.model import Finding

_INLINE = re.compile(r"masaudit:ignore[ \t]+(?P<ids>[A-Za-z]+-[A-Za-z0-9-]+(?:[ \t]*,[ \t]*[A-Za-z]+-[A-Za-z0-9-]+)*)"
                     r"(?P<reason>[^\r\n]*)")
# Comment closers and decoration to trim from the end of a reason.
_TRAILER = re.compile(r"\s*(?:-->|\*/|\*\)|%>|#>|--)\s*$")

BASELINE_SCHEMA = 1


class BaselineError(Exception):
    pass


def _clean_reason(raw: str) -> str:
    reason = _strip_trailers(raw.strip())
    reason = re.sub(r"^[:\-—]+\s*", "", reason)
    return _strip_trailers(reason).strip()


def _strip_trailers(reason: str) -> str:
    while True:
        trimmed = _TRAILER.sub("", reason)
        if trimmed == reason:
            return reason
        reason = trimmed


def parse_line(line: str) -> List[Tuple[str, str]]:
    """Return [(RULE-ID, reason)] for every masaudit:ignore directive on a line."""
    out = []
    for m in _INLINE.finditer(line):
        reason = _clean_reason(m.group("reason"))
        for rule_id in re.split(r"[ \t]*,[ \t]*", m.group("ids").strip()):
            out.append((rule_id.upper(), reason))
    return out


def apply_inline(findings: List[Finding], root: str) -> List[str]:
    """Mark findings suppressed by an inline comment. Returns notes for the report."""
    notes: List[str] = []
    cache: Dict[str, Optional[List[str]]] = {}
    for f in findings:
        if f.status != "open" or f.location.line < 1 or not f.location.path:
            continue
        path = f.location.path
        if path not in cache:
            text = safety.read_text(root, path)
            cache[path] = text.splitlines() if text is not None else None
        lines = cache[path]
        if not lines:
            continue
        for lineno in (f.location.line, f.location.line - 1):
            if not 1 <= lineno <= len(lines):
                continue
            for rule_id, reason in parse_line(lines[lineno - 1]):
                if rule_id != f.rule.id.upper():
                    continue
                if not reason:
                    note = (f"Ignored `masaudit:ignore {f.rule.id}` at {path}:{lineno}: "
                            "a reason is required, so the finding still counts.")
                    if note not in notes:
                        notes.append(note)
                    continue
                f.status = "suppressed"
                f.suppression_reason = safety.mask(reason)
                break
            if f.status == "suppressed":
                break
    return notes


# ---------------------------------------------------------------------------- baseline


def load_baseline(path: str) -> Set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise BaselineError(f"baseline file not found: {path} (create it with --update-baseline)") from None
    except (OSError, ValueError) as exc:
        raise BaselineError(f"can't read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
        raise BaselineError(f"{path} is not a masaudit baseline (expected a 'findings' object)")
    return {str(k) for k in data["findings"]}


def apply_baseline(findings: Iterable[Finding], fingerprints: Set[str]) -> int:
    count = 0
    for f in findings:
        if f.status == "open" and f.fingerprint() in fingerprints:
            f.status = "baselined"
            count += 1
    return count


def write_baseline(path: str, findings: Iterable[Finding]) -> int:
    """Record every finding that isn't suppressed inline. Returns how many were written."""
    entries = {}
    for f in findings:
        if f.status == "suppressed":
            continue
        entries[f.fingerprint()] = {"rule": f.rule.id, "path": f.location.path, "line": f.location.line}
    data = {"schema_version": BASELINE_SCHEMA, "tool": "masaudit",
            "findings": dict(sorted(entries.items()))}
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=False)
        fh.write("\n")
    return len(entries)
