# SPDX-License-Identifier: Apache-2.0
"""Suppressions: inline `masaudit:ignore RULE-ID reason` comments and a baseline file.

Inline: put the comment on the line of the hit or the line above, in any comment syntax
(`//`, `#`, `<!-- -->`, `/* */`). A reason is required; without one the comment is ignored
and the report says so.

Baseline: a JSON file of finding fingerprints that were accepted at some point, each with an optional
reason and expiry date. Baselined findings stay in the report (marked, with the reason) but don't count
toward --fail-on. Entries that match no finding any more, or that expired, are reported.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.model import Finding

_INLINE = re.compile(r"masaudit:ignore[ \t]+(?P<ids>[A-Za-z]+-[A-Za-z0-9-]+(?:[ \t]*,[ \t]*[A-Za-z]+-[A-Za-z0-9-]+)*)"
                     r"(?P<reason>[^\r\n]*)")
# Comment closers and decoration to trim from the end of a reason.
_TRAILER = re.compile(r"\s*(?:-->|\*/|\*\)|%>|#>|--)\s*$")

# 2: a finding on a second identical line has its own fingerprint (Finding.occurrence). A schema 1 file,
# written before that, still covers every identical line, so an upgrade doesn't turn accepted findings new.
# 3: an entry may have a `reason` (shown wherever the finding is listed as accepted) and an `expires` date
# (after it, the finding counts again). Schemas 1 and 2 are still read.
BASELINE_SCHEMA = 3


class BaselineSet(set):
    """The fingerprints of a baseline file; `legacy` when it predates per-occurrence fingerprints, and
    `entries` (fingerprint -> entry) with each entry's rule, path, line, and optional reason and expires."""
    legacy = False
    entries: Dict[str, dict] = {}


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
            cache[path] = safety.lines(text) if text is not None else None
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


MAX_BASELINE_BYTES = 50 * 1024 * 1024
MAX_REASON = 300
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass
class BaselineOutcome:
    """What applying a baseline did: findings it accepted, entries that no longer match any finding (the code
    was fixed, moved, or excluded), and entries past their `expires` date (their findings count again)."""
    matched: int = 0
    stale: List[dict] = field(default_factory=list)
    expired: List[dict] = field(default_factory=list)

    def notes(self, name: str) -> List[str]:
        out = []
        if self.expired:
            n = len(self.expired)
            first = min(e["expires"] for e in self.expired)
            out.append(f"{n} {'entry' if n == 1 else 'entries'} in {name} expired (the first on {first}), so "
                       f"{'its finding counts' if n == 1 else 'their findings count'} again. Fix "
                       f"{'it' if n == 1 else 'them'}, or accept again with a new expires date.")
        if self.stale:
            n = len(self.stale)
            out.append(f"{n} {'entry' if n == 1 else 'entries'} in {name} no longer match a finding (fixed, moved, "
                       "or excluded). Run masaudit with --update-baseline to remove "
                       f"{'it' if n == 1 else 'them'}.")
        return out

    def to_dict(self) -> dict:
        return {"matched": self.matched, "stale": len(self.stale), "expired": len(self.expired)}


def _entry(fp: str, raw: object, path: str) -> dict:
    """One baseline entry, checked: rule, path, line (informational), reason and expires (optional)."""
    raw = raw if isinstance(raw, dict) else {}
    entry = {"fingerprint": fp}
    for key in ("rule", "path"):
        if isinstance(raw.get(key), str):
            entry[key] = safety.clean_text(raw[key])[:300]
    if isinstance(raw.get("line"), int) and not isinstance(raw.get("line"), bool):
        entry["line"] = raw["line"]
    reason = raw.get("reason")
    if reason is not None:
        if not isinstance(reason, str):
            raise BaselineError(f"{path}: the reason of entry {fp[:12]} must be text")
        reason = safety.mask(re.sub(r"\s+", " ", safety.clean_text(reason)).strip())[:MAX_REASON]
        if reason:
            entry["reason"] = reason
    expires = raw.get("expires")
    if expires is not None:
        if not isinstance(expires, str) or not _DATE.match(expires) or not _valid_date(expires):
            raise BaselineError(f"{path}: expires of entry {fp[:12]} must be a date like 2027-01-31, "
                                f"not {str(expires)[:40]!r}")
        entry["expires"] = expires
    return entry


def _valid_date(value: str) -> bool:
    try:
        datetime.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def load_baseline(path: str) -> "BaselineSet":
    try:
        if os.path.getsize(path) > MAX_BASELINE_BYTES:
            raise BaselineError(f"baseline {path} is larger than {MAX_BASELINE_BYTES // (1024 * 1024)} MiB")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise BaselineError(f"baseline file not found: {path} (create it with --update-baseline)") from None
    except (OSError, ValueError, RecursionError) as exc:  # RecursionError: deeply nested JSON
        raise BaselineError(f"can't read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
        raise BaselineError(f"{path} is not a masaudit baseline (expected a 'findings' object)")
    name = os.path.basename(path)
    out = BaselineSet(str(k) for k in data["findings"])
    out.entries = {str(k): _entry(str(k), v, name) for k, v in data["findings"].items()}
    schema = data.get("schema_version")
    out.legacy = not isinstance(schema, int) or schema < 2
    return out


def apply(findings: Iterable[Finding], baseline: Set[str], today: Optional[str] = None) -> BaselineOutcome:
    """Mark open findings the baseline accepts as baselined, unless their entry expired before `today`
    (an ISO date). Every entry that no finding matches, whatever its status, is stale."""
    legacy = getattr(baseline, "legacy", False)
    entries: Dict[str, dict] = getattr(baseline, "entries", {}) or {fp: {"fingerprint": fp} for fp in baseline}
    outcome = BaselineOutcome()
    seen: Set[str] = set()
    expired: Set[str] = set()
    for f in findings:
        fp = f.fingerprint(legacy=legacy)
        if fp not in baseline:
            continue
        seen.add(fp)
        entry = entries.get(fp, {})
        if today and entry.get("expires") and entry["expires"] < today:
            expired.add(fp)
            continue
        if f.status == "open":
            f.status = "baselined"
            f.suppression_reason = entry.get("reason", "")
            outcome.matched += 1
    outcome.expired = [entries.get(fp, {"fingerprint": fp}) for fp in sorted(expired)]
    outcome.stale = [entries.get(fp, {"fingerprint": fp}) for fp in sorted(set(baseline) - seen)]
    return outcome


def apply_baseline(findings: Iterable[Finding], fingerprints: Set[str], today: Optional[str] = None) -> int:
    return apply(findings, fingerprints, today).matched


def write_baseline(path: str, findings: Iterable[Finding], root: Optional[str] = None,
                   previous: Optional[Set[str]] = None, reason: str = "", expires: str = "") -> int:
    """Record every finding that isn't suppressed inline. Returns how many were written. An entry the
    `previous` baseline had keeps its reason and expires date, so hand-written reasons survive a refresh;
    a new entry gets `reason` and `expires`, when given."""
    old: Dict[str, dict] = getattr(previous, "entries", {}) if previous is not None else {}
    legacy = getattr(previous, "legacy", False)
    reason = safety.mask(re.sub(r"\s+", " ", safety.clean_text(reason)).strip())[:MAX_REASON]
    if expires and not (_DATE.match(expires) and _valid_date(expires)):
        raise BaselineError(f"--baseline-expires must be a date like 2027-01-31, not {expires[:40]!r}")
    entries = {}
    for f in findings:
        if f.status == "suppressed":
            continue
        entry = {"rule": f.rule.id, "path": f.location.path, "line": f.location.line}
        before = old.get(f.fingerprint(legacy=legacy)) or old.get(f.fingerprint())
        if before is not None:
            entry.update({k: before[k] for k in ("reason", "expires") if k in before})
        else:
            if reason:
                entry["reason"] = reason
            if expires:
                entry["expires"] = expires
        entries[f.fingerprint()] = entry
    data = {"schema_version": BASELINE_SCHEMA, "tool": "masaudit",
            "findings": dict(sorted(entries.items()))}
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    safety.write_text(path, json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False) + "\n", root,
                      newline=None)
    return len(entries)
