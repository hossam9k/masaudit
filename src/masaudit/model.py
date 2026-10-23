# SPDX-License-Identifier: Apache-2.0
"""Core data types shared by every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Where in the project a hit was found. Hits outside "main" are downgraded, never dropped.
SCOPES = ["main", "debug", "test", "build-script", "ci", "unknown"]


@dataclass
class Rule:
    """One check, loaded from rules/*.json. Text fields are plain language for newcomers."""

    id: str
    title: str
    platform: str                      # android | ios | kmp | cross | ci
    severity: str                      # base severity for the profiles in `profiles`
    profiles: List[str]                # MAS profiles this weakness belongs to: L1, L2, R, P
    why: str                           # one or two sentences: why this matters
    fix: str                           # one to three lines: what to change
    verify: str                        # how to confirm the fix worked
    effort: str                        # minutes | hours | days
    book: str                          # e.g. "§7.1"
    book_url: str                      # absolute link to the book section
    maswe: Optional[str] = None        # e.g. "MASWE-0050"
    masvs: Optional[str] = None        # e.g. "MASVS-NETWORK-1"
    mastg: List[str] = field(default_factory=list)
    app_types: Optional[List[str]] = None   # only these app types need it (e.g. pinning); None = all
    not_needed_reason: str = ""        # shown under "Not needed for your app"
    fix_code: Optional[Dict[str, str]] = None   # {"lang": "xml", "code": "..."}; MIT-0
    confidence: str = "high"           # high | medium | manual (manual = needs a human or AI look)
    safe_fix: bool = False
    detector: Optional[str] = None     # name of a registered Python detector
    pattern: Optional[Dict] = None     # declarative code pattern (see engine.run_pattern)
    retired: bool = False


@dataclass
class Location:
    path: str                          # repo-relative, forward slashes
    line: int = 0                      # 1-based; 0 = whole file / unknown
    snippet: str = ""                  # masked, single line, max 160 chars


@dataclass
class Finding:
    rule: Rule
    location: Location
    message: str = ""                  # detector-specific detail, plain language
    scope: str = "main"
    status: str = "open"               # open | suppressed | baselined
    suppression_reason: str = ""
    effective_severity: str = ""       # filled in by calibration
    bucket: str = ""                   # fix-before-release | fix-soon | notes | not-needed
    bucket_reason: str = ""

    def fingerprint(self) -> str:
        import hashlib

        basis = f"{self.rule.id}|{self.location.path}|{self.location.snippet.strip()}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


@dataclass
class Profile:
    app_type: str                      # banking, identity, health, ...
    mas_profiles: List[str]            # e.g. ["L1", "L2", "P", "R"]
    source: str                        # "flag", "config", "prompt", "default"
    suggestions: List[str] = field(default_factory=list)   # code clues, stated, never applied silently


@dataclass
class Project:
    root: str
    platforms: List[str]               # android, ios, kmp, flutter, react-native, ci
    files: List[str]                   # repo-relative paths that passed safety checks
    unknowns: List[str] = field(default_factory=list)      # things the scanner could not decide
    undecided: Dict[str, str] = field(default_factory=dict)  # rule id -> why it couldn't decide
