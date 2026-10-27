# SPDX-License-Identifier: Apache-2.0
"""Core data types shared by every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Where in the project a hit was found. Hits outside "main" are downgraded, never dropped.
SCOPES = ["main", "debug", "test", "unshipped", "unused", "build-script", "ci", "unknown"]


def a_type(app_type: str) -> str:
    """"a banking", "an ecommerce": the app type with its article."""
    return ("an " if app_type[:1].lower() in "aeiou" else "a ") + app_type


@dataclass
class Rule:
    """One check, loaded from rules/*.json. Text fields are plain language for newcomers."""

    id: str
    title: str
    platform: str                      # android | ios | kmp | flutter | cross | ci
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
    kind: str = "weakness"             # weakness | hardening (a protection the app has nowhere; a checklist item)
    safe_fix: bool = False
    detector: Optional[str] = None     # name of a registered Python detector
    pattern: Optional[Dict] = None     # declarative code pattern (see engine.run_pattern)
    retired: bool = False


@dataclass
class Location:
    path: str                          # repo-relative, forward slashes
    line: int = 0                      # 1-based; 0 = whole file / unknown
    snippet: str = ""                  # masked, single line, max 160 chars
    fingerprint_text: str = ""         # the snippet as safety.mask gives it, for a stable fingerprint; never shown


@dataclass
class Finding:
    rule: Rule
    location: Location
    message: str = ""                  # detector-specific detail, plain language
    scope: str = "main"
    status: str = "open"               # open | suppressed | baselined
    suppression_reason: str = ""
    effective_severity: str = ""       # filled in by calibration
    bucket: str = ""                   # fix-before-release | fix-soon | check-by-hand | hardening | notes | not-needed
    bucket_reason: str = ""
    acknowledged: str = ""             # the team marked it intentional in the source (e.g. Lint tools:ignore)
    severity: str = ""                 # this hit's own severity when it differs from the rule's; "" = rule's
    occurrence: int = 1                # 2, 3, ... for later findings of the same rule on an identical line

    def fingerprint(self, legacy: bool = False) -> str:
        """Stable across line moves: rule, path, and the line's text. A second identical line gets its own
        fingerprint (the first keeps the one earlier versions wrote), so a baseline never covers a copy.
        `legacy`: the fingerprint before 0.6.1, the same for every identical line."""
        import hashlib

        text = self.location.fingerprint_text or self.location.snippet
        basis = f"{self.rule.id}|{self.location.path}|{text.strip()}"
        if self.occurrence > 1 and not legacy:
            basis += f"|#{self.occurrence}"
        # surrogatepass: a lone surrogate (from an imported SARIF, say) can't crash it; valid text is unchanged.
        return hashlib.sha256(basis.encode("utf-8", "surrogatepass")).hexdigest()[:32]


@dataclass
class AppTypeWarning:
    """The code suggests a riskier app type than the one chosen ("Check your app type")."""
    chosen: str                        # the app type in use
    source: str                        # where it came from: flag, config, prompt, default
    suggested: str                     # the type the evidence points to
    evidence: str                      # what was found, e.g. "card-number fields"
    path: str                          # the first file it was found in
    extra_checks: int                  # checks the suggested type runs that the chosen one skips
    hidden: List[Tuple[str, str]] = field(default_factory=list)  # (rule id, title) under Not needed

    def lines(self) -> List[str]:
        """The warning as short plain lines: the first is the headline."""
        chose = ("No app type was given, so masaudit assumed general." if self.source == "default"
                 else f"You chose:  {self.chosen}")
        n = self.extra_checks
        out = [
            "Check your app type.",
            chose,
            f"The code:   {self.path} has {self.evidence}.",
            f"Suggests:   {self.suggested}, which adds {n} {'check' if n == 1 else 'checks'} for this project.",
        ]
        if self.hidden:
            names = "; ".join(title for _id, title in self.hidden[:3]) + ("; ..." if len(self.hidden) > 3 else "")
            k = len(self.hidden)
            out.append(f"Hidden:     {k} {'finding is' if k == 1 else 'findings are'} under Not needed: {names}")
        if self.source == "config":
            out.append(f"To fix:     set app_type = {self.suggested} in .masaudit.ini.")
        else:
            out.append(f"To fix:     run again with --app-type {self.suggested}.")
        out.append(f"Keeping {self.chosen} on purpose? Add app_type_reviewed = {self.suggested} to .masaudit.ini.")
        return out

    def summary(self) -> str:
        """One line, for annotations and SARIF."""
        return (f"Check your app type: {self.path} has {self.evidence}, which suggests {self.suggested} "
                f"({self.extra_checks} more checks) instead of {self.chosen}.")

    def to_dict(self) -> dict:
        return {"chosen": self.chosen, "source": self.source, "suggested": self.suggested,
                "evidence": {"label": self.evidence, "path": self.path},
                "extra_checks": self.extra_checks,
                "hidden": [{"rule_id": i, "title": t} for i, t in self.hidden],
                "message": self.summary()}


@dataclass
class Profile:
    app_type: str                      # banking, identity, health, ...
    mas_profiles: List[str]            # e.g. ["L1", "L2", "P", "R"]
    source: str                        # "flag", "config", "prompt", "default"
    suggestions: List[str] = field(default_factory=list)   # code clues, stated, never applied silently
    warnings: List["AppTypeWarning"] = field(default_factory=list)  # the code suggests a riskier type


@dataclass
class Project:
    root: str
    platforms: List[str]               # android, ios, kmp, flutter, react-native, ci
    files: List[str]                   # repo-relative paths that passed safety checks
    unknowns: List[str] = field(default_factory=list)      # things the scanner could not decide
    undecided: Dict[str, str] = field(default_factory=dict)  # rule id -> why it couldn't decide
    exclude: List[str] = field(default_factory=list)        # the config's `exclude` globs
