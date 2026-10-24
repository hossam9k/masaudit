# SPDX-License-Identifier: Apache-2.0
"""Shared Xcode schemes (`*.xcodeproj/xcshareddata/xcschemes/*.xcscheme`).

A scheme says which build configuration each action uses. The one that matters for a
security scan is the Archive action: its `buildConfiguration` is what ships to TestFlight and
the App Store, whatever the configuration is called. We also keep the targets the scheme
builds for archiving, by their pbxproj object id (BlueprintIdentifier).

Only shared schemes are read: per-user schemes live under xcuserdata, which the scanner skips.
"""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass, field
from typing import List, Optional

from masaudit import safety
from masaudit.parsers import xmlsafe

MAX_SCHEMES = 200


@dataclass
class Scheme:
    name: str
    archive_config: Optional[str] = None             # ArchiveAction@buildConfiguration
    launch_config: Optional[str] = None              # LaunchAction@buildConfiguration
    archive_targets: List[str] = field(default_factory=list)   # BlueprintIdentifier values
    archive_target_names: List[str] = field(default_factory=list)


def parse(text: Optional[str], name: str = "") -> Optional[Scheme]:
    """Parse one .xcscheme. None if it isn't a scheme (or declares a DTD or entities)."""
    if not text:
        return None
    root = xmlsafe.parse(text)
    if root is None or root.tag != "Scheme":
        return None
    scheme = Scheme(name=name)
    for el in root.children:
        if el.tag == "ArchiveAction":
            scheme.archive_config = (el.get("buildConfiguration") or "").strip() or None
        elif el.tag == "LaunchAction":
            scheme.launch_config = (el.get("buildConfiguration") or "").strip() or None
        elif el.tag == "BuildAction":
            for entry in el.iter("BuildActionEntry"):
                if (entry.get("buildForArchiving") or "").upper() != "YES":
                    continue
                for ref in entry.iter("BuildableReference"):
                    bid = (ref.get("BlueprintIdentifier") or "").strip()
                    if bid:
                        scheme.archive_targets.append(bid)
                    bname = (ref.get("BlueprintName") or "").strip()
                    if bname:
                        scheme.archive_target_names.append(bname)
    return scheme


def shared_schemes(root: str, container: str) -> List[Scheme]:
    """Shared schemes of an .xcodeproj or .xcworkspace folder (repo-relative), sorted by name."""
    rel = posixpath.join(container, "xcshareddata", "xcschemes") if container else "xcshareddata/xcschemes"
    full = os.path.join(root, rel)
    if not safety.is_within(root, full) or os.path.islink(full) or not os.path.isdir(full):
        return []
    try:
        names = sorted(os.listdir(full))
    except OSError:
        return []
    out: List[Scheme] = []
    for fname in names[:MAX_SCHEMES]:
        if not fname.endswith(".xcscheme"):
            continue
        path = posixpath.join(rel, fname)
        if os.path.islink(os.path.join(root, path)):
            continue
        scheme = parse(safety.read_text(root, path), fname[: -len(".xcscheme")])
        if scheme is not None:
            out.append(scheme)
    return out
