# SPDX-License-Identifier: Apache-2.0
"""Reading untrusted repositories safely.

masaudit scans code it didn't write. It never follows a symlink outside the scan root,
never reads huge or binary files, never executes anything, and masks secrets in output.
"""

from __future__ import annotations

import os
import re
import stat
from typing import Iterator, List, Optional, Tuple

MAX_FILE_BYTES = 2 * 1024 * 1024        # 2 MiB: source and config files are far smaller
# Large apps have big Xcode project files (Signal's is 2.5 MB); every project-level iOS check needs it.
MAX_PBXPROJ_BYTES = 16 * 1024 * 1024


def max_bytes(rel: str) -> int:
    """Size limit for one file: Xcode project files get more room than everything else."""
    return MAX_PBXPROJ_BYTES if rel.endswith("project.pbxproj") else MAX_FILE_BYTES
MAX_FILES = 200_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".gradle", ".idea", ".vscode", ".cxx", ".externalNativeBuild",
    "build", "out", "DerivedData", "Pods", "Carthage", "node_modules", ".dart_tool",
    "__pycache__", ".venv", "venv", ".tox", "xcuserdata", ".build", ".swiftpm",
    "intermediates", "generated",
}

SCANNED_SUFFIXES = {
    ".kt", ".kts", ".java", ".swift", ".m", ".mm", ".h", ".xml", ".plist", ".pbxproj",
    ".xcconfig", ".entitlements", ".gradle", ".toml", ".properties", ".yml", ".yaml",
    ".json", ".pro", ".cfg", ".txt", ".strings", ".dart", ".js", ".ts", ".tsx", ".xcprivacy",
    ".c", ".cc", ".cpp", ".mk", ".podspec", ".storyboard", ".xib", ".sh",
    ".html", ".htm",  # pages bundled with the app and shown in a WebView
}
SCANNED_NAMES = {"Podfile", "Package.swift", "Cartfile", "gradlew", "CODEOWNERS", "Fastfile",
                 "contents"}  # "contents": a Core Data model (Model.xcdatamodel/contents)


def is_within(root: str, path: str) -> bool:
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    return path_real == root_real or path_real.startswith(root_real + os.sep)


def walk(root: str, skipped: Optional[List[Tuple[str, str]]] = None) -> List[str]:
    """Return repo-relative paths (forward slashes) of files worth scanning.

    Files of a scanned type that are left out for safety go to `skipped` as (path, reason), so the
    report can say what wasn't checked instead of looking clean.
    """
    out: List[str] = []
    root = os.path.abspath(root)

    def skip(full: str, reason: str) -> None:
        if skipped is not None:
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            skipped.append((re.sub(r"[\x00-\x1f\x7f]", "?", rel), reason))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune in place: skipped dirs are never entered.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            suffix = os.path.splitext(name)[1]
            if suffix not in SCANNED_SUFFIXES and name not in SCANNED_NAMES:
                continue
            full = os.path.join(dirpath, name)
            if _CONTROL.search(name) or "\n" in name or "\r" in name:
                skip(full, "control characters in the name")    # they could forge lines in reports
                continue
            if os.path.islink(full) and not is_within(root, full):
                skip(full, "symbolic link to a file outside the folder")
                continue
            if _is_hard_link(full):
                skip(full, "hard link")       # a hard link can point at any file on the same disk
                continue
            if not _is_regular(full):
                skip(full, "not a regular file")    # a FIFO or device would hang the scan
                continue
            try:
                if os.path.getsize(full) > max_bytes(full):
                    skip(full, f"larger than {max_bytes(full) // (1024 * 1024)} MiB")
                    continue
            except OSError:
                skip(full, "unreadable")
                continue
            out.append(os.path.relpath(full, root).replace(os.sep, "/"))
            if len(out) >= MAX_FILES:
                skip(dirpath, f"the scan stops after {MAX_FILES:,} files")
                return out
    return out


def _is_hard_link(full: str) -> bool:
    try:
        st = os.stat(full, follow_symlinks=False)
    except OSError:
        return True
    return stat.S_ISREG(st.st_mode) and st.st_nlink > 1


def _is_regular(full: str) -> bool:
    """A regular file (after following a symlink). A FIFO or device would block or never end a read."""
    try:
        return stat.S_ISREG(os.stat(full).st_mode)
    except OSError:
        return False


def read_text(root: str, rel: str) -> Optional[str]:
    """Read a text file, tolerating BOMs and UTF-16 (.strings files). None if binary/unreadable."""
    full = os.path.join(root, rel)
    if not is_within(root, full) or _is_hard_link(full) or not _is_regular(full):
        return None
    try:
        with open(full, "rb") as fh:
            data = fh.read(max_bytes(rel) + 1)
    except OSError:
        return None
    if len(data) > max_bytes(rel):
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None      # binary (compiled plists are read separately by the plist parser)
    for enc in ("utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def read_bytes(root: str, rel: str) -> Optional[bytes]:
    full = os.path.join(root, rel)
    if not is_within(root, full) or _is_hard_link(full) or not _is_regular(full):
        return None
    try:
        if os.path.getsize(full) > max_bytes(full):
            return None
        with open(full, "rb") as fh:
            return fh.read()
    except OSError:
        return None


# Secret-looking values are masked in every output (reports, SARIF, terminal).
# Two passes: known token formats first, then any long base64/hex-like run that contains a digit.
_MASK_WINDOW = 400
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_KNOWN_TOKEN = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9_\-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}"
)
_LONG_VALUE = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")


def _hide(val: str) -> str:
    shown = val[:4] if len(val) > 8 else ""
    return f"{shown}…[masked]"


def mask(text: str) -> str:
    # Cut first: the output keeps 160 characters anyway, and a bounded input keeps every regex
    # fast on crafted lines of any length.
    line = text.strip()[:_MASK_WINDOW].replace("\t", " ")
    line = _CONTROL.sub(" ", line)
    line = _KNOWN_TOKEN.sub(lambda m: _hide(m.group(0)), line)

    def long_value(m: "re.Match[str]") -> str:
        val = m.group(0)
        # Long runs without a digit are identifiers (NSAllowsArbitraryLoadsInWebContent), not secrets.
        if "…[masked]" in val or not any(ch.isdigit() for ch in val):
            return val
        return _hide(val)

    line = _LONG_VALUE.sub(long_value, line)
    return line[:160]


def iter_lines(text: str) -> Iterator[tuple]:
    for i, line in enumerate(text.splitlines(), start=1):
        yield i, line


def reject_xml_entities(text: str) -> bool:
    """True if the XML declares a DTD or entities anywhere: masaudit refuses to parse those."""
    upper = text.upper()
    return "<!DOCTYPE" in upper or "<!ENTITY" in upper
