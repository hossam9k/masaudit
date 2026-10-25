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
    "intermediates", "generated", ".expo", ".expo-shared", "coverage", "dist", "web-build",
}

SCANNED_SUFFIXES = {
    ".kt", ".kts", ".java", ".swift", ".m", ".mm", ".h", ".xml", ".plist", ".pbxproj",
    ".xcconfig", ".entitlements", ".gradle", ".toml", ".properties", ".yml", ".yaml",
    ".json", ".pro", ".cfg", ".txt", ".strings", ".dart", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
    ".xcprivacy",
    ".c", ".cc", ".cpp", ".mk", ".podspec", ".storyboard", ".xib", ".sh",
    ".html", ".htm",  # pages bundled with the app and shown in a WebView
}
SCANNED_NAMES = {"Podfile", "Package.swift", "Cartfile", "gradlew", "CODEOWNERS", "Fastfile",
                 "contents", ".npmrc", ".yarnrc", ".yarnrc.yml", ".env"}
# Environment files that React Native tooling bundles into the app: .env.production, .env.staging...
_ENV_FILE = re.compile(r"^\.env\.[\w.-]{1,40}$")  # "contents": a Core Data model (Model.xcdatamodel/contents)


MAX_INT_DIGITS = 18      # no real version, size, or duration needs more


def small_int(text: str) -> Optional[int]:
    """The number in `text` when it is a plausible run of ASCII digits, else None. A crafted file can hold a
    5,000-digit number, which Python 3.11+ refuses to convert (ValueError), or a Unicode digit such as "²",
    which isdigit() accepts and int() rejects."""
    t = text.strip()
    if not t or len(t) > MAX_INT_DIGITS or not t.isascii() or not t.isdigit():
        return None
    return int(t)


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

    def unreadable(err: OSError) -> None:
        # A folder that can't be listed (no permission, a path too long) would otherwise vanish silently.
        skip(err.filename or root, f"folder not readable ({err.strerror or err.__class__.__name__})")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=unreadable):
        # Prune in place: skipped dirs are never entered.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            suffix = os.path.splitext(name)[1]
            if suffix not in SCANNED_SUFFIXES and name not in SCANNED_NAMES and not _ENV_FILE.match(name):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if has_control(rel):
                skip(full, "control characters in the name")    # in a file or folder name, they could forge lines
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
    """A file with more than one name: it, or the file a symlink points to, can be any file on the disk."""
    try:
        st = os.stat(full, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            st = os.stat(full)
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


def has_control(path: str) -> bool:
    """Control characters (newlines included) in a file or folder name: printed, they could forge report
    lines or GitHub workflow commands, so no walker accepts such a path."""
    return bool(_CONTROL.search(path)) or "\n" in path or "\r" in path
_KNOWN_TOKEN = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk-[A-Za-z0-9_\-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}"
)
_LONG_VALUE = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")
# Values next to a name that says they are secret, whatever detector matched the line: a quoted value
# assigned to a secret-named key (`clientSecret = "..."`, `password: '...'`), `password=...` inside a
# string (a value with letters and digits, so `password = getPassword()` stays readable), and a key-value
# call (`setItem('password', '...')`).
_NOT_A_SECRET = {"true", "false", "null", "nil", "none", "undefined", "yes", "no", "bearer", "basic"}
_SECRET_NAME = r"(?:secret|passw(?:or)?d|pwd|passphrase|token|api[_-]?key|private[_-]?key|credential)"
_NAME_NOT_SECRET = ("url", "uri", "endpoint", "type", "name", "label", "hint", "header", "path", "field", "key_name",
                    "keyname", "length", "count", "expiry", "expires", "expiration", "storage")
_NAMED_SECRET = re.compile(
    r"(?P<key>" + _SECRET_NAME + r"[\w$-]{0,40})[\"']?\s{0,5}(?:[:=]|=>)\s{0,5}@?[\"'`](?P<v1>[^\"'`\n]{4,200})"
    r"|(?:password|passwd|pwd|secret|token|api[_-]?key)\s{0,5}=\s{0,5}"
    r"(?P<v2>(?=[^\s\"'`&,;<>)]{0,200}\d)(?=[^\s\"'`&,;<>)]{0,200}[a-z])[^\s\"'`&,;<>)]{4,200})"
    r"|[\"'][\w.-]{0,40}" + _SECRET_NAME + r"[\w.-]{0,40}[\"']\s{0,5},\s{0,5}[\"'](?P<v3>[^\"'\n]{4,200})",
    re.IGNORECASE)


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


def mask_names(snippet: str) -> str:
    """mask() plus values that a secret-like name labels (`clientSecret = "..."`, `password=...` in a
    string, `setItem('token', '...')`), for every snippet a report shows. Kept apart from mask(): a
    baseline fingerprint is built from mask()'s text, so a finding keeps its fingerprint across versions."""
    def named(m: "re.Match[str]") -> str:
        g = next(name for name in ("v1", "v2", "v3") if m.group(name) is not None)
        val = m.group(g)
        key = (m.group("key") or "").lower() if g == "v1" else ""
        if ("…[masked]" in val or val.strip().lower() in _NOT_A_SECRET or "://" in val or " " in val.strip()
                or key.endswith(_NAME_NOT_SECRET)):
            return m.group(0)               # a URL, a sentence, or a name like tokenEndpoint or passwordHint
        start, end = m.start(g) - m.start(), m.end(g) - m.start()
        return m.group(0)[:start] + _hide(val) + m.group(0)[end:]

    return _NAMED_SECRET.sub(named, snippet[:_MASK_WINDOW])


def _inside(path: str, root: str) -> bool:
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except ValueError:                  # Windows: another drive
        return False
    return rel != ".." and not rel.startswith(".." + os.sep)


def write_text(path: str, text: str, root: Optional[str] = None, newline: Optional[str] = "\n") -> None:
    """Write a file masaudit owns (a report, baseline, patch, or .masaudit.ini). Inside the scanned folder
    the repository decides what already sits at `path`, so a symlink or hard link there is replaced, never
    followed, and a FIFO or device is refused: the text goes to a new file that takes the old name. Outside
    it (`--output /dev/null`, a path the user typed) the file is written as usual."""
    if root is None or not _inside(path, root):
        with open(path, "w", encoding="utf-8", newline=newline) as fh:
            fh.write(text)
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None and not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
        raise OSError(f"{path} is not a regular file")
    import tempfile
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".masaudit-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as fh:
            fh.write(text)
        mask = os.umask(0)
        os.umask(mask)
        os.chmod(tmp, 0o666 & ~mask)        # the permissions a plain open() would give
        os.replace(tmp, path)               # replaces the directory entry: a link's target is untouched
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def lines(text: str) -> List[str]:
    """The lines of `text`, numbered the way findings count them: split at "\n" only (a trailing "\r" removed).
    str.splitlines also splits at form feeds, U+0085, and U+2028, which would shift every later line."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def iter_lines(text: str) -> Iterator[tuple]:
    for i, line in enumerate(lines(text), start=1):
        yield i, line


def reject_xml_entities(text: str) -> bool:
    """True if the XML declares a DTD or entities anywhere: masaudit refuses to parse those."""
    upper = text.upper()
    return "<!DOCTYPE" in upper or "<!ENTITY" in upper
