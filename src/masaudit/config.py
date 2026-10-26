# SPDX-License-Identifier: Apache-2.0
"""`.masaudit.ini` at the scan root: per-project defaults.

    [masaudit]
    app_type = banking
    fail_on = high
    exclude = vendor/*, third_party/**

Precedence is CLI > config > prompt > default. Unknown sections or keys are an error, so a
typo never silently changes what gets checked.
"""

from __future__ import annotations

import configparser
import fnmatch
import os
import re
from typing import Dict, List, Optional, Sequence

from masaudit import profile, safety

FILE_NAME = ".masaudit.ini"
SECTION = "masaudit"
KEYS = ("app_type", "app_type_reviewed", "fail_on", "exclude")
FAIL_ON = ("critical", "high", "medium", "low")


class ConfigError(Exception):
    pass


def path_for(root: str) -> str:
    return os.path.join(root, FILE_NAME)


def load(root: str) -> Dict[str, object]:
    """Return {"app_type": str|None, "app_type_reviewed": [types], "fail_on": str|None, "exclude": [globs]}."""
    out: Dict[str, object] = {"app_type": None, "app_type_reviewed": [], "fail_on": None, "exclude": []}
    path = path_for(root)
    if not os.path.lexists(path):
        return out
    # The file belongs to the scanned repository: a link could point at any file on the machine, and an
    # error message would then print a line of it.
    st = os.lstat(path)
    if os.path.islink(path) or not os.path.isfile(path) or st.st_nlink > 1:
        raise ConfigError(f"{FILE_NAME}: not read, because it is a link or not a regular file")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8-sig") as fh:     # Windows Notepad saves a BOM
            parser.read_file(fh, source=path)
    except (configparser.Error, OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{FILE_NAME}: can't read it ({exc.__class__.__name__}: {exc})") from exc
    for section in parser.sections():
        if section != SECTION:
            raise ConfigError(f"{FILE_NAME}: unknown section [{section}] (only [{SECTION}] is allowed)")
    if not parser.has_section(SECTION):
        return out
    for key in parser.options(SECTION):
        if key not in KEYS:
            raise ConfigError(f"{FILE_NAME}: unknown key '{key}' (allowed: {', '.join(KEYS)})")
    sec = parser[SECTION]
    if sec.get("app_type", "").strip():
        try:
            out["app_type"] = profile.normalize(sec["app_type"])
        except ValueError as exc:
            raise ConfigError(f"{FILE_NAME}: {exc}") from exc
    if sec.get("app_type_reviewed", "").strip():
        # App types the code suggested that the team reviewed and decided against; they don't warn.
        try:
            out["app_type_reviewed"] = [profile.normalize(t) for t in split_globs(sec["app_type_reviewed"])]
        except ValueError as exc:
            raise ConfigError(f"{FILE_NAME}: app_type_reviewed: {exc}") from exc
    if sec.get("fail_on", "").strip():
        value = sec["fail_on"].strip().lower()
        if value not in FAIL_ON:
            raise ConfigError(f"{FILE_NAME}: fail_on must be one of {', '.join(FAIL_ON)}, not '{value}'")
        out["fail_on"] = value
    if sec.get("exclude", "").strip():
        out["exclude"] = split_globs(sec["exclude"])
    return out


def split_globs(value: str) -> List[str]:
    parts = value.replace("\n", ",").split(",")
    return [p.strip().replace("\\", "/") for p in parts if p.strip()]


def is_excluded(path: str, globs: List[str]) -> bool:
    """True if a repo-relative path matches a glob, or sits under a directory that does."""
    if not globs:
        return False
    parts = path.split("/")
    prefixes = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    for pattern in globs:
        pat = pattern[2:] if pattern.startswith("./") else pattern
        pat = pat.rstrip("/")
        if pat.endswith("/**"):
            pat = pat[:-3]
        for candidate in prefixes:
            if fnmatch.fnmatchcase(candidate, pat):
                return True
    return False


def save_app_type(root: str, app_type: str, reviewed: Sequence[str] = ()) -> str:
    """Write app_type (and, with `reviewed`, add those types to app_type_reviewed) to .masaudit.ini, keeping
    every other line. A key already in the file is replaced, never added twice. Returns the path."""
    path = path_for(root)
    values = {"app_type": app_type}
    if reviewed:
        try:
            before = list(load(root)["app_type_reviewed"])  # type: ignore[arg-type]
        except ConfigError:
            before = []
        values["app_type_reviewed"] = ", ".join(dict.fromkeys(before + list(reviewed)))
    if not os.path.isfile(path) or os.path.islink(path) or os.stat(path).st_nlink > 1:
        # No config yet, or a symlink or hard link (replaced, never read or followed, as in load()).
        safety.write_text(path, f"[{SECTION}]\n" + "".join(f"{k} = {v}\n" for k, v in values.items()), root, None)
        return path
    with open(path, encoding="utf-8-sig") as fh:
        lines = fh.readlines()
    header = next((i for i, x in enumerate(lines) if x.strip() == f"[{SECTION}]"), None)
    if header is None:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"[{SECTION}]\n")
        header = len(lines) - 1
    end = next((i for i in range(header + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
    for key, value in values.items():
        at = [i for i in range(header + 1, end) if re.match(r"\s*" + key + r"\s*[=:]", lines[i])]
        if at:
            lines[at[0]] = f"{key} = {value}\n"
            for i in reversed(at[1:]):
                del lines[i]
                end -= 1
        else:
            lines.insert(header + 1, f"{key} = {value}\n")
            end += 1
    safety.write_text(path, "".join(lines), root, None)
    return path


def resolve_fail_on(cli_value: Optional[str], cfg: Dict[str, object]) -> Optional[str]:
    return cli_value or cfg.get("fail_on")  # type: ignore[return-value]
