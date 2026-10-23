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
from typing import Dict, List, Optional

from masaudit import profile

FILE_NAME = ".masaudit.ini"
SECTION = "masaudit"
KEYS = ("app_type", "fail_on", "exclude")
FAIL_ON = ("critical", "high", "medium", "low")


class ConfigError(Exception):
    pass


def path_for(root: str) -> str:
    return os.path.join(root, FILE_NAME)


def load(root: str) -> Dict[str, object]:
    """Return {"app_type": str|None, "fail_on": str|None, "exclude": [globs]}."""
    out: Dict[str, object] = {"app_type": None, "fail_on": None, "exclude": []}
    path = path_for(root)
    if not os.path.isfile(path):
        return out
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as fh:
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


def save_app_type(root: str, app_type: str) -> str:
    """Write (or add) app_type to .masaudit.ini, keeping any existing lines. Returns the path."""
    path = path_for(root)
    line = f"app_type = {app_type}\n"
    if not os.path.isfile(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"[{SECTION}]\n{line}")
        return path
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    for i, existing in enumerate(lines):
        if existing.strip() == f"[{SECTION}]":
            lines.insert(i + 1, line)
            break
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines += [f"[{SECTION}]\n", line]
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    return path


def resolve_fail_on(cli_value: Optional[str], cfg: Dict[str, object]) -> Optional[str]:
    return cli_value or cfg.get("fail_on")  # type: ignore[return-value]
