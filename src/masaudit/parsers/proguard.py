# SPDX-License-Identifier: Apache-2.0
"""R8 / ProGuard keep-rule files, split into one entry per option.

A rule starts with `-option` and runs until the next option; `#` starts a comment. We only read
the text, never the classes it names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_OPTION = re.compile(r"-(?P<name>[A-Za-z]+)(?P<rest>[^\n]*)")


@dataclass
class Option:
    line: int        # 1-based line of the `-option`
    name: str        # "keep", "keepnames", "dontobfuscate", ...
    spec: str        # the rest of the rule, whitespace collapsed (may span lines)


def _strip_comment(line: str) -> str:
    i = line.find("#")
    return line if i == -1 else line[:i]


def parse(text: str) -> List[Option]:
    out: List[Option] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("-"):
            m = _OPTION.match(line)
            if m:
                out.append(Option(lineno, m.group("name"), " ".join(m.group("rest").split())))
                continue
        if out:          # continuation of the previous rule, such as a class body over several lines
            prev = out[-1]
            prev.spec = (prev.spec + " " + " ".join(line.split()))[:2000]
    return out


def class_pattern(spec: str) -> str:
    """The class name pattern of a keep rule: `class com.x.** { *; }` -> "com.x.**". Empty if none."""
    m = re.search(r"(?:^|\s)(?:class|interface|enum|@interface)\s+(\S+)", spec)
    return m.group(1) if m else ""
