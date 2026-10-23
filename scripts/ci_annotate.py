#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn failing unittest output into GitHub annotations (public, unlike job logs).

    python scripts/ci_annotate.py unittest-output.txt
"""

import re
import sys


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def main(path: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as fh:
        out = fh.read()
    blocks = re.split(r"\n(?==+\n(?:FAIL|ERROR): )", out)
    failures = [b for b in blocks if re.match(r"=+\n(?:FAIL|ERROR): ", b.lstrip("\n"))]
    if not failures:
        failures = [out[-3000:]]
    for block in failures[:10]:
        lines = block.strip("\n=").splitlines()
        title = lines[0][:120] if lines else "unit tests"
        print(f"::error title={escape(title)}::{escape(block[-2500:])}")


if __name__ == "__main__":
    main(sys.argv[1])
