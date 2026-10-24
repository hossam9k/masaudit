#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build dist/masaudit.pyz: a single-file, stdlib-only build runnable as `python3 masaudit.pyz .`.

The archive is reproducible: entries are sorted, timestamps are fixed (SOURCE_DATE_EPOCH, or
1980-01-01), permissions are fixed, and __pycache__ / compiled files are left out. It uses
zipfile directly because `python -m zipapp` doesn't control timestamps or ordering.

    python3 scripts/build_zipapp.py [--output PATH]
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE_DIR = os.path.join(ROOT, "src", "masaudit")
SHEBANG = b"#!/usr/bin/env python3\n"
MAIN = (
    "# SPDX-License-Identifier: Apache-2.0\n"
    "import sys\n\n"
    "from masaudit.cli import main\n\n"
    "sys.exit(main())\n"
)
INCLUDE_SUFFIXES = (".py", ".json")
EPOCH_1980 = (1980, 1, 1, 0, 0, 0)


def _date_time():
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch:
        try:
            t = time.gmtime(max(int(epoch), 315532800))     # zip can't store dates before 1980
            return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2)
        except (ValueError, OverflowError):
            pass
    return EPOCH_1980


def collect() -> list:
    """(archive name, source path) pairs for the package, sorted."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(PACKAGE_DIR):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
        for name in filenames:
            if not name.endswith(INCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, os.path.dirname(PACKAGE_DIR)).replace(os.sep, "/")
            entries.append((rel, full))
    return sorted(entries)


def _info(name: str, date_time) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=date_time)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3                                   # Unix, so the mode bits below are honored
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def build(output: str) -> str:
    output = os.path.abspath(output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    date_time = _date_time()
    tmp = output + ".tmp"
    with open(tmp, "wb") as raw:
        raw.write(SHEBANG)
        with zipfile.ZipFile(raw, "w") as zf:
            zf.writestr(_info("__main__.py", date_time), MAIN.encode("utf-8"), compresslevel=9)
            for name, full in collect():
                with open(full, "rb") as fh:
                    data = fh.read()
                zf.writestr(_info(name, date_time), data, compresslevel=9)
    os.chmod(tmp, 0o700)          # runnable by its owner; git records only the executable bit
    os.replace(tmp, output)
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build a reproducible masaudit.pyz")
    parser.add_argument("--output", default=os.path.join(ROOT, "dist", "masaudit.pyz"),
                        help="where to write the archive (default: dist/masaudit.pyz)")
    args = parser.parse_args(argv)
    path = build(args.output)
    print(f"Built {path} ({os.path.getsize(path)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
