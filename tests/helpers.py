# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers: scan a fixture directory with every platform enabled."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from masaudit import engine, safety  # noqa: E402
from masaudit.model import Project  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ALL_PLATFORMS = ["android", "ios", "kmp", "ci", "flutter", "react-native"]


def _materialized(path):
    """Copy a fixture to a temp dir with {{FAKE_*}} placeholders filled in, if it has any."""
    import shutil
    import tempfile

    from fake_secrets import materialize

    needs = False
    for dirpath, _dirs, names in os.walk(path):
        for name in names:
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    if "{{FAKE_" in fh.read():
                        needs = True
            except (UnicodeDecodeError, OSError):
                pass
    if not needs:
        return path
    tmp = os.path.join(tempfile.mkdtemp(prefix="masaudit-fixture-"), os.path.basename(path))
    shutil.copytree(path, tmp)
    for dirpath, _dirs, names in os.walk(tmp):
        for name in names:
            full = os.path.join(dirpath, name)
            try:
                with open(full, encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            if "{{FAKE_" in text:
                with open(full, "w", encoding="utf-8") as fh:
                    fh.write(materialize(text))
    return tmp


def scan_dir(path, rule_ids=None):
    path = _materialized(path)
    files = safety.walk(path)
    project = Project(root=path, platforms=ALL_PLATFORMS, files=files)
    rules = engine.load_rules()
    if rule_ids:
        rules = [r for r in rules if r.id in rule_ids]
    return engine.run(project, rules)
