# SPDX-License-Identifier: Apache-2.0
"""Each hashed lock file pins exactly what its .in file asks for.

A regenerated lock can silently drop a package: pip-compile leaves out setuptools unless told
otherwise, and the release build (`python -m build --no-isolation`) needs it from the lock.
"""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
PAIRS = [("scripts", "build-requirements"), ("scripts", "lint-requirements"), ("fuzz", "requirements")]
PIN = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;\\]+)", re.M)


def pins(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return {name.lower().replace("_", "-"): version for name, version in PIN.findall(fh.read())}


class LockFiles(unittest.TestCase):
    def test_every_requested_pin_is_locked(self):
        for folder, stem in PAIRS:
            wanted = pins(f"{folder}/{stem}.in")
            locked = pins(f"{folder}/{stem}.txt")
            with self.subTest(lock=f"{folder}/{stem}.txt"):
                self.assertTrue(wanted, "no pins in the .in file")
                for name, version in wanted.items():
                    self.assertEqual(locked.get(name), version, f"{name}=={version} is missing from the lock")

    def test_every_locked_package_has_a_hash(self):
        for folder, stem in PAIRS:
            with open(os.path.join(ROOT, folder, f"{stem}.txt"), encoding="utf-8") as fh:
                entries = re.split(r"\n(?=[A-Za-z0-9])", fh.read())
            with self.subTest(lock=f"{folder}/{stem}.txt"):
                for entry in entries:
                    if PIN.match(entry):
                        self.assertIn("--hash=sha256:", entry, entry.splitlines()[0])
