# SPDX-License-Identifier: Apache-2.0
"""Reading untrusted repositories: symlinks, XML entities, huge files, secret masking."""

import os
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import safety
from masaudit.parsers import xmlsafe


class Safety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "repo")
        self.outside = os.path.join(self.tmp.name, "outside")
        os.makedirs(self.root)
        os.makedirs(self.outside)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_symlink_outside_root_is_not_read(self):
        secret = os.path.join(self.outside, "secret.xml")
        self._write(secret, "<secret>AKIAABCDEFGHIJKLMNOP</secret>")
        self._write(os.path.join(self.root, "ok.xml"), "<ok/>")
        try:
            os.symlink(secret, os.path.join(self.root, "link.xml"))
            os.symlink(self.outside, os.path.join(self.root, "linkdir"))
        except (OSError, NotImplementedError):
            self.skipTest("can't create symlinks here")
        files = safety.walk(self.root)
        self.assertIn("ok.xml", files)
        self.assertNotIn("link.xml", files)
        self.assertFalse(any(f.startswith("linkdir/") for f in files))
        self.assertIsNone(safety.read_text(self.root, "link.xml"))
        self.assertIsNone(safety.read_text(self.root, "../outside/secret.xml"))
        self.assertIsNone(safety.read_bytes(self.root, "link.xml"))

    def test_xml_with_entities_is_refused(self):
        bomb = ('<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol">'
                '<!ENTITY lol2 "&lol;&lol;&lol;">]>\n<manifest>&lol2;</manifest>')
        self.assertTrue(safety.reject_xml_entities(bomb))
        self.assertIsNone(xmlsafe.parse(bomb))
        late = "<a>" + " " * 5000 + '<!ENTITY x SYSTEM "file:///etc/passwd"></a>'
        self.assertIsNone(xmlsafe.parse(late))
        self.assertIsNotNone(xmlsafe.parse("<manifest><application/></manifest>"))

    def test_large_file_is_skipped(self):
        big = os.path.join(self.root, "big.xml")
        with open(big, "wb") as fh:
            fh.write(b"<a>" + b"x" * (safety.MAX_FILE_BYTES + 10) + b"</a>")
        self._write(os.path.join(self.root, "small.xml"), "<a/>")
        files = safety.walk(self.root)
        self.assertNotIn("big.xml", files)
        self.assertIn("small.xml", files)
        self.assertIsNone(safety.read_text(self.root, "big.xml"))

    def test_skip_dirs_and_binary(self):
        self._write(os.path.join(self.root, "build", "gen.xml"), "<a/>")
        with open(os.path.join(self.root, "bin.json"), "wb") as fh:
            fh.write(b"{\x00\x01}")
        self.assertNotIn("build/gen.xml", safety.walk(self.root))
        self.assertIsNone(safety.read_text(self.root, "bin.json"))

    def test_mask_hides_aws_keys(self):
        line = 'val key = "AKIAIOSFODNN7EXAMPLE" // AWS'
        masked = safety.mask(line)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", masked)
        self.assertNotIn("IOSFODNN7EXAMPLE", masked)
        self.assertIn("[masked]", masked)
        self.assertNotIn("ghp_" + "a" * 36, safety.mask("token=ghp_" + "a" * 36))
        self.assertLessEqual(len(safety.mask("x" * 1000 + " y")), 160)


if __name__ == "__main__":
    unittest.main()
