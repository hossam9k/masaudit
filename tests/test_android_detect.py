# SPDX-License-Identifier: Apache-2.0
"""Android is detected from the imports of a source folder that has no manifest or Gradle file."""

import os
import shutil
import tempfile
import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import detect, safety


class AndroidFromImports(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _platforms(self, with_root=True):
        files = safety.walk(self.root)
        return detect.platforms(files, self.root if with_root else None)

    def test_kotlin_file_importing_android(self):
        self._write("src/com/acme/Login.kt", "package com.acme\n\nimport android.os.Bundle\n\nclass Login\n")
        self.assertIn("android", self._platforms())
        self.assertNotIn("android", self._platforms(with_root=False))

    def test_java_file_importing_androidx(self):
        self._write("Main.java", "package a;\n\nimport androidx.webkit.WebViewCompat;\n\nclass Main {}\n")
        self.assertIn("android", self._platforms())

    def test_plain_jvm_code_is_not_android(self):
        self._write("src/main/kotlin/Server.kt", "package srv\n\nimport java.net.ServerSocket\n// import android.os\n"
                                                 "val note = \"import android.os.Bundle\"\n")
        self.assertNotIn("android", self._platforms())

    def test_android_import_only_in_tests_is_not_enough(self):
        self._write("src/test/kotlin/LoginTest.kt", "import android.content.Context\n")
        self._write("src/main/kotlin/Login.kt", "import kotlinx.coroutines.flow.Flow\n")
        self.assertNotIn("android", self._platforms())


if __name__ == "__main__":
    unittest.main()
