# SPDX-License-Identifier: Apache-2.0
"""The lexer blanks comments (and optionally strings) without moving anything."""

import unittest

import helpers  # noqa: F401  (sets sys.path)
from masaudit import lexer


def same_shape(a, b):
    return len(a) == len(b) and [i for i, c in enumerate(a) if c == "\n"] == [i for i, c in enumerate(b) if c == "\n"]


class Lexer(unittest.TestCase):
    def test_nested_kotlin_block_comments(self):
        code = "/* outer /* inner proceed() */ still comment proceed() */\nval x = proceed()\n"
        out = lexer.strip(code, "kotlin")
        self.assertTrue(same_shape(code, out))
        self.assertNotIn("still comment", out)
        self.assertEqual(out.count("proceed()"), 1)
        self.assertIn("val x = proceed()", out)

    def test_java_block_comments_do_not_nest(self):
        code = "/* a /* b */ int x = 1;"
        out = lexer.strip(code, "java")
        self.assertIn("int x = 1;", out)

    def test_line_comment_and_url_in_string(self):
        code = 'val u = "http://example.com" // trailing note\n'
        out = lexer.strip(code, "kotlin")
        self.assertIn('"http://example.com"', out)
        self.assertNotIn("trailing", out)

    def test_swift_raw_strings(self):
        code = 'let a = #"no // comment "here""#\nlet b = 1 // gone\n'
        kept = lexer.strip(code, "swift")
        self.assertIn('#"no // comment "here""#', kept)
        self.assertNotIn("gone", kept)
        blanked = lexer.strip(code, "swift", keep_strings=False)
        self.assertTrue(same_shape(code, blanked))
        self.assertNotIn("comment", blanked)
        self.assertIn("let b = 1", blanked)

    def test_swift_double_hash_raw_string_with_inner_delimiter(self):
        code = 'let s = ##"inner "# still string"##; let t = 2\n'
        out = lexer.strip(code, "swift", keep_strings=False)
        self.assertTrue(same_shape(code, out))
        self.assertNotIn("still", out)
        self.assertIn("let t = 2", out)

    def test_swift_multiline_raw_string(self):
        code = 'let s = #"""\nline // one\n"""#\nlet z = 3\n'
        out = lexer.strip(code, "swift", keep_strings=False)
        self.assertTrue(same_shape(code, out))
        self.assertNotIn("one", out)
        self.assertIn("let z = 3", out)

    def test_line_numbers_preserved(self):
        code = "a\n/* x\ny\nz */\nb // c\n\"\"\"q\nr\"\"\"\nd\n"
        for lang in ("kotlin", "java", "swift", "js"):
            for keep in (True, False):
                with self.subTest(lang=lang, keep=keep):
                    out = lexer.strip(code, lang, keep)
                    self.assertTrue(same_shape(code, out))
                    self.assertEqual(out.splitlines()[-1], "d")


if __name__ == "__main__":
    unittest.main()
