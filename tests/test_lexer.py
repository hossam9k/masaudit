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

    def test_dart_strings_and_nested_comments(self):
        code = ("/* a /* b */ print(token) */\nvar p = r'C:\\'; var q = \'\'\'\nmd5 // x\n\'\'\';\n"
                "var u = 'http://acme.com'; // gone\n")
        kept = lexer.strip(code, "dart")
        self.assertTrue(same_shape(code, kept))
        self.assertNotIn("print(token)", kept)
        self.assertIn("r'C:\\'", kept)
        self.assertIn("md5 // x", kept)
        self.assertIn("'http://acme.com'", kept)
        self.assertNotIn("gone", kept)
        blanked = lexer.strip(code, "dart", keep_strings=False)
        self.assertTrue(same_shape(code, blanked))
        self.assertNotIn("md5", blanked)
        self.assertNotIn("acme", blanked)
        self.assertIn("var u =", blanked)

    def test_line_numbers_preserved(self):
        code = "a\n/* x\ny\nz */\nb // c\n\"\"\"q\nr\"\"\"\nd\n"
        for lang in ("kotlin", "java", "swift", "js", "dart"):
            for keep in (True, False):
                with self.subTest(lang=lang, keep=keep):
                    out = lexer.strip(code, lang, keep)
                    self.assertTrue(same_shape(code, out))
                    self.assertEqual(out.splitlines()[-1], "d")


class JavaScript(unittest.TestCase):
    """Template literals, regex literals, and JSX text in .js/.ts/.tsx."""

    def test_template_literal_keeps_url_and_code_after_it(self):
        code = "const u = `http://${host}/x`; send(token)\n"
        kept = lexer.strip(code, "js")
        self.assertEqual(kept, code)                          # `//` inside a template isn't a comment
        blanked = lexer.strip(code, "js", keep_strings=False)
        self.assertTrue(same_shape(code, blanked))
        self.assertNotIn("http", blanked)
        self.assertIn("${host}", blanked)                     # the expression stays code
        self.assertIn("send(token)", blanked)

    def test_nested_templates_and_braces(self):
        code = "t = `a ${ b ? `in ${c}` : {x: 1}.x } z` + 'q'\nnext()"
        blanked = lexer.strip(code, "js", keep_strings=False)
        self.assertIn("${ b ? `   ${c}` : {x: 1}.x }", blanked)
        self.assertIn("next()", blanked)

    def test_regex_literal_vs_division(self):
        code = 'r = /"/; k = "secret"; y = a / b / c; return /x[/]y/g.test(s) // note\n'
        blanked = lexer.strip(code, "js", keep_strings=False)
        self.assertTrue(same_shape(code, blanked))
        self.assertNotIn("secret", blanked)                   # the quote in /"/ opened no string
        self.assertIn("y = a / b / c;", blanked)
        self.assertIn("/g.test(s)", blanked)
        self.assertNotIn("note", blanked)

    def test_apostrophe_in_jsx_text_is_not_a_string(self):
        code = "<Text>Don't share</Text>\nsend(token)\n"
        self.assertEqual(lexer.strip(code, "js", keep_strings=False), code)

    def test_typescript_and_jsx_suffixes(self):
        for suffix in (".ts", ".tsx", ".jsx", ".mjs", ".cjs"):
            self.assertEqual(lexer.LANG_BY_SUFFIX[suffix], "js")

    def test_crafted_input_is_fast(self):
        import time
        for crafted in ("(/[" * 300_000, "`${" * 300_000, "'a" * 450_000, "`" + "\\" * 900_000):
            start = time.monotonic()
            lexer.strip(crafted, "js", keep_strings=False)
            self.assertLess(time.monotonic() - start, 3.0, crafted[:6])


class SameAsReference(unittest.TestCase):
    """The fast lexer must give exactly what the original character-by-character one gave."""

    EDGE_CASES = [
        "/* a /* b */ c */ x",           # nested comment (Kotlin, Swift) vs flat (Java)
        "/*/ y */ z",                    # opener that overlaps a closer
        '"a\\',                          # backslash at the very end
        "'\\\n' x",                      # escaped newline inside a quote
        "r'''x''' r\"y\" r'z",           # Dart raw strings, one unterminated
        '#"a"# ##"b"## #"""c"""#',       # Swift raw strings
        "#!/usr/bin/env x\n# comment",   # Groovy line comments
        '"""unterminated',               # triple quote to end of file
        "u = `http://${host}/x`; f()",   # JS template literal holding `//`
        "t = `a ${ b ? `in ${c}` : {x: 1}.x } z`",  # nested templates and braces in ${...}
        "s = `open ${ x",                # template expression never closed
        'r = /"/; k = "secret"',         # regex literal holding a quote
        "return /a[/]b/g.exec(s) // c",  # slash inside a class, then a comment
        "x = a / b / c",                 # division, not a regex
        "<Text>Don't // x</Text>\nf()",  # apostrophe in JSX text
        "s = `esc \\` ${y} z`",        # escaped backtick
        "(/[" * 50,                      # unclosed regex classes
    ]

    def test_fixtures_mutations_and_edge_cases(self):
        import os
        import random
        import sys

        import reference_lexer
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "fuzz"))
        import fuzz_parsers

        langs = sorted(set(lexer.LANG_BY_SUFFIX.values()))
        pool = list(fuzz_parsers._seeds(os.path.join(os.path.dirname(__file__), "fixtures")))
        rng = random.Random(3)
        cases = [p.decode("utf-8", "replace") for p in pool] + self.EDGE_CASES
        cases += [fuzz_parsers._mutate(rng, rng.choice(pool), pool).decode("utf-8", "replace") for _ in range(300)]
        for text in cases:
            for lang in langs:
                for keep in (True, False):
                    self.assertEqual(lexer.strip(text, lang, keep), reference_lexer.strip(text, lang, keep),
                                     f"{lang} keep_strings={keep}: {text[:60]!r}")


if __name__ == "__main__":
    unittest.main()
