# SPDX-License-Identifier: Apache-2.0
"""Findings in a function nothing calls get the scope `unused` (masaudit.unused)."""

import os
import shutil
import tempfile
import unittest

from helpers import ALL_PLATFORMS  # noqa: F401  (sets sys.path)
from masaudit import engine, profile, safety
from masaudit.detectors import cross
from masaudit.model import Project

APP = "app/build.gradle.kts"
LIB = "lib/build.gradle.kts"
KT = "app/src/main/java/a/Crypto.kt"
# Feeder's AesCbcWithIntegrity: a password-based key derivation nothing in the app calls.
CRYPTO = """package a

import javax.crypto.spec.PBEKeySpec

object Crypto {
    private const val ITERATIONS = 10000

    @Throws(GeneralSecurityException::class)
    fun keyFromPassword(password: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).encoded
    }

    @Throws(GeneralSecurityException::class)
    fun keyFromPassword(
        password: String,
        salt: String,
    ): ByteArray = keyFromPassword(password, Base64.decode(salt, 0))

    @Throws(GeneralSecurityException::class)
    fun encrypt(data: ByteArray): ByteArray = data
}
"""


class UnusedCode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._write(APP, 'plugins { id("com.android.application") }\nandroid { namespace = "a" }\n')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _scan(self, rule_id):
        project = Project(root=self.tmp, platforms=["android"], files=safety.walk(self.tmp))
        rules = [r for r in engine.load_rules() if r.id == rule_id]
        return engine.calibrate(engine.run(project, rules), profile.make("banking", "flag"))

    def _scopes(self, rule_id):
        return sorted((f.location.path, f.location.line, f.scope) for f in self._scan(rule_id))

    def test_feeder_key_derivation_nothing_calls(self):
        self._write(KT, CRYPTO)
        found = self._scan("XPL-015")
        # One finding, at the overload that passes the salt on (not at the `@Throws` lines), lowered to Notes.
        self.assertEqual([(f.location.line, f.scope, f.bucket) for f in found], [(18, "unused", "notes")])
        self.assertIn("nothing in the project calls", found[0].bucket_reason)

    def test_a_call_anywhere_keeps_it(self):
        callers = {
            "app/src/main/java/a/Login.kt": "class Login { fun go() = Crypto.keyFromPassword(\"p\", \"s\") }\n",
            "app/src/main/java/a/Login.java": "class Login { void go() { Crypto.INSTANCE.keyFromPassword(p, s); } }\n",
            "app/src/main/java/a/Reflect.kt": 'class R { val m = Crypto::class.java.getMethod("keyFromPassword") }\n',
            "app/src/main/res/layout/a.xml": '<Button android:onClick="keyFromPassword"/>\n',
            "app/proguard-rules.pro": "-keep class a.Crypto { *** keyFromPassword(...); }\n",
            "app/src/main/cpp/bridge.cpp": 'env->GetStaticMethodID(cls, "keyFromPassword", "()V");\n',
            "shared/src/iosMain/kotlin/A.swift": "let k = Crypto.shared.keyFromPassword(password: p, salt: s)\n",
        }
        for rel, text in callers.items():
            with self.subTest(caller=rel):
                self._write(KT, CRYPTO)
                self._write(rel, text)
                self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})
                os.remove(os.path.join(self.tmp, rel))

    def test_comments_and_its_own_body_are_not_calls(self):
        self._write(KT, CRYPTO)
        self._write("app/src/main/java/a/Notes.kt", "// call keyFromPassword() some day\n/** [Crypto.keyFromPassword] */\n"
                                                   "class Notes\n")
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"unused"})

    def test_entry_points_are_never_judged(self):
        cases = {
            "override": "class W : X() { override fun derive(p: String, s: ByteArray) = PBEKeySpec(p.toCharArray(), s, 1000, 256) }\n",
            "annotation": "class W { @JavascriptInterface fun derive(p: String, s: ByteArray) = PBEKeySpec(p.toCharArray(), s, 1000, 256) }\n",
            "main": "fun main(p: String, s: ByteArray) { PBEKeySpec(p.toCharArray(), s, 1000, 256) }\n",
        }
        for what, text in cases.items():
            with self.subTest(what=what):
                self._write(KT, text)
                self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})

    def test_code_inside_a_function_nothing_calls_even_in_an_override(self):
        self._write(KT, "class Help { fun open(w: WebView) {\n    w.webViewClient = object : WebViewClient() {\n"
                        "        override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) {\n"
                        "            h.proceed()\n        }\n    }\n} }\n")
        self.assertEqual({f.scope for f in self._scan("AND-004")}, {"unused"})
        self._write("app/src/main/java/a/Main.kt", "class Main { fun start(w: WebView) = Help().open(w) }\n")
        self.assertEqual({f.scope for f in self._scan("AND-004")}, {"main"})

    def test_a_library_public_function_may_be_called_from_outside(self):
        self._write(LIB, 'plugins { id("com.android.library") }\n')
        self._write("settings.gradle.kts", 'include(":app", ":lib")\n')
        self._write(APP, 'plugins { id("com.android.application") }\ndependencies { implementation(project(":lib")) }\n')
        text = CRYPTO.replace("fun keyFromPassword(password: String, salt: ByteArray)",
                              "private fun derive(password: String, salt: ByteArray)")
        self._write("lib/src/main/java/a/Crypto.kt", CRYPTO)
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})
        self._write("lib/src/main/java/a/Crypto.kt", text.replace("= keyFromPassword(password", "= derive(password"))
        # The private one is called by the public overload, which a library user may call: kept.
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})
        self._write("lib/src/main/java/a/Crypto.kt", text)
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"unused"})

    def test_java_private_and_static_methods(self):
        java = ("class C {\n    {} private static byte[] derive(String p, byte[] s) throws Exception {\n"
                "        return f.generateSecret(new PBEKeySpec(p.toCharArray(), s, 1000, 256)).getEncoded();\n    }\n}\n")
        self._write("app/src/main/java/a/C.java", java)
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"unused"})
        # A public instance method may be a callback the framework calls (a Java override needs no @Override).
        self._write("app/src/main/java/a/C.java", java.replace("private static", "public"))
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})

    def test_expression_bodies(self):
        self._write(KT, "class K {\n    fun deriveKey(p: String, s: ByteArray) =\n        PBEKeySpec(p.toCharArray(),\n"
                        "            s, 1000, 256)\n            .also { }\n\n    fun b() = deriveKey(\"p\", ByteArray(1))\n}\n")
        # deriveKey is called by b, which nothing calls. deriveKey is judged by its own name, which b
        # mentions: only a finding inside b would be lowered.
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"main"})
        self._write(KT, "class K {\n    fun deriveKey(p: String, s: ByteArray) =\n        PBEKeySpec(p.toCharArray(),\n"
                        "            s, 1000, 256)\n            .also { }\n}\n")
        self.assertEqual({f.scope for f in self._scan("XPL-015")}, {"unused"})


class FunctionNames(unittest.TestCase):
    def test_annotation_arguments_are_not_the_parameter_list(self):
        self.assertEqual(cross._function_name("\n    @Throws(GeneralSecurityException::class)\n    fun derive(\n"
                                              "        password: String,\n    ): Keys "), "derive")
        self.assertEqual(cross._function_name('@objc(run:) @available(iOS 13, *) func run(_ x: Int) '), "run")
        self.assertEqual(cross._function_name("void run(int x) "), "run")

    def test_declarations_are_not_call_sites(self):
        blank = ("fun derive(p: String): Keys = derive(p, 1)\nfun <T> List<T>.derive(x: Int) {}\n"
                 "Keys derive(String p) throws E { return derive(p, 2); }\n")
        starts = [blank.count("\n", 0, s) + 1 for s, _p, dotted in cross._call_sites(blank)["derive"] if not dotted]
        self.assertEqual(starts, [1, 3])                 # the two calls; not the declarations


if __name__ == "__main__":
    unittest.main()
