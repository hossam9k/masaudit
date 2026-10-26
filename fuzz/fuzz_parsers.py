# SPDX-License-Identifier: Apache-2.0
"""Fuzz every parser that reads untrusted repository files.

masaudit scans code it doesn't trust, so each parser must return a value or None for any input,
quickly. An exception or a slow input is a bug.

With atheris (Linux, CPython 3.12+), seeded with the test fixtures and fuzz/seeds (a SARIF file):
    python fuzz/fuzz_parsers.py -max_total_time=300 -timeout=5 tests/fixtures fuzz/seeds
Without it, a stdlib mutation run that works anywhere:
    python fuzz/fuzz_parsers.py --smoke 20000
"""

import json
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from masaudit import engine, importers, lexer, safety, suppress  # noqa: E402
from masaudit.detectors import flutter, ios, kmp, reactnative, rn_platform, rn_storage  # noqa: E402
from masaudit.model import Project  # noqa: E402
from masaudit.parsers import (  # noqa: E402
    gradle, manifest, pbxproj, plist, proguard, workflows, xcconfig, xcscheme, xmlsafe,
)

LANGS = sorted(set(lexer.LANG_BY_SUFFIX.values()))
RULES = engine.load_rules()
_TMP = tempfile.mkdtemp(prefix="masaudit-fuzz-")
# Flutter and KMP detectors read files from a project on disk: one Dart file and one shared Kotlin file.
_DART, _KOTLIN = "lib/a.dart", "shared/src/commonMain/kotlin/a/A.kt"
_PROJECT_FILES = {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n",
                  "settings.gradle.kts": 'include(":shared")\n',
                  "shared/build.gradle.kts": 'plugins { kotlin("multiplatform") }\n'}
_DETECTORS = [getattr(mod, name) for mod, names in (
    (flutter, ("trust_all", "prefs_token", "dio_logger", "webview_file_access", "webview_trust_all",
               "webview_debugging", "biometric_boolean", "obfuscation")),
    (kmp, ("mechanism_expect", "native_in_common", "ktor_pinning", "ktor_logging", "darwin_trust_all",
           "settings_token"))) for name in names]


def _write(rel: str, text: str) -> None:
    path = os.path.join(_TMP, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(text)


for _rel, _text in _PROJECT_FILES.items():
    _write(_rel, _text)


def check_project(text: str) -> None:
    """Flutter and KMP detectors, the SARIF importer, and xcconfig includes on one input."""
    _write(_DART, text)
    _write(_KOTLIN, text)
    files = sorted(_PROJECT_FILES) + [_DART, _KOTLIN]
    ctx = engine.Context(Project(root=_TMP, platforms=["flutter", "kmp", "android", "ios"], files=files))
    for detect in _DETECTORS:
        list(detect(ctx, None))
    # Every include of every file resolves to this same text: cycles and fan-out on any input.
    xcconfig.resolve(_TMP, "a.xcconfig", read=lambda _root, _rel: text, unknowns=[])
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        _write("in.sarif", text)
        try:
            importers.import_sarif(os.path.join(_TMP, "in.sarif"), _TMP, RULES)
        except importers.SarifImportError:
            pass


def check(data: bytes) -> None:
    """Run one input through every parser. Raises only if a parser has a bug."""
    plist.loads(data)
    text = data.decode("utf-8", "replace")
    root = xmlsafe.parse(text)
    if root is not None:
        for el in list(root.iter())[:200]:
            xmlsafe.ack_text(el, "AcceptsUserCertificates", "ExportedService")
    manifest.parse(text)
    pbxproj.parse(text)
    xcconfig.parse(text)
    xcscheme.parse(text)
    if len(ios._blank_debug(text)) != len(text):
        raise AssertionError("#if blanking changed the length of the text")
    for line in text.splitlines()[:20]:
        ios._eval_cond(line[:300], ios.CondEnv(known={"A", "DEBUG"}, defined={"B": "1"}))
    workflows.parse_workflow(text)
    workflows.parse_action(text)
    workflows.unpinned_uses_policies(text)
    workflows.github_origin(text)
    gradle.toml_versions(text)
    gradle.toml_libraries(text)
    proguard.parse(text)
    for lang in LANGS:
        code = lexer.strip(text, lang)
        blank = lexer.strip(text, lang, keep_strings=False)
        if len(code) != len(text) or len(blank) != len(text):
            raise AssertionError(f"lexer changed the length of the text for {lang}")
    kt_code, kt_blank = lexer.strip(text, "kotlin"), lexer.strip(text, "kotlin", keep_strings=False)
    gradle.blocks(kt_code, kt_blank)
    gradle.build_types(kt_code, kt_blank)
    gradle.product_flavors(kt_code, kt_blank)
    gradle.dependencies(kt_code)
    # React Native: imports, JSX tags and their props, call arguments, function heads, __DEV__ guards, JSON.
    js_code, js_blank = lexer.strip(text, "js"), lexer.strip(text, "js", keep_strings=False)
    reactnative._parse_imports(js_code)
    for k, el in enumerate(reactnative.jsx_elements(js_code, js_blank, ["WebView", "View", "Web.View"])):
        for p in el.props.values():
            reactnative.literal(p.text(js_code))
        if k >= 50:
            break
    opens = [i for i, ch in enumerate(js_blank[:20_000]) if ch == "("][:50]
    for i in opens:
        reactnative.call_args(js_blank, i)
        rn_platform._parse_fn(js_blank, i, i + 2000)
    reactnative.DevGuard(js_code, js_blank)
    rn_storage._load_json(text)
    safety.mask(text)
    safety.reject_xml_entities(text)
    for line in text.splitlines()[:50]:
        suppress.parse_line(line)
    check_project(text)


def _seeds(root: str):
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            with open(os.path.join(dirpath, name), "rb") as fh:
                yield fh.read()


def _mutate(rng: random.Random, data: bytes, pool) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.randrange(5)
        i = rng.randrange(len(b) + 1)
        if op == 0 and b:
            del b[i:i + rng.randint(1, 16)]
        elif op == 1:
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif op == 2:
            b[i:i] = rng.choice((b"{", b"}", b"(", b"\"", b"'", b"/*", b"*/", b"//", b"<", b">", b"<!",
                                 b"\n", b"\r", b"\\", b"${", b"=", b":", b"- ", b"  ", b"\xef\xbb\xbf",
                                 b'"""', b"#", b";", b"@", b"&", b"\x00"))
        elif op == 3 and pool:
            other = rng.choice(pool)
            j = rng.randrange(len(other) + 1)
            b[i:i] = other[j:j + rng.randint(1, 256)]
        elif b:
            k = rng.randrange(len(b))
            b[i:i] = b[k:k + rng.randint(1, 64)] * rng.randint(1, 50)
    return bytes(b[:200_000])


_ODD_VALUES = (None, 0, -1, 10 ** 30, 1.5, True, "", "x" * 300, "file:///", "../a", "/abs", "C:/x", "%SRCROOT%",
               "\ud800", [], {}, [{}], {"uri": 5})


def _mutate_json(rng: random.Random, node):
    """The same document with a few values swapped for wrong types and odd strings: still valid JSON, so
    the SARIF importer's handling of each field is reached (byte mutations rarely leave JSON parseable)."""
    if rng.random() < 0.08:
        return rng.choice(_ODD_VALUES)
    if isinstance(node, dict):
        return {k: _mutate_json(rng, v) for k, v in node.items()}
    if isinstance(node, list):
        return [_mutate_json(rng, v) for v in node] * rng.choice((1, 1, 1, 3))
    return node


def smoke(runs: int, seed: int = 0, quiet: bool = False) -> int:
    """Mutate the test fixtures `runs` times. Returns 1 on the first failing input."""
    rng = random.Random(seed)
    here = os.path.dirname(os.path.abspath(__file__))
    pool = list(_seeds(os.path.join(here, "..", "tests", "fixtures"))) + list(_seeds(os.path.join(here, "seeds")))
    with open(os.path.join(here, "seeds", "sample.sarif"), encoding="utf-8") as fh:
        sarif = json.load(fh)
    for n in range(runs):
        if n % 10 == 0:
            data = json.dumps(_mutate_json(rng, sarif)).encode("utf-8", "surrogatepass")
        else:
            data = _mutate(rng, rng.choice(pool), pool)
        start = time.monotonic()
        try:
            check(data)
        except Exception:  # noqa: BLE001
            path = f"fuzz-crash-{n}.bin"
            with open(path, "wb") as fh:
                fh.write(data)
            print(f"Crash on input {n}, saved to {path}", file=sys.stderr)
            raise
        if time.monotonic() - start > 2:
            print(f"Slow input {n} ({len(data)} bytes)", file=sys.stderr)
            return 1
    if not quiet:
        print(f"{runs} inputs, no crashes")
    return 0


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--smoke":
        sys.exit(smoke(int(sys.argv[2]) if len(sys.argv) > 2 else 20000))
    import atheris  # Linux only; see fuzz/requirements.txt

    atheris.instrument_all()
    atheris.Setup(sys.argv, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
