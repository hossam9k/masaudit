# SPDX-License-Identifier: Apache-2.0
"""Fuzz every parser that reads untrusted repository files.

masaudit scans code it doesn't trust, so each parser must return a value or None for any input,
quickly. An exception or a slow input is a bug.

With atheris (Linux, CPython 3.12+), seeded with the test fixtures:
    python fuzz/fuzz_parsers.py -max_total_time=300 -timeout=5 tests/fixtures
Without it, a stdlib mutation run that works anywhere:
    python fuzz/fuzz_parsers.py --smoke 20000
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from masaudit import lexer, safety, suppress  # noqa: E402
from masaudit.detectors import ios, reactnative, rn_platform, rn_storage  # noqa: E402
from masaudit.parsers import (  # noqa: E402
    gradle, manifest, pbxproj, plist, proguard, workflows, xcconfig, xcscheme, xmlsafe,
)

LANGS = sorted(set(lexer.LANG_BY_SUFFIX.values()))


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


def smoke(runs: int, seed: int = 0, quiet: bool = False) -> int:
    """Mutate the test fixtures `runs` times. Returns 1 on the first failing input."""
    rng = random.Random(seed)
    pool = list(_seeds(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")))
    for n in range(runs):
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
