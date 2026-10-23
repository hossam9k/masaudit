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
from masaudit.parsers import gradle, manifest, pbxproj, plist, workflows, xcconfig, xmlsafe  # noqa: E402

LANGS = sorted(set(lexer.LANG_BY_SUFFIX.values()))


def check(data: bytes) -> None:
    """Run one input through every parser. Raises only if a parser has a bug."""
    plist.loads(data)
    text = data.decode("utf-8", "replace")
    xmlsafe.parse(text)
    manifest.parse(text)
    pbxproj.parse(text)
    xcconfig.parse(text)
    workflows.parse_workflow(text)
    gradle.toml_versions(text)
    for lang in LANGS:
        code = lexer.strip(text, lang)
        blank = lexer.strip(text, lang, keep_strings=False)
        if len(code) != len(text) or len(blank) != len(text):
            raise AssertionError(f"lexer changed the length of the text for {lang}")
    gradle.blocks(lexer.strip(text, "kotlin"), lexer.strip(text, "kotlin", keep_strings=False))
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


def smoke(runs: int, seed: int = 0) -> int:
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
