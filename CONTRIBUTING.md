# Contributing

Thanks for helping. The most useful contributions, in order:

1. **False-positive reports.** Use the [false-positive form](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).
   A rule that cries wolf gets ignored, so precision matters more than coverage.
2. **New rules.** Each rule is a JSON entry, a detector or pattern, and a fixture. It takes about 30 minutes.
3. **Better wording.** Every message is read by people new to security. Clearer is better.

## Add a rule in 30 minutes

Read [docs/writing-rules.md](docs/writing-rules.md), then:

1. Add an entry to `src/masaudit/rules/<platform>.json` with the next free ID for that platform.
2. Add a `pattern`, or a detector in `src/masaudit/detectors/<platform>.py`.
3. Add `tests/fixtures/<RULE-ID>/vulnerable/`, `clean/` (near-misses that must not fire), and `expected.json`.
4. Run the tests and regenerate the derived files:

```bash
cd tests && python3 -m unittest -q && cd ..
python3 scripts/generate.py
uvx ruff@0.17.1 check src tests fuzz scripts   # the linter CI runs
```

The tests check that the book link resolves, the MASWE ID exists and matches its MASVS control,
the text has no filler words, and the rule fires only where it should.

## Ground rules

- Every bug fix and every new feature comes with a test that fails without it. CI runs the tests
  on Linux, macOS, and Windows with Python 3.9 to 3.13, plus a fuzzer and CodeQL.
- Python 3.9+, standard library only. No runtime dependencies.
- masaudit never executes project code, never follows symlinks out of the scan root, and never
  makes network calls. Changes that break this won't be merged.
- Every rule cites the book section that teaches it. If the book doesn't cover it yet, open an
  issue on [the book](https://github.com/hossam9k/mobile-app-security) first.
- Rule IDs are never reused. Retire a rule with `"retired": true`.
- Code is Apache-2.0; `fix_code` snippets are MIT-0. By contributing, you license your work the same way.
