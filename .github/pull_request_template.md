<!-- Thanks for the contribution. CONTRIBUTING.md has the full checklist. -->

## What this changes

## Checks

- [ ] `cd tests && python3 -m unittest -q` passes
- [ ] A new or changed rule has a `vulnerable` and a near-miss `clean` fixture, with counts in `expected.json`
- [ ] Fixtures use `{{FAKE_*}}` placeholders, never real-looking secrets
- [ ] `python3 scripts/generate.py` was run and its output committed (rule docs, sample reports, the plugin's pyz)
- [ ] `uvx ruff@0.17.1 check src tests fuzz scripts` passes
- [ ] A detector change was checked on a real app, or the PR says why it wasn't
- [ ] CHANGELOG.md has a line for anything a user would notice
