[masaudit documentation](README.md) › Writing a rule

# Writing a rule

A rule is one entry in `src/masaudit/rules/<platform>.json`, plus either a declarative
`pattern` or a Python detector in `src/masaudit/detectors/<platform>.py`, plus a fixture in
`tests/fixtures/<RULE-ID>/`. The tests check the rest automatically.

## 1. The JSON entry

```json
{
  "id": "AND-001",
  "title": "Cleartext (plain HTTP) traffic is allowed",
  "platform": "android",
  "severity": "high",
  "profiles": ["L1"],
  "why": "One or two plain sentences: what an attacker gains.",
  "fix": "One to three lines: what to change.",
  "verify": "How to confirm the fix worked.",
  "effort": "minutes",
  "book": "§7.1",
  "book_url": "https://github.com/hossam9k/mobile-app-security/blob/main/book/03-data-in-transit.md#71-the-baseline",
  "maswe": "MASWE-0026",
  "masvs": "MASVS-NETWORK-1",
  "mastg": ["MASTG-TEST-0235"],
  "app_types": null,
  "not_needed_reason": "",
  "fix_code": {"lang": "xml", "code": "..."},
  "confidence": "high",
  "safe_fix": false,
  "detector": "android_cleartext"
}
```

| Field | Rules |
|---|---|
| `id` | `AND-`, `IOS-`, `RN-` (React Native), `KMP-`, `FLT-` (Flutter), `XPL-` (cross-platform code), or `CI-`, then 3 digits. Never reuse an ID; retire with `"retired": true`. |
| `platform` | `android`, `ios`, `kmp`, `flutter`, `cross`, `ci`. The rule runs only if the project has that platform. |
| `severity` | `critical`, `high`, `medium`, `low`, `info`: the severity for an app whose profile includes this weakness. |
| `profiles` | The MAS profiles the weakness belongs to (book §3.2): `L1` baseline, `L2` high-risk data and untrusted OS, `R` resilience, `P` privacy. If the app's profile shares none of them, the finding goes to "Not needed for your app". |
| `app_types` | Optional allowlist of app types that need this (for example, pinning: `["banking","identity","health","ecommerce-cards"]`, from §8.8). Requires `not_needed_reason`. |
| `why`, `fix`, `verify` | Plain language for someone new to security. Short sentences, no idioms, American spelling, no "simply/just/easy". |
| `book`, `book_url` | A real `§x.y` or `Chapter N` and its URL from `rules/_book_sections.json` (the test checks they match). |
| `maswe`, `masvs` | Only if the book gives one. MASWE v1.0.0 IDs; `masvs` must match the MASWE's control (`rules/_maswe.json`). |
| `mastg` | Optional. MASTG v2 IDs the book cites: tests (`MASTG-TEST-0200` and above), best practices (`MASTG-BEST-*`), and other v2 IDs (`TECH`, `KNOW`, `DEMO`). |
| `fix_code` | Optional paste-ready fix, taken from the book's verified code where possible. Released as MIT-0. |
| `confidence` | `high` (a hit is almost always real), `medium`, or `manual` (a hit needs a human or AI to confirm). Aim for at least 90% precision for `high`. |
| `safe_fix` | Only AND-002 has a safe fix today. Set it to `false` for new rules. |

## 2. Detect it

**Pattern** (code, after comments are blanked):

```json
"pattern": {
  "suffixes": [".kt", ".java"],
  "prefilter": "proceed(",
  "regex": "onReceivedSslError[\\s\\S]{0,400}?\\.proceed\\(\\)",
  "flags": "",
  "strings": "keep",
  "unless_file": "",
  "message": "Plain-language detail for this hit."
}
```

`prefilter` is a literal that must appear in the raw file (fast skip). `strings: "blank"` also blanks
string contents (use it when a match inside a string would be a false positive). `unless_file`
skips files where that regex matches.

**Detector** (structured files or logic), in `src/masaudit/detectors/<platform>.py`:

```python
@detector("android_cleartext")
def cleartext(ctx, rule):
    for path in ctx.files(name="AndroidManifest.xml"):
        root = xmlsafe.parse(ctx.text(path) or "")
        ...
        yield Hit(path, line, ctx.snippet(path, line), "message")
```

`ctx.files(*suffixes, name=None)`, `ctx.text(path)`, `ctx.code(path, keep_strings=True)`,
`ctx.line_of(text, index)`, `ctx.snippet(path, line)` (masked), `ctx.note_unknown(msg)`, and
`ctx.profile` (may be `None`). If the scanner can't decide (a `${placeholder}`, a missing file),
call `ctx.note_unknown(...)` and yield nothing: **never turn "not found" into a finding** unless the
rule is explicitly about absence and the evidence is conclusive.

## 3. The fixture

```text
tests/fixtures/AND-001/
  expected.json        {"vulnerable": 2, "clean": 0}
  vulnerable/...       the smallest files that should trigger the rule
  clean/...            near-misses that must NOT trigger it (the fixed version, the same text in a comment,
                       a debug-only variant, a similar but safe API)
```

## 4. Check

Run the tests, regenerate `docs/rules.md` and the sample reports, and lint, as listed in
[CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md#add-a-rule-in-30-minutes).
CI fails if `python3 scripts/generate.py` changes any file.
