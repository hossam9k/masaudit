# masaudit

**A free mobile security scanner that scales its advice to your app's risk.**
Point it at an Android, iOS, or Kotlin Multiplatform project. It finds the weaknesses that matter
*for your kind of app*, explains each one in plain words, and tells you what you **don't** need.

A news app should never be told to pin certificates. A banking app should. Most scanners give
both the same list.

[![ci](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hossam9k/masaudit/badge)](https://scorecard.dev/viewer/?uri=github.com/hossam9k/masaudit)
[![PyPI](https://img.shields.io/pypi/v/masaudit)](https://pypi.org/project/masaudit/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md)

---

## Three ways in

| **Scan, no AI needed** | **Fix it with an AI assistant** | **Learn why** |
|---|---|---|
| `pipx run masaudit .` | Claude Code: `/plugin marketplace add hossam9k/masaudit` | Every rule links to the free book |
| Offline, Python 3.9+, zero dependencies. Writes `SECURITY-AUDIT.md`. | Audits, triages, fixes one finding at a time, reviews PRs. Works in any [Agent Skills](#use-it-with-an-ai-assistant) tool. | [*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security) |

## See it on a real report

The repository ships a deliberately insecure demo app, *Acme Wallet*. Here's the same code
scanned under two profiles:

| | As a **banking** app | As a **news** app |
|---|---|---|
| Fix before release | 13 | 10 |
| Fix soon | 13 | 10 |
| Not needed for your app | 0 | 6: pinning, Keychain hardening, biometric key binding, … each with the reason |
| Full report | [sample-report-banking.md](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-banking.md) | [sample-report-news.md](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-news.md) |

Each finding says **why it matters**, **how to fix it** (with paste-ready code), **how to verify the
fix**, how long it takes, its OWASP MASWE/MASVS IDs, and the book section that explains it.

## Scan without AI

```bash
pipx run masaudit .            # or: uvx masaudit .   or: pip install masaudit
```

No pip? Download `masaudit.pyz` from the [latest release](https://github.com/hossam9k/masaudit/releases/latest)
and run `python3 masaudit.pyz .`. It's one file, works offline, and needs nothing else.

The first run asks one question, **"What kind of app is this?"**, and offers to save your answer
in `.masaudit.ini`. In CI, or without an answer, it assumes a general app and says so.

```bash
masaudit . --app-type banking                  # banking, fintech, health, ecommerce-cards, ecommerce,
                                               # marketplace, social, content (or news), enterprise, game
masaudit . --format sarif --output masaudit.sarif
masaudit . --fail-on high                      # exit 1 on high or critical findings
masaudit --explain AND-004                     # what a rule checks and how to fix it, offline
masaudit . --fix-safe                          # preview vetted safe fixes as a diff; changes nothing
```

### In CI

```yaml
permissions:
  contents: read
  security-events: write          # to show results in GitHub code scanning
steps:
  - uses: actions/checkout@<commit-sha>  # pin every action to a full commit SHA
    with:
      persist-credentials: false
  - uses: hossam9k/masaudit@<commit-sha> # v0.1.1
    with:
      app-type: banking
      fail-on: high
```

The Action runs from its own pinned source: no download, no network. Results appear in the
Security tab. A [pre-commit hook](https://github.com/hossam9k/masaudit/blob/main/.pre-commit-hooks.yaml) is available too.

### Team features

- **Suppress with a reason:** `// masaudit:ignore AND-015 internal activity, reachable only via signature permission`
  on the line or the line above. A suppression without a reason is ignored and reported.
- **Baselines for older apps:** `masaudit . --update-baseline`, then `--baseline .masaudit-baseline.json`
  fails CI only on *new* findings.
- **Bring your other tools:** `--import-sarif lint.sarif mobsfscan.sarif` calibrates Android Lint,
  mobsfscan, Semgrep, and zizmor results by the same profile.

## Use it with an AI assistant

**Claude Code**

```text
/plugin marketplace add hossam9k/masaudit
/plugin install masaudit@masaudit
```

Then `/masaudit:scan`, `/masaudit:fix`, `/masaudit:review`, or `/masaudit:explain AND-004`, or just
ask: *"Is my app ready for a pentest?"*

**Other tools** (Codex, GitHub Copilot, Cursor, Gemini CLI, and other tools that read
[Agent Skills](https://agentskills.io)): copy [`plugin/skills/masaudit/`](https://github.com/hossam9k/masaudit/tree/main/plugin/skills/masaudit) into
your tool's skills folder. The skill bundles the scanner, so it works offline.

**Any chat assistant:** the end of every `SECURITY-AUDIT.md` has a *Fix plan for your AI assistant*.
Paste it in.

The assistant confirms each finding in context, looks for what a scanner can't see (server-side
trust, biometric flows, token handling), and fixes one finding at a time. It asks before any
behavior-changing fix and never commits.

## What it checks

75 rules: 33 Android, 21 iOS, 10 cross-platform code, 8 CI and supply chain, 3 Kotlin Multiplatform.
See [docs/rules.md](https://github.com/hossam9k/masaudit/blob/main/docs/rules.md).

- **Network:** cleartext, ATS exceptions, user CAs, TLS bypasses, weak TLS, pinning (only where the profile needs it).
- **Storage:** Keychain classes, file protection, deprecated `EncryptedSharedPreferences`, Tink's silent cleartext fallback, backups, end-of-life SQLCipher.
- **Platform:** exported components, intent redirection, PendingIntent, deep links, FileProvider, WebView TLS, file access, JavaScript bridges, debugging.
- **Auth:** biometric prompts not bound to a key, keys that survive new enrollments, tokens in UserDefaults.
- **Code:** hardcoded secrets (masked in every output), ECB, fixed IVs, weak hashes and randomness, logged tokens.
- **Build and CI:** debuggable releases, R8 off, target SDK, unpinned actions, `pull_request_target`, script injection, committed signing keys.

## How it compares

| | masaudit | MobSF | mobsfscan | Android Lint |
|---|---|---|---|---|
| Advice scaled to the app's risk | **Yes** | No | No | No |
| "Not needed for your app", with reasons | **Yes** | No | No | No |
| Plain-language why, fix, and verify per finding | **Yes** | Partly | Partly | Partly |
| Android + iOS + KMP + GitHub Actions | **Yes** | Android, iOS (binaries) | Android, iOS (source) | Android |
| Install | Single file, no dependencies | Docker | pip (Semgrep) | Android SDK |
| Imports the others' SARIF and calibrates it | **Yes** | — | — | — |

MobSF analyzes built binaries and does dynamic testing, which masaudit doesn't. Use both.

## What it can't do

masaudit reads your source and configuration. It can't see your server, runtime behavior, or
business logic, which is where many real breaches happen. Every report ends with a *Residual risk*
section that says so, and lists anything the scanner couldn't decide. Rules marked *Check by hand*
need a human or an AI assistant to confirm.

## Safe to run on any code

masaudit never executes project code, never follows symlinks out of the scan root, refuses XML
entity tricks, makes **no network calls** (a test enforces it), and masks secrets in every output.
No telemetry. See [SECURITY.md](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md).

## Contributing

False-positive reports are the most valuable contribution: a rule that cries wolf gets ignored.
Adding a rule takes about 30 minutes: see [CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md).

## About

Built by **Hossam Atef**, a mobile engineer (Android, iOS, Kotlin Multiplatform), as the practical
companion to his free book,
[*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security).
Every rule traces to a section of the book, and the book records how each claim was verified.

masaudit is not an OWASP project; OWASP doesn't certify apps or endorse tools.
Licensing: code Apache-2.0, fix snippets MIT-0, explanations CC BY-SA 4.0. See [LICENSING.md](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md).

masaudit is free. If it saved you an audit, you can [sponsor it](https://github.com/sponsors/hossam9k).
