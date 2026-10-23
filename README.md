# masaudit

**A free mobile security scanner that scales its advice to your app's risk.**
Point it at an Android, iOS, Kotlin Multiplatform, or Flutter project. It finds the weaknesses that matter
*for your kind of app*, explains each one in plain words, and tells you what you **don't** need.

A news app should never be told to pin certificates. A banking app should. Most scanners give
both the same list.

[![ci](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hossam9k/masaudit/badge)](https://scorecard.dev/viewer/?uri=github.com/hossam9k/masaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15835/badge)](https://www.bestpractices.dev/projects/15835)
[![PyPI](https://img.shields.io/pypi/v/masaudit)](https://pypi.org/project/masaudit/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md)

---

## What is masaudit?

masaudit reads the source code of your Android, iOS, Kotlin Multiplatform, or Flutter app and finds security
weaknesses before you ship. It catches traffic sent over plain HTTP, secrets left in the code,
screens other apps can open, weak encryption, risky build settings, and unsafe CI workflows. It
runs on your machine, needs no account, and sends nothing anywhere.

The name is **MAS** + **audit**: it audits your app against
[OWASP MAS](https://mas.owasp.org/) (Mobile Application Security), the standards behind its checks.
masaudit is an independent project, not part of OWASP.

## Why you need it

Most mobile security problems aren't clever attacks. They're settings and code that slipped
through review: a debug flag left on, a test server that accepts any certificate, a token written
to the log. A pentest finds them late and costs money. The app stores don't look for them at all.

Other scanners find these too, but they give every app the same list. A news app gets told to pin
certificates like a bank, which adds outage risk for no gain, and the team learns to ignore the
tool. masaudit first asks what kind of app you're building. Then it sorts every finding into
**fix before release**, **fix soon**, or **not needed for your app**, and says why.

## Who it's for

- **Mobile developers** who want a security check without becoming security experts first.
- **Tech leads** getting ready for a pentest, a security review, or a compliance audit.
- **Security engineers** who want results scaled to each app's risk, in SARIF, on every pull request.

## How it works

1. **You answer one question:** what kind of app is this (banking, health, shop, loyalty, game, …)?
   masaudit saves the answer for next time.
2. **It reads your project:** manifests, Gradle files, `Info.plist`, Xcode projects, Kotlin, Java,
   and Swift code, and GitHub workflows. It never builds or runs your code.
3. **It writes `SECURITY-AUDIT.md`:** a verdict, the top fixes with paste-ready code, how to check
   each fix worked, and links to OWASP and to a free book that explains every finding.

## Three ways in

| **Scan, no AI needed** | **Fix it with an AI assistant** | **Learn why** |
|---|---|---|
| `uvx masaudit .` | Claude Code: `/plugin marketplace add hossam9k/masaudit` | Every rule links to the free book |
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
fix**, how long it takes, its OWASP IDs (MASWE, the catalog of mobile weaknesses, and MASVS, the
standard's controls), and the book section that explains it.

## Scan without AI

You need Python 3.9 or later (check with `python3 --version`). Run the scan from your project's root
folder, or pass the folder's path. Pick one way to run it:

```bash
uvx masaudit .              # if you have uv: https://docs.astral.sh/uv/
pipx run masaudit .         # if you have pipx: https://pipx.pypa.io/
python3 masaudit.pyz .      # no installer: download masaudit.pyz from the latest release
```

`masaudit.pyz` is one file from the [latest release](https://github.com/hossam9k/masaudit/releases/latest):
it works offline and needs nothing else. To install the command for good, use `pipx install masaudit`.
Plain `pip install masaudit` works inside a virtual environment.

The first run asks one question, **"What kind of app is this?"**, and offers to save your answer in
`.masaudit.ini`. If two types fit, pick the riskier one. The answer maps to OWASP's MAS profiles,
shown in the report: **L1** is the baseline, **L2** adds protection for sensitive data, **R** resists
tampering, and **P** covers privacy.

Without an answer (in CI, for example), it assumes `general` and lists higher-risk checks as
*Not needed*. Set `--app-type` in CI.

The report, `SECURITY-AUDIT.md`, starts with a verdict and the top 3 fixes. Fix those, scan again,
then add masaudit to CI.

### Options

These examples use `masaudit`. If you run it another way, type `uvx masaudit` or
`python3 masaudit.pyz` instead.

```bash
masaudit . --app-type loyalty     # banking, identity, health, ecommerce-cards, ecommerce, loyalty,
                                  # marketplace, social, content, device-control, enterprise, game, general
masaudit . --format sarif --output masaudit.sarif   # SARIF: the format GitHub code scanning reads
masaudit . --fail-on high         # exit 1 on open high or critical findings (exit 2: tool error)
masaudit --explain AND-004        # what a rule checks and how to fix it, offline
masaudit . --fix-safe             # preview automatic fixes as a diff; changes nothing
```

`--fix-safe` applies only fixes that can't change how a correct app behaves. Today that's one:
removing `android:debuggable="true"` from the main manifest. Every other finding has a paste-ready
fix in the report.

### In CI

Add this file as `.github/workflows/masaudit.yml`:

```yaml
name: masaudit
on: [push, pull_request]
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write          # to show results in GitHub code scanning
    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          persist-credentials: false
      - uses: hossam9k/masaudit@<commit-sha> # v0.3.0
        with:
          app-type: banking
          fail-on: high
```

Replace each `<commit-sha>` with the full 40-character commit ID of the release you want: open the
action's Releases page, click the tag, and copy the commit ID. A tag can be moved to other code; a
commit ID can't. Dependabot keeps the IDs current.

The Action runs from its own pinned source, with no download and no network. Results appear in the
repository's Security tab. Pull requests from forks skip the upload.

To scan before every commit, add this to `.pre-commit-config.yaml` ([pre-commit](https://pre-commit.com/)):

```yaml
repos:
  - repo: https://github.com/hossam9k/masaudit
    rev: v0.3.0
    hooks:
      - id: masaudit
        args: [--app-type, banking]
```

### Team features

- **Suppress a finding, with a reason.** Put a comment on the line or the line above. In Kotlin, Java,
  or Swift: `// masaudit:ignore AND-004 test server only, never in release`. In XML:
  `<!-- masaudit:ignore AND-015 reachable only with our signature permission -->`. A suppression
  without a reason is ignored and reported.
- **Accept today's findings in an older app.** `masaudit . --update-baseline` saves the current
  findings to `.masaudit-baseline.json`. Later runs with `--baseline .masaudit-baseline.json` show
  them as *Accepted* and fail only on new ones.
- **Bring your other tools.** `--import-sarif lint.sarif mobsfscan.sarif` sorts Android Lint,
  mobsfscan, Semgrep, and zizmor results by the same app type.

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

77 rules: 33 Android, 21 iOS, 10 cross-platform code, 8 CI and supply chain, 3 Kotlin Multiplatform, 2 Flutter.
Cross-platform rules read Kotlin, Java, Swift, Objective-C, and Dart.
See [docs/rules.md](https://github.com/hossam9k/masaudit/blob/main/docs/rules.md).

- **Network:** cleartext, ATS exceptions, user CAs, TLS bypasses (including Dart's `badCertificateCallback`), weak TLS, pinning (only where the profile needs it; Dart-side pinning counts for Flutter apps).
- **Storage:** Keychain classes, file protection, deprecated `EncryptedSharedPreferences`, Tink's silent cleartext fallback, backups, end-of-life SQLCipher.
- **Platform:** exported components, intent redirection, PendingIntent, deep links, FileProvider, WebView TLS, file access, JavaScript bridges, debugging.
- **Auth:** biometric prompts not bound to a key, keys that survive new enrollments, tokens in UserDefaults or Flutter's shared_preferences.
- **Code:** hardcoded secrets (masked in every output), ECB, fixed IVs, weak hashes and randomness, logged tokens.
- **Build and CI:** debuggable releases, R8 off, target SDK, unpinned actions, `pull_request_target`, script injection, committed signing keys.

## How it compares

| | masaudit | MobSF | mobsfscan | Android Lint |
|---|---|---|---|---|
| Advice scaled to the app's risk | **Yes** | No | No | No |
| "Not needed for your app", with reasons | **Yes** | No | No | No |
| Plain-language why, fix, and verify per finding | **Yes** | Partly | Partly | Partly |
| Android + iOS + KMP + Flutter + GitHub Actions | **Yes** | Android, iOS (binaries and source) | Android, iOS (source) | Android |
| Install | Single file, no dependencies | Docker (recommended) | pip (Semgrep) | Android SDK |
| Imports the others' SARIF and calibrates it | **Yes** | — | — | — |

MobSF also analyzes built APK and IPA files and runs the app for dynamic testing, which masaudit
doesn't. Use both.

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
