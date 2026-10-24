# masaudit

**A free mobile security scanner that scales its advice to your app's risk.**

[![ci](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hossam9k/masaudit/badge)](https://scorecard.dev/viewer/?uri=github.com/hossam9k/masaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15835/badge)](https://www.bestpractices.dev/projects/15835)
[![PyPI](https://img.shields.io/pypi/v/masaudit)](https://pypi.org/project/masaudit/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md)

masaudit reads the source code of your Android, iOS, Kotlin Multiplatform, or Flutter app and finds
security weaknesses before you ship. It first asks what kind of app you're building, then sorts every
finding into **fix before release**, **fix soon**, or **not needed for your app**, and says why.
masaudit tells a banking app to pin certificates, and never tells a news app to.

masaudit needs no AI, no account, and no network connection after the first download.

**[Documentation](https://github.com/hossam9k/masaudit/blob/main/docs/README.md)** ·
**[Getting started](https://github.com/hossam9k/masaudit/blob/main/docs/getting-started.md)** ·
**[Rules](https://github.com/hossam9k/masaudit/blob/main/docs/rules.md)**

## Quick start

Use masaudit on its own, or with an AI assistant. The scan, the report, and every fix work without AI.

| | Without AI | With an AI assistant (optional) |
|---|---|---|
| Start | Run one command, below | Install the masaudit plugin or skill in your assistant |
| You get | `SECURITY-AUDIT.md`: what to fix, why, how, and how to verify | The same report, plus the assistant confirms each finding in your code and fixes them with you |
| Guide | [Getting started](https://github.com/hossam9k/masaudit/blob/main/docs/getting-started.md) | [Use masaudit with an AI assistant](https://github.com/hossam9k/masaudit/blob/main/docs/ai-assistants.md) |

### Without AI

You need Python 3.9 or later. In your project's root folder, run one of these:

```bash
uvx masaudit .                       # if you have uv: https://docs.astral.sh/uv/
pipx run masaudit .                  # if you have pipx: https://pipx.pypa.io/
python3 ~/Downloads/masaudit.pyz .   # no installer: one file, works offline
```

For the last line, first download `masaudit.pyz` from the
[latest release](https://github.com/hossam9k/masaudit/releases/latest) to your Downloads folder. On
Windows, run `py $HOME\Downloads\masaudit.pyz .` in PowerShell.
[Install and upgrade](https://github.com/hossam9k/masaudit/blob/main/docs/install.md) lists every way
to run it.

masaudit asks one question, "What kind of app is this?", reads your project without running it, and
writes `SECURITY-AUDIT.md` with the top fixes first.
[Getting started](https://github.com/hossam9k/masaudit/blob/main/docs/getting-started.md) walks you
through your first fix.

### With an AI assistant

In Claude Code:

```text
/plugin marketplace add hossam9k/masaudit
/plugin install masaudit@masaudit
/masaudit:scan
```

Codex, GitHub Copilot, Cursor, Gemini CLI, and other [Agent Skills](https://agentskills.io) tools can
use the same skill, and any chat assistant can use the report's fix plan. See
[Use masaudit with an AI assistant](https://github.com/hossam9k/masaudit/blob/main/docs/ai-assistants.md).

## See it on a real app

The repository ships a deliberately insecure demo app,
[Acme Wallet](https://github.com/hossam9k/masaudit/tree/main/examples/acme-wallet). Scanned as a news
app, the terminal shows (trimmed):

```text
$ uvx masaudit examples/acme-wallet --app-type news
Profile:   content (News, video, music, reading, or learning); MAS-L1+P; from --app-type
Clue:      Found a payment SDK (Stripe) in android/app/build.gradle.kts - ecommerce may fit

Fix before release: 9   Fix soon: 12   Notes: 0   Not needed: 18   Accepted: 0

Top fixes:
  1. [critical] Release build is debuggable (AND-002) - android/app/build.gradle.kts:17
  2. [critical] WebView ignores TLS certificate errors (AND-004) - .../WalletApi.kt:40
  3. [critical] pull_request_target workflow checks out the pull request's code (CI-003) - ...
```

The same code gets different advice under each app type:

| | As a **banking** app | As a **news** app |
|---|---|---|
| Fix before release | 12 | 9 |
| Fix soon | 27 | 12 |
| Not needed for your app | 0 | 18: pinning, root and debugger detection, App Attest, Play Integrity, screenshot blocking, … each with the reason |
| Full report | [banking report](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-banking.md) | [news report](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-news.md) |

Each finding tells you why it matters, how to fix it (often with paste-ready code), how to verify the
fix, how long it takes, its OWASP IDs, and the section of a free book that explains it.

## What it checks

172 rules: 66 Android, 42 iOS, 42 cross-platform code, 8 Flutter, 8 CI and supply chain, 6 Kotlin
Multiplatform. Together they cover 52 of the 78 weaknesses in OWASP's MASWE catalog and cite 132
OWASP MASTG tests.

- **Network:** cleartext, ATS exceptions, user CAs, TLS bypasses, old TLS versions, gRPC plaintext, and pinning where the app type needs it.
- **Storage:** tokens in plain preferences or UserDefaults, Keychain classes, backups and device transfer, shared and world-readable files.
- **Crypto:** hardcoded keys, ECB, CBC without a MAC, fixed IVs and salts, broken ciphers, small keys, weak PBKDF2.
- **Platform:** exported components, intent redirection, deep links, FileProvider, Dirty Stream, Zip Slip, WebView risks, screenshot and overlay protection.
- **Auth:** biometrics not bound to a key, passcode fallback for sensitive actions, keys that survive new enrollments.
- **Privacy:** sensitive permissions, hardware identifiers, IDFA without App Tracking Transparency, privacy manifests, tracking domains.
- **Build and CI:** debuggable releases, debug tools in release, R8 keep rules, unpinned actions, persisted tokens, script injection, committed signing keys.
- **Resilience,** for banking, identity, loyalty, and game apps: Play Integrity, App Attest, and root, debugger, emulator, and hooking detection.

## Guides by task

| You want to | Read |
|---|---|
| Scan on your own machine and fix findings | [Getting started](https://github.com/hossam9k/masaudit/blob/main/docs/getting-started.md), then [Read and fix the report](https://github.com/hossam9k/masaudit/blob/main/docs/fixing.md) |
| Pick the right app type | [Choose your app type](https://github.com/hossam9k/masaudit/blob/main/docs/app-type.md) |
| Scan every pull request | [Use masaudit in CI](https://github.com/hossam9k/masaudit/blob/main/docs/ci.md) |
| Have an AI assistant confirm and fix findings | [Use masaudit with an AI assistant](https://github.com/hossam9k/masaudit/blob/main/docs/ai-assistants.md) |
| Share settings, suppress findings, adopt it in an older app | [Use masaudit in a team](https://github.com/hossam9k/masaudit/blob/main/docs/team.md) |

In GitHub Actions, the step looks like this; the [CI guide](https://github.com/hossam9k/masaudit/blob/main/docs/ci.md)
has the complete workflow:

```yaml
- uses: hossam9k/masaudit@<commit-sha> # v0.4.3
  with:
    app-type: banking
    fail-on: high
```

## How accurate it is

The rules were measured on 19 open-source apps, including Signal, Bitwarden, Wikipedia, Nextcloud,
DuckDuckGo, and Thunderbird. Reviewers who didn't write the rules opened every finding in shipping
code (CI findings were sampled). The maintainers fixed every false alarm, added a test for it, and
scanned the apps again.

- **79 rules fired on these apps; 78 are at 90% precision or better.** The one below, IOS-012 (89%),
  is marked *Check by hand*. Rules that found nothing there are checked by their test fixtures.
- **Fast on large code bases:** the largest app, DuckDuckGo for Android (about 10,000 files), scans in
  under 6 seconds on a laptop, with no crashes on any of the 19.

Method and per-rule numbers: [Accuracy and speed](https://github.com/hossam9k/masaudit/blob/main/docs/precision.md).

## Limits and safety

- **What it can't see:** your server, runtime behavior, and business logic, which is where many
  breaches happen. Every report has a *Residual risk* section for that reason.
- **Safe to run on any code:** masaudit never builds or runs your code, makes no network calls (a test
  enforces it), sends no telemetry, and masks secrets in every output. Crafted files can't stall it.

[How masaudit works](https://github.com/hossam9k/masaudit/blob/main/docs/how-it-works.md) explains both.
To report a vulnerability, see [SECURITY.md](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md).

## How it compares

| | masaudit | MobSF | mobsfscan | Android Lint |
|---|---|---|---|---|
| Advice scaled to the app's risk | **Yes** | No | No | No |
| "Not needed for your app", with reasons | **Yes** | No | No | No |
| Plain-language why, fix, and verify per finding | **Yes** | Partly | Partly | Partly |
| Android + iOS + KMP + Flutter + GitHub Actions | **Yes** | Android, iOS (binaries and source) | Android, iOS (source) | Android |
| Install | Single file, no dependencies | Docker (recommended) | pip (Semgrep) | Android SDK |
| Imports SARIF from Android Lint, mobsfscan, Semgrep, and zizmor, and sorts it by app type | **Yes** | — | — | — |
| Published precision on real apps | **Yes** | — | — | — |

MobSF also analyzes built APK and IPA files and runs the app for dynamic testing, which masaudit
doesn't. Use both.

## Documentation

The [documentation home](https://github.com/hossam9k/masaudit/blob/main/docs/README.md) has every guide,
the [command-line](https://github.com/hossam9k/masaudit/blob/main/docs/cli.md) and
[config file](https://github.com/hossam9k/masaudit/blob/main/docs/config.md) reference, and
[how masaudit works](https://github.com/hossam9k/masaudit/blob/main/docs/how-it-works.md).

## Contributing

False-positive reports are the most valuable contribution: a rule that raises false alarms gets
ignored. Use the [false-positive form](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).
Adding a rule takes about 30 minutes; see
[CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md).

## About

Built by **Hossam Atef**, a mobile engineer (Android, iOS, Kotlin Multiplatform), as the practical
companion to his free book,
[*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security).
Every rule traces to a section of the book, and the book records how each claim was verified.

The name is **MAS** + **audit**: it audits your app against [OWASP MAS](https://mas.owasp.org/)
(Mobile Application Security), the standards behind its checks. masaudit is not an OWASP project;
OWASP doesn't certify apps or endorse tools.

Licensing: code Apache-2.0, fix snippets MIT-0, explanations CC BY-SA 4.0. See
[LICENSING.md](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md).

masaudit is free. If it saved you an audit, you can [sponsor it](https://github.com/sponsors/hossam9k).
