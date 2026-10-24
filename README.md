# masaudit

**A free mobile security scanner that scales its advice to your app's risk.**

[![ci](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/hossam9k/masaudit/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hossam9k/masaudit/badge)](https://scorecard.dev/viewer/?uri=github.com/hossam9k/masaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15835/badge)](https://www.bestpractices.dev/projects/15835)
[![PyPI](https://img.shields.io/pypi/v/masaudit)](https://pypi.org/project/masaudit/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/hossam9k/masaudit/blob/main/LICENSING.md)

masaudit reads the source code of your Android, iOS, Kotlin Multiplatform, or Flutter app and finds
security weaknesses before you ship. It first asks what kind of app you're building. Then it sorts
every finding into **fix before release**, **fix soon**, or **not needed for your app**, and says why.

A news app should never be told to pin certificates. A banking app should. Most scanners give both
the same list.

It runs on your machine, needs no account, and sends nothing anywhere. Use it two ways:

- **On its own, no AI needed:** the [quick start](https://github.com/hossam9k/masaudit#quick-start-no-ai-needed) below. Everything,
  including the report and its fixes, works offline.
- **With an AI assistant** that confirms findings and applies fixes: see
  [Use it with an AI assistant](https://github.com/hossam9k/masaudit#use-it-with-an-ai-assistant).

## Quick start (no AI needed)

You need Python 3.9 or later. Check with `python3 --version`. In your project's root folder, run
one of these:

```bash
uvx masaudit .              # if you have uv: https://docs.astral.sh/uv/
pipx run masaudit .         # if you have pipx: https://pipx.pypa.io/
python3 masaudit.pyz .      # no installer: download masaudit.pyz from the latest release
```

`masaudit.pyz` is a single file from the [latest release](https://github.com/hossam9k/masaudit/releases/latest).
It works offline and needs nothing else. To keep the `masaudit` command installed, run
`pipx install masaudit`. For Windows and other options, see the
[usage guide](https://github.com/hossam9k/masaudit/blob/main/docs/usage.md).

What happens:

1. **It asks one question: "What kind of app is this?"** For example banking, health, shop, loyalty,
   or game. If two types fit, pick the riskier one. masaudit offers to save your answer in
   `.masaudit.ini`.
2. **It reads your project.** It reads manifests, Gradle files, `Info.plist`, Xcode projects, Kotlin,
   Java, Swift, Objective-C, and Dart code, and GitHub workflows. It never builds or runs your code.
3. **It writes `SECURITY-AUDIT.md`.** The report starts with a verdict and the top fixes.

If the code suggests a riskier app type than your answer, for example card-number fields in a news
app, masaudit warns you with "Check your app type" instead of switching on its own.

Fix those, scan again, then
[add masaudit to CI](https://github.com/hossam9k/masaudit/blob/main/docs/ci.md).

## What a scan looks like

The repository ships a deliberately insecure demo app,
[Acme Wallet](https://github.com/hossam9k/masaudit/tree/main/examples/acme-wallet). Here is the
terminal summary when you scan it as a news app:

```text
$ masaudit examples/acme-wallet --app-type news
masaudit 0.4.1 (rules 2.0.0) - acme-wallet
Platforms: android, ios, ci
Profile:   content (News, video, music, reading, or learning); MAS-L1+P; from --app-type
Clue:      Found a payment SDK (Stripe) in android/app/build.gradle.kts - ecommerce may fit

Fix before release: 9   Fix soon: 12   Notes: 0   Not needed: 18   Accepted: 0

Top fixes:
  1. [critical] Release build is debuggable (AND-002) - android/app/build.gradle.kts:17
  2. [critical] WebView ignores TLS certificate errors (AND-004) - android/app/src/main/java/com/acme/wallet/WalletApi.kt:40
  3. [critical] pull_request_target workflow checks out the pull request's code (CI-003) - .github/workflows/release.yml:10
```

The same code gets different advice under each app type:

| | As a **banking** app | As a **news** app |
|---|---|---|
| Fix before release | 12 | 9 |
| Fix soon | 27 | 12 |
| Not needed for your app | 0 | 18: pinning, root and debugger detection, App Attest, Play Integrity, screenshot blocking, … each with the reason |
| Full report | [sample-report-banking.md](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-banking.md) | [sample-report-news.md](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-news.md) |

Each finding in the report tells you:

- **why it matters** and **how to fix it**, with paste-ready code;
- **how to verify the fix** and how long the fix takes;
- its OWASP IDs: MASWE (the catalog of mobile weaknesses) and MASVS (the standard's controls);
- the section of a free book that explains it.

## Why masaudit

Most mobile security problems aren't clever attacks. They're settings and code that got past review:
a debug flag left on, a test server that accepts any certificate, a token written to the log. A
pentest finds them late and costs money. The app stores don't look for them at all.

Other scanners find these too, but they give every app the same list. When a news app is told to pin
certificates like a bank, it adds outage risk for no gain, and the team learns to ignore the tool.
masaudit gives each app the advice its risk calls for, and explains what it left out.

It's built for:

- **Mobile developers** who want a security check without becoming security experts first.
- **Tech leads** getting ready for a pentest, a security review, or a compliance audit.
- **Security engineers** who want results scaled to each app's risk, in SARIF, on every pull request.

## Use it with an AI assistant

**Claude Code:**

```text
/plugin marketplace add hossam9k/masaudit
/plugin install masaudit@masaudit
```

Then run `/masaudit:scan`, `/masaudit:fix`, `/masaudit:review`, or `/masaudit:explain AND-004`. You
can also ask in your own words, for example *"Is my app ready for a pentest?"*

**Other tools** (Codex, GitHub Copilot, Cursor, Gemini CLI, and other tools that read
[Agent Skills](https://agentskills.io)): copy
[`plugin/skills/masaudit/`](https://github.com/hossam9k/masaudit/tree/main/plugin/skills/masaudit)
into your tool's skills folder. The skill bundles the scanner, so it works offline.

**Any chat assistant:** every `SECURITY-AUDIT.md` ends with a *Fix plan for your AI assistant*.
Paste it into the chat.

The assistant confirms each finding in context and looks for what a scanner can't see, such as
server-side trust, biometric flows, and token handling. It fixes one finding at a time, asks before
any fix that changes behavior, and never commits.

## Use it in CI and in a team

The GitHub Action uploads results to the repository's Security tab and fails the job on open
findings at or above the level you choose. The step looks like this:

```yaml
      - uses: hossam9k/masaudit@<commit-sha> # v0.4.1
        with:
          app-type: banking
          fail-on: high
```

The [CI guide](https://github.com/hossam9k/masaudit/blob/main/docs/ci.md) has the complete workflow,
how to pin the Action to a commit, and a pre-commit hook.

For teams, masaudit can also suppress a single finding with a written reason, accept an older app's
current findings with a baseline so only new ones fail, and sort Android Lint, mobsfscan, Semgrep,
and zizmor results by the same app type. See
[Team features](https://github.com/hossam9k/masaudit/blob/main/docs/usage.md#team-features).

## What it checks

172 rules: 66 Android, 42 iOS, 42 cross-platform code, 8 Flutter, 8 CI and supply chain, 6 Kotlin
Multiplatform. Cross-platform rules read Kotlin, Java, Swift, Objective-C, and Dart. Together they
cover 52 of the 78 weaknesses in OWASP's MASWE catalog and cite 132 OWASP MASTG tests. Many of the
remaining weaknesses can't be seen in source code, such as server behavior or a built binary.

- **Network:** cleartext (app-wide or per domain), ATS exceptions, user CAs, TLS bypasses in Kotlin, Swift, Dart, and native code, old TLS versions, gRPC plaintext, pinning (only where the profile needs it).
- **Storage:** tokens in SharedPreferences, DataStore, UserDefaults, or shared_preferences; Keychain classes; backups and device-to-device transfer; shared and world-readable files; App Group files; Tink's silent cleartext fallback.
- **Crypto:** hardcoded keys, ECB, CBC without a MAC, fixed IVs and salts, DES/3DES/RC4, small keys, weak PBKDF2, MAC comparison with `==`, keys that both encrypt and sign.
- **Platform:** exported components (knowing which must be public), intent redirection, implicit intents carrying secrets, PendingIntent, deep links, FileProvider, Dirty Stream, Zip Slip, WebView file access and JavaScript bridges, screenshot and overlay protection, clipboard secrets, custom keyboards.
- **Auth:** biometrics not bound to a key, passcode fallback for sensitive actions, keys that survive new enrollments, LocalAuthentication reuse.
- **Privacy:** sensitive permissions, hardware identifiers, IDFA without App Tracking Transparency, privacy manifests and required-reason APIs, tracking domains, personal data sent to analytics.
- **Build and CI:** debuggable or test-only releases, debug tools and DEBUG code in release, R8 and keep rules, signing, unpinned actions (ranked by who owns them), persisted tokens, script injection, committed signing keys.
- **Resilience (MAS-R, only for banking, identity, loyalty, and game apps):** Play Integrity, App Attest, root, debugger, emulator, and hooking detection.

Every rule, with its fix and book link, is in
[docs/rules.md](https://github.com/hossam9k/masaudit/blob/main/docs/rules.md). Offline, run
`masaudit --explain AND-004` for one rule or `masaudit --list-rules` for all of them.

## How accurate it is

The rules were measured on 19 open-source apps, including Signal, Bitwarden, Wikipedia, Nextcloud,
DuckDuckGo, and Thunderbird. Reviewers who didn't write the rules opened every open finding in
shipping code and judged whether it was real. CI findings were sampled. Each false alarm they found
was fixed, with a test, and the apps were scanned again.

- **79 rules fired on these apps. 78 of them are at 90% precision or better.** The one below 90%,
  IOS-012 (89%), is marked *Check by hand*.
- Rules that found nothing in these apps are checked by their vulnerable and clean test fixtures.
- **Fast and safe on large code bases:** no crashes on any of the 19 apps, and the largest
  (DuckDuckGo for Android, about 10,000 files) scans in under 6 seconds on a laptop.

The method and per-rule numbers are in
[docs/precision.md](https://github.com/hossam9k/masaudit/blob/main/docs/precision.md).

## How it compares

| | masaudit | MobSF | mobsfscan | Android Lint |
|---|---|---|---|---|
| Advice scaled to the app's risk | **Yes** | No | No | No |
| "Not needed for your app", with reasons | **Yes** | No | No | No |
| Plain-language why, fix, and verify per finding | **Yes** | Partly | Partly | Partly |
| Android + iOS + KMP + Flutter + GitHub Actions | **Yes** | Android, iOS (binaries and source) | Android, iOS (source) | Android |
| Install | Single file, no dependencies | Docker (recommended) | pip (Semgrep) | Android SDK |
| Imports the others' SARIF and calibrates it | **Yes** | — | — | — |
| Published precision on real apps | **Yes** | — | — | — |

MobSF also analyzes built APK and IPA files and runs the app for dynamic testing, which masaudit
doesn't. Use both.

## What it can't do

masaudit reads your source and configuration. It can't see your server, runtime behavior, or
business logic, which is where many real breaches happen. Every report ends with a *Residual risk*
section that says so and lists anything the scanner couldn't decide. Findings marked
*Check by hand* need a person or an AI assistant to confirm them.

## Safe to run on any code

masaudit never executes project code, never follows symlinks out of the scan root, refuses XML
entity tricks, makes **no network calls** (a test enforces it), and masks secrets in every output.
No telemetry. To report a vulnerability or verify a download, see
[SECURITY.md](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md).

## Documentation

- [Usage guide](https://github.com/hossam9k/masaudit/blob/main/docs/usage.md): install options, app types, every option, the config file, and team features.
- [CI guide](https://github.com/hossam9k/masaudit/blob/main/docs/ci.md): GitHub Action, pre-commit hook, and other CI systems.
- [Rules](https://github.com/hossam9k/masaudit/blob/main/docs/rules.md): all 172 rules with fixes and book links.
- [Precision](https://github.com/hossam9k/masaudit/blob/main/docs/precision.md): how each rule was measured.
- Sample reports: [banking](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-banking.md) and [news](https://github.com/hossam9k/masaudit/blob/main/docs/sample-report-news.md).
- [Writing a rule](https://github.com/hossam9k/masaudit/blob/main/docs/writing-rules.md) and [CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md).
- [CHANGELOG.md](https://github.com/hossam9k/masaudit/blob/main/CHANGELOG.md) and [SECURITY.md](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md).
- The book: [*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security).

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
