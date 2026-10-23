# Changelog

All notable changes, newest first. Versions follow [SemVer](https://semver.org/); the rules have
their own version (`rules_version`), shown in every report.

## 0.3.0 — 2026-10-24

- **Flutter (Dart) source scanning.** Until now masaudit read a Flutter app's Android and iOS
  configuration but not its Dart code.
  - The cross-platform rules now read `.dart` files: hardcoded secrets (XPL-001 to XPL-003), ECB and
    CBC through package:encrypt and PointyCastle (XPL-004, XPL-005), fixed IVs such as
    `IV.allZerosOfLength` and `IV.fromUtf8('...')` (XPL-006), MD5 and SHA-1 from package:crypto
    (XPL-007), dart:math `Random()` in code that handles tokens or nonces (XPL-008), plain-HTTP URLs
    and `Uri.http(...)` (XPL-009), and tokens passed to `print`, `debugPrint`, or `log` (XPL-010).
  - New `FLT-001`: `badCertificateCallback` that returns `true` (TLS bypass, critical).
  - New `FLT-002`: tokens or passwords written to shared_preferences; use `flutter_secure_storage`.
  - The Android and iOS pinning checks (AND-007, IOS-007) no longer skip Flutter apps. Dart-side
    pinning (`SecurityContext(withTrustedRoots: false)`, `setTrustedCertificatesBytes`, Dio's
    `validateCertificate`, or a pinning package in `pubspec.yaml`) counts as pinning. Native-only
    pinning is listed under residual risk, because Dart's HttpClient has its own TLS stack and
    ignores it. React Native apps are still skipped.
  - The lexer understands Dart raw strings (`r'...'`), `'''` strings, and nested block comments.
  - Cross-platform rules now run on projects that are only Flutter (`pubspec.yaml`).
- README, the Claude Code plugin, the skill, and the GitHub Action now name Flutter as a supported
  platform.
- Rules version 1.1.0 (two new rules, Dart patterns in ten existing ones).

## 0.2.0 — 2026-10-23

- **App types:** 13 instead of 11, so every common app has a clear choice.
  - New: `identity` (eID, government, password manager, VPN, carrier), `loyalty` (points, coupons,
    gift cards, tickets), and `device-control` (smart locks, home devices, cars).
  - `fintech` is merged into `banking`; `--app-type fintech` and saved `.masaudit.ini` files still
    work. More aliases, such as `restaurant`, `rewards`, `dating`, and `smart-home`.
  - `general` now includes privacy checks (MAS-P), which the book recommends for every app that
    handles user data. Descriptions fit an 80-column terminal.
  - New code clues suggest `loyalty`, `identity`, `device-control`, and crypto wallets. The card
    clue no longer fires on the word "pan".
- **Fixed:** the Android pinning check went silent when any comment or test mentioned "pinning",
  and missed TrustKit added as a Gradle dependency. Found by scanning a real app.
- **Fixed:** `--import-sarif` mapped Android Lint's AllowBackup to the backup-pin rule and
  SetJavaScriptEnabled to the JavaScript-bridge rule. Every mapping now names its rule explicitly
  and is tested.
- **Fixed:** a crafted workflow file with a stray `}` inside `[...]` made the scanner hang. Found by
  the new fuzz tests.
- The closing hint shows the command you actually ran (`uvx masaudit`, `python3 masaudit.pyz`, ...)
  and offers `--fix-safe` only when a safe fix exists. `--fail-on` says why it exits 1.
- The report heading "What was checked and held" is now "Checked, nothing found".
- README: valid CI workflow, pre-commit snippet, prerequisites, XML suppression syntax, and plain
  definitions of SARIF, MAS profiles, and baselines.
- Added: coverage-guided fuzzing of every parser in CI, CodeQL, ruff, and the signed provenance
  bundle as a release asset. The release build uses setuptools 84 (CVE-2026-59890).

## 0.1.1 — 2026-10-23

- Fixed: `action.yml` was not valid YAML, so the GitHub Action failed to load (and Dependabot
  could not read it). CI now runs the Action itself on every change.

## 0.1.0 — 2026-10-23

- First version: risk-calibrated scanning for Android, iOS, Kotlin Multiplatform, and GitHub Actions;
  Markdown, JSON, and SARIF reports; inline suppressions and baselines; safe auto-fix preview;
  SARIF import from Android Lint, mobsfscan, Semgrep, and zizmor; a GitHub Action; a pre-commit hook;
  and a portable Agent Skill packaged as a Claude Code plugin.
