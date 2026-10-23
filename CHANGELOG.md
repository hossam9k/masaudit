# Changelog

All notable changes, newest first. Versions follow [SemVer](https://semver.org/); the rules have
their own version (`rules_version`), shown in every report.

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
