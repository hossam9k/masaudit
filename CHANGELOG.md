# Changelog

All notable changes, newest first. Versions follow [SemVer](https://semver.org/); the rules have
their own version (`rules_version`), shown in every report.

## Unreleased

- Fixed: a crafted workflow file with a stray `}` inside `[...]` made the scanner hang. Found by
  the new fuzz tests.
- Added: coverage-guided fuzzing of every parser in CI, CodeQL analysis, and the signed
  provenance bundle as a release asset. The release build now uses setuptools 84
  (CVE-2026-59890).

## 0.1.1 — 2026-10-23

- Fixed: `action.yml` was not valid YAML, so the GitHub Action failed to load (and Dependabot
  could not read it). CI now runs the Action itself on every change.

## 0.1.0 — 2026-10-23

- First version: risk-calibrated scanning for Android, iOS, Kotlin Multiplatform, and GitHub Actions;
  Markdown, JSON, and SARIF reports; inline suppressions and baselines; safe auto-fix preview;
  SARIF import from Android Lint, mobsfscan, Semgrep, and zizmor; a GitHub Action; a pre-commit hook;
  and a portable Agent Skill packaged as a Claude Code plugin.
