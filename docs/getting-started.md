[masaudit documentation](README.md) › Getting started

# Getting started: your first scan and fix

In this tutorial, you scan a small, deliberately insecure demo app, read the results, fix one finding,
and see it disappear. Then you scan your own app the same way. It takes about ten minutes.

This tutorial uses only the command line: **no AI and no account**. masaudit runs on your machine
and makes no network calls. If you want an AI assistant to help later, see
[Use masaudit with an AI assistant](ai-assistants.md).

You need Python 3.9 or later (check with `python3 --version`, or `py --version` on Windows), Git, and
[uv](https://docs.astral.sh/uv/). If you don't use uv, see [Install and upgrade](install.md) for other
ways to run masaudit, and type that command wherever this page says `uvx masaudit`.

## 1. Get the demo app

The masaudit repository includes the demo app, Acme Wallet:

```bash
git clone https://github.com/hossam9k/masaudit
cd masaudit/examples/acme-wallet
```

## 2. Run your first scan

```bash
uvx masaudit .
```

masaudit asks one question and lists 13 app types:

```text
What kind of app is this?
   1. banking          Banking, payments, wallets, crypto, lending, or insurance
   2. identity         Digital ID, government, password manager, VPN, or carrier
   ...
  13. general          Something else: a tool, notes, photos, maps (or not sure)

Code clues (suggestions only):
  - Found a payment SDK (Stripe) in android/app/build.gradle.kts - ecommerce may fit
Enter a number or name [13 = general]:
```

Acme Wallet holds people's money, so type `banking` and press Enter. When masaudit asks
`Save 'banking' to .masaudit.ini so you aren't asked again? [Y/n]:`, press Enter to save it.

The clue suggests `ecommerce` because the app uses Stripe. A clue never changes your answer: a
wallet holds money, so `banking` is right.

If masaudit doesn't ask, it can't read your keyboard (for example, in some IDE consoles, or when the
`CI` variable is set). It then says it assumed a general app. Run `uvx masaudit . --app-type banking`
instead, and add `--app-type banking` to the scan in step 6 too.

The app type matters: it decides which advice the app gets. A banking app is told to pin
certificates; a news app isn't. [Choose your app type](app-type.md) explains how to pick one.

## 3. Read the summary

The scan takes a few seconds. masaudit prints a summary like this (paths shortened):

```text
masaudit 0.6.0 (rules 2.2.0) - acme-wallet
Platforms: android, ios, ci
Profile:   banking (Banking, payments, wallets, crypto, lending, or insurance); MAS-L1+L2+R+P; from your answer
Clue:      Found a payment SDK (Stripe) in android/app/build.gradle.kts - ecommerce may fit

Fix before release: 12   Fix soon: 27   Notes: 0   Not needed: 0   Accepted: 0

Top fixes:
  1. [critical] Release build is debuggable (AND-002) - android/app/build.gradle.kts:17
  2. [critical] WebView ignores TLS certificate errors (AND-004) - .../WalletApi.kt:40
  3. [critical] pull_request_target workflow checks out the pull request's code (CI-003) - ...
Couldn't decide 1 thing; see Residual risk in the report.

Report: .../acme-wallet/SECURITY-AUDIT.md
Next: open SECURITY-AUDIT.md and start with Top fixes.
```

- **Fix before release:** 12 issues serious enough to block a release of a banking app.
- **Fix soon:** 27 real issues to schedule.
- **Not needed:** findings this app type doesn't need. A banking app needs everything, so it's 0.
- **Couldn't decide:** something the scanner couldn't check from source alone. The report's
  *Residual risk* section lists it for you to check by hand.

## 4. Open the report

masaudit wrote `SECURITY-AUDIT.md` in the app's folder. Open it and find the first top fix,
**Release build is debuggable (AND-002)**. Like every finding, it tells you why it matters, where it
is, how to fix it, and how to verify the fix.

You can also read about any rule in the terminal, offline:

```bash
uvx masaudit --explain AND-002
```

## 5. Fix the first finding

Open `android/app/build.gradle.kts`. Line 17, in the `release` build type, says:

```kotlin
isDebuggable = true
```

Change it to:

```kotlin
isDebuggable = false
```

## 6. Scan again

```bash
uvx masaudit .
```

masaudit doesn't ask the question again; it reads `.masaudit.ini`. The summary now shows
`Fix before release: 11`, and *Release build is debuggable* is gone from the top fixes. You found,
fixed, and verified your first finding.

## 7. Scan your own app

Go to your own project's root folder, the one with your `build.gradle.kts`, Xcode project, or
`pubspec.yaml` (for React Native, the folder with `package.json`), and run the same command:

```bash
uvx masaudit .
```

Answer the question for your own app, then work through the top fixes the same way.

The report lists your app's open weaknesses. If your repository is public, add `SECURITY-AUDIT.md` to
`.gitignore` so you don't publish it before you fix them.

## Next steps

- **Understand everything in the report:** [Read and fix the report](fixing.md).
- **Scan every pull request:** [Use masaudit in CI](ci.md).
- **Get help from an AI assistant** to confirm findings and apply fixes:
  [Use masaudit with an AI assistant](ai-assistants.md).
