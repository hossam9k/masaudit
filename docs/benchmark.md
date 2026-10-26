[masaudit documentation](README.md) › Benchmark on unseen apps

# Benchmark on apps no rule was tuned on

[Accuracy and speed](precision.md) measures masaudit on the apps its rules were tuned on, after the false
alarms found there were fixed. That number is optimistic by design. This page measures what a new user
gets: open-source apps that no rule was written or fixed for, scanned by masaudit and three other free
scanners on the same commits, in two rounds. Losses are included.

**Short version** (October 2026):

- **On code it hasn't seen, expect a third or more of masaudit's app-code findings to be false alarms.**
  Round 2 measured 0.6.3 on 18 new apps: 45% of the sampled app-code findings were false (33–58%).
  One file in one app, a list of XMP namespace URLs that XPL-009 read as plain-HTTP traffic, produced 16%
  of all app-code findings; without it, 35% were false. Round 1 measured 0.6.2 at 26%.
- **Only about 1 in 11 app-code findings is a vulnerability as described.** Most of the rest are real
  gaps that matter less than they sound: a missing hardening control, a debug-only setting.
- **CI findings hold up:** none of the 45 sampled in round 2 was false (11 as serious as stated), and 2 of
  49 in round 1.
- **The other free scanners did worse in both rounds.** Round 2: mobsfscan's sampled findings were real
  or overrated 12% of the time (0 of 60 as serious as stated), rnsec's 8% (0 of 40), Semgrep's free
  rules 0 of 3. Round 1 was similar.
- **Fixing one round's false alarms didn't make the next round clean.** After round 1, the same sample
  fell to about 1 in 18 false; this page said the true figure for 0.6.3 would be between that and 1 in 4.
  Round 2 found it was higher than both: new apps bring new causes. They are listed below as the next
  work list.

## Method

1. **Apps:** 21 open-source apps, chosen for mixed platforms and real users, none used to write or tune
   a rule: Aegis, KeePassDX, Home Assistant (Android and iOS), Jellyfin, Mihon, Proton Mail, Kickstarter,
   NetNewsWire, Firefox for iOS, DuckDuckGo for iOS, Zulip, Valora, iNaturalist, Ente Auth, FluffyChat,
   AppFlowy, LocalSend, Bitkey, Droidcon, and Confetti. Commits and the folder scanned in each monorepo
   are in `scripts/benchmark_compare.py`.
2. **Tools, with their defaults:** masaudit 0.6.2; mobsfscan 1.0.1 (Android and iOS source); Semgrep
   Community Edition 1.182.1 with the free registry rulesets for each app's languages (`p/kotlin`,
   `p/java`, `p/swift`, `p/javascript`, `p/typescript`, `p/react`; the registry has none for Dart);
   rnsec 1.4.0 on the React Native apps. Android Lint was left out: it needs each app to build.
3. **Scope:** the same path rules drop test, sample, preview, and demo folders for every tool. masaudit's
   *notes* (findings it places in test, debug, or build code, listed apart from what to fix) are left
   out too, as a reader of its report would.
4. **masaudit twice:** once as a banking app, so every rule runs, and once with each app's own type
   (an authenticator is `identity`, a smart-home client `device-control`, a reader `content`; the table
   is in the script). The second is what a user who sets the app type gets.
5. **Judging:** a random sample of 248 findings (120 masaudit, 80 mobsfscan, 40 rnsec, all 8 Semgrep),
   shuffled across tools with the tool names removed. Each was opened in its real source file and
   labelled *real* (the weakness exists in shipped code, as described), *overrated* (real, but clearly
   less serious than stated), *false*, or *unclear*.
6. **Who judged:** AI reviewers (Claude agents) that wrote no rule, not independent human experts. Rule
   IDs still hint at the tool. Treat the numbers as a careful first measurement, and check the judged
   findings yourself. Everything needed to repeat it is published.

Every judged finding, with its verdict and the reason, is in
[benchmark-judgments.json](benchmark-judgments.json). `python3 scripts/benchmark_compare.py fetch DIR`,
then `scan DIR OUT`, `summary OUT DIR`, and `sample OUT DIR N` reproduce every step.

## Results

### Findings and time (shipping code, all 21 apps)

| Tool | Findings | Apps it can scan | Total time |
|---|---|---|---|
| masaudit, every rule (banking) | 1,037 (422 CI, 615 app code) | 21 | 31 s |
| masaudit, each app's own type | 789 (422 CI, 367 app code) | 21 | 32 s |
| mobsfscan | 869 | 18 (not React Native) | 65 min |
| Semgrep, free registry rules | 8 | 17 (not Flutter) | 49 s |
| rnsec | 84 | 3 (React Native) | 16 s |

Semgrep's free rulesets have few mobile rules, so this says little about Semgrep with mobile rules of
your own or Semgrep's paid rules.

### How many findings are real (judged sample, 95% intervals)

| Tool | Sample | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| masaudit app code, every rule | 68 | 5 (7%, 3–16%) | 47 | 16 | 76% (65–85%) |
| masaudit app code, own app type | 46 | 4 (9%, 3–20%) | 30 | 12 | 74% (60–84%) |
| masaudit CI | 49 | 17 (35%, 23–49%) | 30 | 2 | 96% (86–99%) |
| mobsfscan | 80 | 1 (1%, 0–7%) | 15 | 64 | 20% (13–30%) |
| rnsec | 40 | 1 (3%, 0–13%) | 6 | 32 | 18% (9–32%) |
| Semgrep, free registry rules | 8 | 0 | 0 | 8 | 0% (0–32%) |

### Where masaudit loses

- **Most app-code findings are hardening, not vulnerabilities.** Missing root, debugger, emulator, or
  hooking detection, forced update, R8, and App Attest made up most of the *overrated* findings. Setting
  the app type removed 22 of the 68 sampled findings (17 of them overrated), but 8 of the remaining 46
  are still resilience checks that a judge called optional for that app.
- **False alarms the tuned corpus never showed:**
  - Preview and sample code in shipping folders: Jetpack Compose `@Preview` functions, mock factories, a
    sample Xcode project (XPL-009, XPL-036, IOS-019).
  - Protections masaudit doesn't see: a Flutter plugin that sets `FLAG_SECURE` (AND-045), OAuth
    callbacks caught inside `ASWebAuthenticationSession` or a web view (IOS-017), a message origin
    checked by a broker object (IOS-015), a job switched off with `if: false` (CI-005).
  - Rules that misjudge context: BouncyCastle added at the lowest priority (AND-050), TOTP codes read
    as random numbers from the clock (XPL-045), Play Integrity expected for a self-hosted client
    (AND-048), permissions that match the app's purpose (AND-033), obfuscation expected for an
    open-source Flutter app (FLT-008).
- **Recall isn't measured here.** No one knows every weakness in these apps. Only the overlap is
  known: both sampled findings that another tool got right, masaudit also reported.

### What the others found that masaudit didn't

Among the sampled findings judged real or overrated, the ones masaudit didn't report were debug
logging of non-secret values (mobsfscan), `allowBackup` on apps whose targetSdk already blocks adb
backup (mobsfscan), missing tapjacking protection (mobsfscan), feed HTML loaded into a web view in a
feed reader (mobsfscan), and analytics SDKs in `package.json` (rnsec). Judges rated all of them low
impact, and masaudit leaves out most on purpose, but they are gaps if your threat model includes them.

## What to take from it

- Set your app type. It is the difference between a report about your app and a checklist for a bank.
- Read *Fix before release* first. The long tail of hardening findings is advice, not a list of bugs.
- Report false alarms. Each one in this benchmark became a fix with a test.

## Round 2: 0.6.3 on 18 more apps

Chosen after 0.6.3 was released, so no fix had seen them: Catima, Habitica, WireGuard, Material Files,
Seal, Nextcloud Notes, Pocket Casts (Android); Ice Cubes, Simplenote, WooCommerce, Wire (iOS); Ledger
Live and Blixt (React Native); Thunder, Aves, Hiddify, RustDesk (Flutter); Spotube (Kotlin
Multiplatform). Same tools, scope, and judging as round 1, with one change: masaudit's sample was drawn
from what a user sees, each app scanned with its own type (the types are in the script). Every verdict
is in [benchmark-judgments-2.json](benchmark-judgments-2.json).

| Tool | Findings | Total time |
|---|---|---|
| masaudit, each app's own type | 609 (318 CI, 291 app code) | 26 s |
| mobsfscan | 1,793 | 45 min |
| Semgrep, free registry rules | 3 | 52 s |
| rnsec | 536 | 21 s |

| Tool | Sample | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| masaudit app code | 55 | 5 (9%, 4–20%) | 25 | 25 (45%, 33–58%) | 55% (42–67%) |
| masaudit app code, without Aves' XMP file | 46 | 5 | 25 | 16 (35%) | 65% |
| masaudit CI | 45 | 11 (24%, 14–39%) | 34 | 0 (0–8%) | 100% (92–100%) |
| mobsfscan | 60 | 0 (0–6%) | 7 | 53 | 12% (6–22%) |
| rnsec | 40 | 0 (0–9%) | 3 | 37 | 8% (3–20%) |
| Semgrep, free registry rules | 3 | 0 | 0 | 3 | 0% |

**masaudit's false alarms in round 2,** the work list for the next release:

- XPL-009 reads XMP namespace URLs (`http://ns.google.com/photos/1.0/camera/`), a connectivity-check
  option, and a placeholder in a demo credentials file as plain-HTTP traffic; none is fetched with user
  data (11 of the 25).
- IOS-019 checks Xcode test-host apps (`WireDataModelTestHost`) and a Flutter app's macOS runner, which
  aren't iOS apps that ship.
- AND-015 reports exported components that read no input: a settings screen, AndroidX's
  `MediaTransferReceiver` (exported for the system's output switcher), a Wear OS main activity.
- One each: IOS-021 on a Release configuration the App Store archive doesn't use, RN-008 on a web view
  limited by `originWhitelist`, XPL-010 on a log of an option's name, XPL-017 on a loopback gRPC channel
  that switches to mTLS, XPL-040 when a forced-update screen exists under another name, AND-031 on native
  libraries unpacked from the app's own APK, AND-047 on R8 keep rules in a module that doesn't minify,
  and AND-048 for a self-custodial wallet with no backend.

## After the fixes

On `main` (unreleased), each false alarm in the sample was traced to its cause and fixed with a test,
and a check of the 29 tuned-corpus apps found no real finding lost. Of the 18 false alarms masaudit
asked you to fix (2 more were already notes), 13 are gone or moved to the notes, 2 (IOS-017) are now
rated low with a message that says what risk is left, and 3 are left on purpose:

- Preview-only code (Compose `@Preview`, SwiftUI `#Preview` and `PreviewProvider`) and `mock` or
  `fake` folders count as debug code, so their findings move to the report's notes.
- A sample or demo Xcode project next to the real app (SampleBrowser, ExampleApp) isn't checked for a
  privacy manifest.
- A job with `if: false` is skipped by every CI rule, and a Gradle task that pushes tags counts as a push.
- Sign-in callbacks received by `ASWebAuthenticationSession`, FlutterWebAuth2, or the app's own web view
  are rated low: no other app can catch the code, though one can still start a sign-in as yours.
- `FLAG_SECURE` set in a local Flutter package outside the scanned folder is reported as unknown, not
  missing; BouncyCastle appended with `addProvider` is no longer reported; TOTP codes, event-name
  constants, empty script handlers, and Wear OS settings screens are no longer false alarms.

| masaudit, own app type | Sample still reported | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| App code | 36 | 4 | 30 | 2 | 94% (82–98%) |
| CI | 47 | 17 | 30 | 0 | 100% (92–100%) |

These are the same findings that guided the fixes, so they overstate what you'll see on new code;
[round 2](#round-2-063-on-18-more-apps) measured 0.6.3 on new apps. The
three left on purpose question what a rule should report rather than how it reads code: a passcode
fallback for a kiosk settings screen (XPL-018), Play Integrity for a self-hosted client (AND-048), and
obfuscation for an open-source app (FLT-008). A new set of unseen apps will measure the next release.
