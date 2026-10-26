[masaudit documentation](README.md) › Benchmark on unseen apps

# Benchmark on apps no rule was tuned on

[Accuracy and speed](precision.md) measures masaudit on the apps its rules were tuned on, after the false
alarms found there were fixed. That number is optimistic by design. This page measures what a new user
gets: open-source apps that no rule was written or fixed for, scanned by masaudit and three other free
scanners on the same commits, in four rounds. Losses are included.

**Short version** (October 2026):

- **On code it hasn't seen, expect about 1 in 3 findings in masaudit's fix lists to be a false alarm.**
  Round 4 (0.6.5, 16 new apps): 33% (23–44%) of the app-code findings in *Fix before release* and *Fix
  soon*. 0.6.5 moved the noisiest findings, 162 of 350 in app code, to *Check by hand* and the *Hardening
  checklist*, which don't fail CI; none of the 30 sampled there was a real vulnerability. Counting every
  bucket, the rate is about where it was: 26% for 0.6.2, 45% for 0.6.3, 40% for 0.6.4, about 44% for 0.6.5.
  The rules didn't get more accurate; the fix lists got cleaner.
- **Only about 1 in 7 to 1 in 11 app-code findings is a vulnerability as described.** Most of the rest are
  real gaps that matter less than they sound: a missing hardening control, a debug-only setting.
- **CI findings hold up:** none of 30 false in round 4, 1 of 62 in round 3, none of 45 in round 2, 2 of 49
  in round 1.
- **The other free scanners did worse in every round.** Round 4: mobsfscan's sampled findings were false
  91% of the time, rnsec's 72% (none as serious as stated), Semgrep's free rules 3 of 3.
- **The next step is reading what ships:** about a third of the false alarms left are in demo apps, test
  modules, and debug-only build types. See [Round 4](#round-4-065-on-16-more-apps).

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

**After the fixes** (on `main`, not yet released): 21 of the 25 are gone, each with a test, and nothing a
judge called real or overrated was lost. On the same sample, 4 of 34 app-code findings (12%) are still
false. As after round 1, that number is optimistic: these are the findings the fixes were written for.
Two are left on purpose:

- AND-015 still reports an exported screen that reads nothing from its intent (Material Files, Habitica's
  Wear OS app). DIVA's credential screen and InsecureBankv2's transfer screen read nothing either, yet
  opening them is the flaw, so taking no input doesn't make a screen safe.
- IOS-021 counts a Release configuration that a shared scheme archives, even when the App Store build uses
  another (Simplenote archives Release from its screenshot and intents schemes).

AND-048 for a wallet with no backend is the same judgment call as in round 1.

## Round 3: 0.6.4 on 16 more apps

Chosen after 0.6.4 was released: Feeder, Fossify Messages, Breezy Weather, Etar, bitchat (Android);
Pocket Casts, bitchat, Element, Proton VPN (iOS); Discourse and Jitsi Meet (React Native); Cake Wallet,
Saber, Openreads, AuthPass (Flutter); Keyguard (Kotlin Multiplatform). Same method as round 2. The first
draw held only 38 app-code findings, so 30 more were drawn at random from the rest (and 10 more mobsfscan
findings, so judges still saw tools mixed); the 68 together are a random sample of the 241. Every verdict
is in [benchmark-judgments-3.json](benchmark-judgments-3.json).

| Tool | Findings | Total time |
|---|---|---|
| masaudit, each app's own type | 659 (418 CI, 241 app code) | 24 s |
| mobsfscan | 2,591 | 35 min |
| Semgrep, free registry rules | 1 | 41 s |
| rnsec | 128 | 21 s |

| Tool | Sample | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| masaudit app code | 68 | 10 (15%, 8–25%) | 31 | 27 (40%, 29–52%) | 60% (48–71%) |
| masaudit CI | 62 | 14 (23%, 14–34%) | 47 | 1 (2%, 0–9%) | 98% (91–100%) |
| mobsfscan | 70 | 0 (0–5%) | 5 | 65 | 7% (3–16%) |
| rnsec | 40 | 0 (0–9%) | 19 | 21 | 48% (33–63%) |
| Semgrep, free registry rules | 1 | 0 | 0 | 1 | 0% |

**Why fixing round by round didn't help:** the 27 false alarms come from 22 rules, one to three each,
and fall into three groups:

- **Code that doesn't ship** (about a third): a Gradle build plugin, a `scripts/` tool, a `sampleapps/`
  app, a test client app, a macOS file in no project, a function nothing calls.
- **Android manifest merging:** a permission removed with `tools:node="remove"`, and `allowBackup="false"`
  set in a library module's manifest that the app inherits.
- **Context a pattern can't see:** `Random()` for a UI animation tag, an all-zero key used only to test
  for AES-256 support, logging behind a constant `false`, a PBKDF2 function nothing calls.

Matching patterns one file at a time, masaudit can't know which code ships or what a value is for. The
next releases aim at that rather than at single cases: reading the Gradle and Xcode project structure (which
modules and targets build the app, and the merged Android manifest) to decide what ships, and marking the
rules that keep misfiring *Check by hand* until they are reliable.

## Round 4: 0.6.5 on 16 more apps

Chosen after 0.6.5 was released, the first version with *Check by hand* and the *Hardening checklist*:
Termux, Delta Chat, Tasks.org, Proton Pass, Mullvad VPN (Android); Kickstarter, Kiwix, Session, Monal
(iOS); Zeus and Edge (React Native); BlueBubbles, wger, ProxyPin, Mangayomi (Flutter); Tivi (Kotlin
Multiplatform). Same tools, scope, and judging as round 2, with each app scanned as its own type. masaudit's
findings were drawn from three pools, so each could be measured: 70 from its fix lists in app code, 30
from *Check by hand* and the *Hardening checklist* in app code, and 30 from its fix lists in CI. Judges
didn't see which pool a finding came from: the text the two new buckets add to a message was removed.
Every verdict is in [benchmark-judgments-4.json](benchmark-judgments-4.json); `sample --buckets` and
`--where` repeat the draws.

| Tool | Findings | Total time |
|---|---|---|
| masaudit, each app's own type | 738 (388 CI; 350 app code: 188 in the fix lists, 162 in *Check by hand* or the *Hardening checklist*) | 25 s |
| mobsfscan | 1,214 | 32 min |
| Semgrep, free registry rules | 3 | 55 s |
| rnsec | 583 | 53 s |

| Tool | Sample | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| masaudit fix lists, app code | 70 | 12 (17%, 10–28%) | 35 | 23 (33%, 23–44%) | 67% (56–77%) |
| masaudit *Check by hand* and *Hardening checklist*, app code | 30 | 0 (0–11%) | 13 | 17 (57%, 39–73%) | 43% (27–61%) |
| masaudit CI | 30 | 16 (53%, 36–70%) | 14 | 0 (0–11%) | 100% (89–100%) |
| mobsfscan | 70 | 1 (1%, 0–8%) | 5 | 64 | 9% (4–17%) |
| rnsec | 40 | 0 (0–9%) | 11 | 29 | 28% (16–43%) |
| Semgrep, free registry rules | 3 | 0 | 0 | 3 | 0% |

**What the new buckets did:** they took 46% of the app-code findings (162 of 350) out of the fix lists,
and none of the 30 sampled was a real vulnerability as described. 14 of their 17 false alarms were
plain-HTTP URLs (XPL-009), the rest exported components and resilience checks. In the fix lists, 33% are
false against 40% in round 3; the intervals overlap, so treat that as a likely improvement, not a
measured one. Weighting the two app-code samples by the size of their pools, about 44% of all app-code
findings are false, close to round 3: the rules didn't get more accurate.

**The 23 false alarms left in the fix lists:**

- **Code that doesn't ship** (7): a demo app module, an end-to-end test app, a test module's network
  config, a QA-only flavor, a LeakCanary build type, a design-system demo screen behind internal tools.
- **Context a pattern can't see** (16): Swift symbols stripped at App Store export (IOS-021), password
  fields made secure in code rather than in the storyboard (IOS-043), a shell argument from the OS's own
  interface list, a public partner key, an NFC entitlement the app uses, a hidden PIN field.

The next release aims at the first group: reading the Gradle and Xcode project structure to decide which
modules, flavors, and targets build the shipped app.

## After the round 1 fixes

In 0.6.3, each false alarm in the sample was traced to its cause and fixed with a test,
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
