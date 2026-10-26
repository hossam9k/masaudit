[masaudit documentation](README.md) › Benchmark on unseen apps

# Benchmark on apps no rule was tuned on

[Accuracy and speed](precision.md) measures masaudit on the apps its rules were tuned on, after the false
alarms found there were fixed. That number is optimistic by design. This page measures what a new user
gets: 21 open-source apps that no rule was written or fixed for, scanned by masaudit and three other
free scanners on the same commits. Losses are included.

**Short version** (October 2026, masaudit 0.6.2):

- **masaudit's findings on app code are useful about 7 times in 10, but only about 1 in 12 is a
  vulnerability as described.** Most are real gaps that matter less than they sound: a missing
  hardening control, a debug-only setting, a protection the app type doesn't need.
- **About 3 in 10 of its app-code findings are false alarms.** The tuned corpus suggests 1 in 10, so
  expect more noise on your code than [Accuracy and speed](precision.md) shows.
- **Its CI findings hold up much better:** 48 of 50 sampled were real, 18 of them as serious as stated.
- **The other free scanners did worse on the same apps.** On the sampled findings: mobsfscan was useful
  2 times in 10 (1 of 80 serious), rnsec 2 in 10, and Semgrep's free registry rules 0 in 8.
- **Every real weakness another tool found in the sample, masaudit found too** (2 of 2). The other
  tools' extra findings were low-impact: debug logging, `allowBackup`, tapjacking.

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
3. **Scope:** the same path rules drop test, sample, preview, and demo folders for every tool.
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
| masaudit, every rule (banking) | 1,074 (445 CI, 629 app code) | 21 | 31 s |
| masaudit, each app's own type | 825 (445 CI, 380 app code) | 21 | 32 s |
| mobsfscan | 869 | 18 (not React Native) | 65 min |
| Semgrep, free registry rules | 8 | 17 (not Flutter) | 49 s |
| rnsec | 84 | 3 (React Native) | 16 s |

Semgrep's free rulesets have few mobile rules, so this says little about Semgrep with mobile rules of
your own or Semgrep's paid rules.

### How many findings are real (judged sample, 95% intervals)

| Tool | Sample | Real | Overrated | False | Real or overrated |
|---|---|---|---|---|---|
| masaudit app code, every rule | 70 | 5 (7%, 3–16%) | 47 | 18 | 74% (63–83%) |
| masaudit app code, own app type | 48 | 4 (8%, 3–20%) | 30 | 14 | 71% (57–82%) |
| masaudit CI | 50 | 18 (36%, 24–50%) | 30 | 2 | 96% (87–99%) |
| mobsfscan | 80 | 1 (1%, 0–7%) | 15 | 64 | 20% (13–30%) |
| rnsec | 40 | 1 (3%, 0–13%) | 6 | 32 | 18% (9–32%) |
| Semgrep, free registry rules | 8 | 0 | 0 | 8 | 0% (0–32%) |

### Where masaudit loses

- **Most app-code findings are hardening, not vulnerabilities.** Missing root, debugger, emulator, or
  hooking detection, forced update, R8, and App Attest made up most of the *overrated* findings. Setting
  the app type removed 22 of the 70 sampled findings (17 of them overrated), but 8 of the remaining 48
  are still resilience checks that a judge called optional for that app.
- **False alarms the tuned corpus never showed.** They are the work list for the next release:
  - Test and preview code in shipping folders: a `uiTest` source set, Jetpack Compose `@Preview`
    functions, mock factories, a sample Xcode target (AND-005, XPL-009, XPL-036, IOS-019).
  - Protections masaudit doesn't see: a Flutter plugin that sets `FLAG_SECURE` (AND-045), OAuth
    callbacks caught inside `ASWebAuthenticationSession` or a web view (IOS-017), a message origin
    checked by a broker object (IOS-015).
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
- Report false alarms. Each one in this benchmark is now an issue to fix, with a test.
