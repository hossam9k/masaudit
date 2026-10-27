[masaudit documentation](README.md) › Accuracy and speed

# Accuracy and speed

Developers ignore a scanner that raises many false alarms, so the maintainers measure every rule on
real apps before each release.

These numbers come from the apps the rules were tuned on, after their false alarms were fixed, so they
are the best case. On apps no rule was tuned on, about 1 in 3 app-code findings in the fix lists was a false
alarm for 0.7.0, and about 4 in 10 counting every bucket (26% for 0.6.2, 45% for 0.6.3, 40% for 0.6.4, about
44% for 0.6.5, about 38% for 0.7.0, on 87 apps in all): see [Benchmark on unseen apps](benchmark.md).

## Method

These numbers are for masaudit 0.4.0, measured in October 2026.

1. **Corpus:** 19 open-source apps, scanned from source as they were on 2026-10-24: Signal (Android,
   iOS), Bitwarden (Android, iOS), Wikipedia (Android, iOS), Nextcloud (Android, iOS), Element X
   (Android, iOS), DuckDuckGo (Android), Thunderbird (Android), Tusky, NewPipe, AntennaPod, Mastodon
   (iOS), KotlinConf (Kotlin Multiplatform), Lichess (Flutter), and Immich (Flutter).
2. **Every rule runs:** each app is scanned as `--app-type banking`, an app type that enables every
   rule.
3. **Independent review:** reviewers who didn't write the rules opened every open finding in shipping
   code in its real source file and judged it: a real weakness, real but rated too high, or false.
   "Not found anywhere" rules count only when a search confirms the protection is absent.
   CI rules were sampled (145 findings across the 7 CI rules that fired).
4. **Fix, then re-check:** every false positive was fixed in the detector, with a test fixture that must
   stay quiet, and the corpus was scanned again to confirm it was gone and no real finding was lost.

`scripts/corpus.py` downloads the corpus at the commits used, scans it, and compares two scans, so
anyone can repeat the method. Every later rule change goes through the same gate: scan the corpus
before and after, and open every added or removed finding. In 0.5.0, the 15 new rules and the fixes to
20 existing ones added 3 findings to the corpus, all real (one AND-012 JavaScript bridge, and two AND-075
WebViews that open any link, both low risk), and removed none. The table below is still the 0.4.0
review; the new rules have no other corpus findings, so their fixtures and the recall apps below check
them. The React Native work in 0.6.0 changed no finding on these 19 apps; it is measured on its own
corpus, [below](#react-native-precision).

**Precision** below is the share of a rule's findings that are real weaknesses after those fixes. A rule
must reach 90% or be marked *Check by hand*. Rules with no findings in this corpus are checked by
their vulnerable and clean test fixtures only.

## Results

Open findings (fix before release or fix soon) in shipping code and CI. "Apps" is how many of the
19 apps the rule fired in.

| Rule | Title | Findings | Apps | Precision |
|---|---|---|---|---|
| AND-001 | Cleartext (plain HTTP) traffic is allowed | 6 | 5 | 100% |
| AND-003 | User-installed CAs are trusted in release | 8 | 6 | 100% |
| AND-006 | OkHttp or SSLContext allows old TLS or plain HTTP | 2 | 1 | 100% |
| AND-007 | No certificate pinning (needed for high-risk apps) | 7 | 7 | 100% |
| AND-010 | WebView can read local files | 2 | 2 | 100% |
| AND-011 | WebView loads HTTP content inside HTTPS pages | 1 | 1 | 100% |
| AND-012 | JavaScript bridge is reachable from every frame | 15 | 5 | 100% |
| AND-015 | Exported component has no permission | 19 | 7 | 100% |
| AND-016 | FileProvider shares too much of the filesystem | 16 | 8 | 100% |
| AND-020 | SQL query built by joining strings | 2 | 1 | 100% |
| AND-021 | Backup is on with no exclusion rules | 1 | 1 | 100% |
| AND-022 | Deprecated EncryptedSharedPreferences (Jetpack Security) | 14 | 2 | 100% |
| AND-024 | Tink may silently store its keyset in plain text | 1 | 1 | 100% |
| AND-025 | Biometric prompt is not tied to a key | 6 | 4 | 100% |
| AND-029 | minSdk is below 24 | 1 | 1 | 100% |
| AND-032 | Java deserialization with ObjectInputStream | 3 | 2 | 100% |
| AND-034 | Token or password stored in plain SharedPreferences or DataStore | 5 | 3 | 100% |
| AND-036 | Backup rules don't keep sensitive data out of device-to-device transfer | 5 | 4 | 100% |
| AND-040 | WebView Safe Browsing is turned off | 2 | 2 | 100% |
| AND-041 | Keystore key accepts caller-chosen IVs | 1 | 1 | 100% |
| AND-045 | App never blocks screenshots or the recents thumbnail | 6 | 6 | 100% |
| AND-046 | App has no overlay (tapjacking) protection | 11 | 11 | 100% |
| AND-047 | R8 keep rules undo obfuscation | 9 | 6 | 100% |
| AND-048 | Play Integrity is not integrated | 12 | 12 | 100% |
| AND-050 | Crypto call names an explicit provider | 3 | 2 | 100% |
| AND-052 | Biometric prompt doesn't require explicit confirmation | 6 | 2 | 100% |
| AND-056 | Receiver registered in code is exported | 6 | 3 | 100% |
| AND-059 | WebView runs JavaScript with content access on | 30 | 6 | 100% |
| AND-060 | App writes to shared external storage | 6 | 3 | 100% |
| AND-062 | StrictMode logging ships in release | 1 | 1 | 100% |
| AND-065 | Serializable object read from an Intent | 6 | 2 | 100% |
| AND-072 | App requests fraud-relevant permissions | 6 | 6 | 100% |
| CI-001 | Action is pinned to a tag or branch, not a commit SHA | 440 | 12 | 100% of 62 sampled |
| CI-002 | Workflow token permissions are not restricted | 76 | 11 | 100% of 24 sampled |
| CI-003 | pull_request_target workflow checks out the pull request's code | 2 | 2 | 100% |
| CI-004 | Untrusted event text is pasted into a run script | 6 | 1 | 100% |
| CI-005 | actions/checkout leaves the job token on disk | 159 | 15 | 100% of 42 sampled |
| CI-006 | Signing key or signing password is committed to the repository | 2 | 2 | 100% |
| CI-007 | Gradle wrapper download is not checked against a SHA-256 | 7 | 7 | 100% |
| FLT-007 | Flutter biometric check only returns a boolean | 1 | 1 | 100% |
| FLT-008 | Flutter release build is not obfuscated | 1 | 1 | 100% |
| IOS-001 | App Transport Security is turned off | 6 | 2 | 100% |
| IOS-002 | An ATS exception allows plain HTTP to a host | 3 | 1 | 100% |
| IOS-004 | A server-trust handler accepts certificates without validating them | 8 | 1 | 100% |
| IOS-007 | No certificate pinning (needed for high-risk apps) | 9 | 8 | 100% |
| IOS-009 | Keychain item can migrate to another device | 6 | 4 | 100% |
| IOS-011 | Token or password stored in UserDefaults | 1 | 1 | 100% |
| IOS-012 | Biometric check only flips a boolean | 9 | 4 | 89% |
| IOS-014 | Web view inspection is on in release builds | 2 | 2 | 100% |
| IOS-015 | Script message handler doesn't check who sent the message | 5 | 3 | 100% |
| IOS-017 | Sign-in callback uses a custom URL scheme | 5 | 4 | 100% |
| IOS-018 | Insecure NSKeyedUnarchiver API | 2 | 1 | 100% |
| IOS-019 | App target has no privacy manifest | 3 | 3 | 100% |
| IOS-020 | Secret copied to the general pasteboard without localOnly | 4 | 3 | 100% |
| IOS-021 | Release build keeps symbols or testability | 1 | 1 | 100% |
| IOS-023 | Web view file-origin rules turned off through key-value coding | 1 | 1 | 100% |
| IOS-027 | Required-reason API used without a declared reason | 1 | 1 | 100% |
| IOS-028 | App Attest isn't integrated | 9 | 8 | 100% |
| IOS-030 | App never hides its screen in the app switcher or recordings | 4 | 4 | 100% |
| IOS-036 | App doesn't refuse third-party keyboards | 10 | 9 | 100% |
| KMP-004 | Ktor client logs headers or bodies in every build | 1 | 1 | 100% |
| XPL-002 | Google API key in code (restrict it in the console) | 3 | 2 | 100% |
| XPL-004 | AES in ECB mode, or with no mode named | 1 | 1 | 100% |
| XPL-005 | AES-CBC needs a separate MAC to detect tampering | 3 | 1 | 100% |
| XPL-009 | Hardcoded plain-HTTP URL | 1 | 1 | 100% |
| XPL-015 | PBKDF2 uses too few iterations | 2 | 2 | 100% |
| XPL-018 | Biometric check falls back to the device passcode | 7 | 6 | 100% |
| XPL-021 | No root or jailbreak detection found | 22 | 18 | 100% |
| XPL-022 | No debugger detection found | 23 | 19 | 100% |
| XPL-023 | RSA encryption uses PKCS #1 v1.5 or no padding | 2 | 1 | 100% |
| XPL-025 | MAC or signature compared with an ordinary equality check | 3 | 1 | 100% |
| XPL-027 | SecRandomCopyBytes result is not checked | 4 | 2 | 100% |
| XPL-028 | App never checks that the device has a screen lock | 12 | 9 | 100% |
| XPL-031 | Local database stores credentials without encryption | 2 | 1 | 100% |
| XPL-033 | Password or PIN field shows the typed text | 1 | 1 | 100% |
| XPL-036 | Staging, test, or private-network endpoint in release code | 24 | 6 | 100% |
| XPL-038 | No emulator detection found | 20 | 16 | 100% |
| XPL-039 | No hooking or instrumentation detection found | 23 | 19 | 100% |
| XPL-040 | App has no way to force an update | 21 | 17 | 100% |

IOS-012 is the one rule under 90%: one of its nine findings is a confirmation prompt before saving a
biometric-bound key, not an unlock check. The rule is marked *Check by hand*.

## Recall on apps with known weaknesses

Precision says how often a finding is real. Recall says how many real weaknesses masaudit finds. To
measure it, masaudit 0.5.0 scanned four public apps whose authors list the weaknesses they planted, as
banking apps:

| App (commit) | In scope | Found, 0.4.3 | Found, 0.5.0 |
|---|---|---|---|
| [OWASP MASTG demos](https://github.com/OWASP/mastg/tree/master/demos), Android (2eb0f709) | 53 | 33 | 52 |
| OWASP MASTG demos, iOS (2eb0f709) | 39 | 19 | 35 |
| [DIVA Android](https://github.com/payatu/diva-android) (2bb63b53) | 13 | 6 | 13 |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) (3c8cc3a3) | 14 | 9 | 13 |
| [DVIA-v2](https://github.com/prateek147/DVIA-v2) (96466ab8) | 14 | 3 | 13 |
| **Total** | **133** | **70 (53%)** | **126 (95%)** |

- **In scope** means visible in source or config. Runtime, reverse-engineering, server, dependency, and
  business-logic weaknesses are out of scope for a source scanner, as are MASTG demos of a passing app
  and repeats of the same sample with another tool.
- **Found** means a finding from a rule that targets that weakness, at its line or at the config that
  causes it.
- **Read the 95% with care.** The 0.5.0 rules and fixes were written from the 0.4.3 misses on these same
  apps, so this is recall on apps masaudit was tuned against, not a prediction for your code. They are
  also small, deliberately vulnerable samples.
- **MASTG demos are scanned in a normal app layout** (a manifest, `res/xml/`, symlinks resolved).
  Scanned as raw demo folders, 47 of 92 are found, mostly because a lone Kotlin file with no manifest
  gives too little context.

The 7 still missed, and why:

- **Keyboard caching of a name, email, or username field** (MASTG-DEMO-0076, InsecureBankv2, DVIA-v2):
  the rules cover password, PIN, card, and account fields only. Flagging every name field would bury
  the real ones.
- **MD5 or SHA-1 with no security purpose in sight** (MASTG-DEMO-0015, 0016): XPL-007 needs a password,
  signature, or token nearby, because most MD5 in real apps is a checksum or a cache key.
- **A person's name in a notification** (MASTG-DEMO-0078): XPL-032 covers one-time codes and balances;
  names appear in every messaging app's notifications by design.
- **A secret file excluded from iOS backup** (MASTG-DEMO-0019): IOS-046 treats `isExcludedFromBackup` as
  the fix, as the book does. MASTG fails the demo because exclusion isn't guaranteed.

## React Native precision

masaudit 0.6.0 adds React Native rules and teaches older rules to read JavaScript, TypeScript, and Expo
config, so it was measured on a second corpus: 10 open-source React Native apps, scanned from source as
they were on 2026-10-25, as banking apps. Mattermost, Rocket.Chat, Bluesky, Expensify, BlueWallet,
MetaMask, Rainbow, Joplin (`packages/app-mobile`), Standard Notes (`packages/mobile`), and Artsy (Eigen).

Three reviewers who didn't write the rules opened every finding that 0.6.0 adds to these apps, plus
every finding it removes. False alarms that a detector could avoid without missing real cases were
fixed, with a test fixture, and the apps were scanned again. In the table below:

- **Findings** are the open findings 0.6.0 adds, after those fixes.
- **Real** includes findings that are real but less risky than rated. 34 of the 57 are, mostly because
  these apps aren't money or health apps, or the page or data behind the finding is the app's own.
- **Removed:** 0.6.0 also stops 6 findings that 0.5.0 made on these apps: 4 for forced update and 2 for
  app-switcher protection. The apps use React Native libraries that 0.5.0 couldn't see. All 6 were false
  alarms.

| Rule | Title | Findings | Apps | Real | Precision |
|---|---|---|---|---|---|
| AND-007 | No certificate pinning (needed for high-risk apps) | 3 | 3 | 3 | 100% |
| AND-011 | WebView loads HTTP content inside HTTPS pages | 1 | 1 | 1 | 100% |
| AND-021 | Backup is on with no exclusion rules | 1 | 1 | 1 | 100% |
| AND-027 | R8 is off in the release build | 5 | 5 | 5 | 100% |
| IOS-007 | No certificate pinning (needed for high-risk apps) | 7 | 7 | 7 | 100% |
| IOS-009 | Keychain item can migrate to another device | 3 | 3 | 3 | 100% |
| RN-002 | Secret bundled into the app through build-time config | 5 | 2 | 5 | 100%\* |
| RN-005 | WebView can read local files | 2 | 2 | 2 | 100% |
| RN-006 | WebView may navigate to any origin or URL scheme | 4 | 1 | 4 | 100% |
| RN-007 | WebView loads a URL from navigation params or user input with no allowlist | 2 | 1 | 0 | 0%, *Check by hand* |
| RN-008 | WebView bridge trusts the page | 4 | 3 | 3 | 75%, *Check by hand* |
| RN-012 | React Native biometric check only returns a boolean | 4 | 3 | 4 | 100% |
| RN-014 | Over-the-air JavaScript updates are not signature-checked | 1 | 1 | 1 | 100% |
| RN-015 | JavaScript console output ships in release builds | 3 | 3 | 2 | 67%, *Check by hand* |
| RN-019 | npm dependencies can be swapped at the source or in transit | 4 | 3 | 4 | 100% |
| XPL-003 | Client or API secret is assigned a literal value | 2 | 1 | 2 | 100%\* |
| XPL-008 | Non-cryptographic or seeded random number generator | 1 | 1 | 0 | 0%, *Check by hand* |
| XPL-012 | Secret copied to the clipboard without the sensitive flag | 3 | 2 | 3 | 100% |
| XPL-015 | PBKDF2 uses too few iterations | 1 | 1 | 1 | 100% |
| XPL-018 | Biometric check falls back to the device passcode | 4 | 3 | 4 | 100% |
| XPL-034 | Analytics SDK receives personal data | 1 | 1 | 1 | 100% |
| XPL-036 | Staging, test, or private-network endpoint in release code | 2 | 2 | 1 | 50% (96% with the 19 apps) |
| **Total** | | **63** | | **57** | **90%** |

Four of the five rules under 90% are marked *Check by hand*; XPL-036 isn't, because it is at 96% across
both corpora. Deciding these findings needs knowledge of the app that a source scanner doesn't have:

- **RN-007:** both WebView screens take their URL from navigation params, but the app only ever opens
  them with fixed URLs, and no deep link reaches them.
- **RN-008:** a message handler with no origin check only shows a toast. A fake message changes nothing.
- **RN-015:** the console calls are in a debugging helper that nothing calls.
- **XPL-008 and XPL-036:** a `Math.random` cache-busting parameter, and a design-tool URL that only a
  build-time flag includes.

\* Expensify's partner password (2 findings each for RN-002 and XPL-003) split the reviewers. One judged
it a real credential that ships in the app, at low risk. The other judged it a public client identifier,
since every Expensify client sends it. It counts as real here; counted as false, RN-002 would be at 60%
and XPL-003 at 0%.

## React Native recall

masaudit 0.6.0 scanned three public React Native apps whose authors list the weaknesses they planted,
as banking apps. 0.5.0 read only their native folders.

| App (commit) | In scope | Found, 0.5.0 | Found, 0.6.0 |
|---|---|---|---|
| [Deliberately Insecure React Native App](https://github.com/atomicsecurity/deliberately-insecure-react-native-app) (661401bd) | 17 | 5 | 13 |
| [Damn Vulnerable React Native](https://github.com/waseeq14/Damn-Vulnerable-React-Native) (8180663c), three variants | 4 | 0 | 4 |
| [React-Native-CTF](https://github.com/MateuszMatyska/React-Native-CTF) (9e1d309d) | 7 | 1 | 4 |
| **Total** | **28** | **6 (21%)** | **21 (75%)** |

- **Out of scope:** a dependency with a known CVE (masaudit has no vulnerability database; use
  OSV-Scanner or `npm audit`), and an authorization check that the server skips.
- **Read the 75% with care,** as with the native recall above: the 0.6.0 rules were written with these
  apps in view, and they are small, deliberately vulnerable samples.

The 7 still missed, and why:

- **Sample keys marked `EXAMPLE`** (`AKIAIOSFODNN7EXAMPLE`): placeholder values are dropped on purpose,
  because documentation and sample code are full of them.
- **A JWT decoded with `atob` and trusted without checking its signature:** no rule yet.
- **A token read from storage and sent over plain HTTP:** the cleartext setting is flagged, but the
  flow from storage to the request needs data-flow analysis.
- **An exported main activity with browsable `http` and custom-scheme filters:** most React Native apps
  have one. The risk is what the app does with the link, which RN-009 checks, so the filter alone isn't
  flagged.
- **Names (not tokens) in AsyncStorage through a wrapper with a variable key:** RN-001 covers tokens and
  passwords only.
- **A deep link handled in another file that navigates to a screen:** RN-009 follows data within one
  file.
- **A PIN compared with a hardcoded base64 value in a Java native module:** XPL-043 doesn't decode
  base64.

## Speed

Every app in the corpus scans without a crash. End-to-end times for the largest, as a banking app (so
every rule runs), on an Apple M5 laptop with Python 3.14, version 0.6.0 (best of three runs):

| App | Files | Time |
|---|---|---|
| Signal (Android) | 9,530 | 5.5 s |
| DuckDuckGo (Android) | 10,011 | 5.2 s |
| Lichess (Flutter) | 7,885 | 4.0 s |
| Signal (iOS) | 3,741 | 4.4 s |
| Expensify (React Native, 107 MB of JavaScript) | 11,420 | 14.0 s |
| MetaMask (React Native) | 16,845 | 9.0 s |
| Mattermost (React Native) | 3,964 | 2.7 s |

JavaScript apps take longer per file: their source files are larger, and more than 50 rules read them.

Crafted inputs are a known risk for a scanner that reads code it doesn't trust, so the parsers are
fuzzed in CI, and tests rebuild every slow input found so far (thousands of nested blocks, unclosed
brackets, huge single lines, xcconfig files that include each other many times) and check that each
scans in well under a second. Audits since 0.6.0 found 18 such inputs that took from 3 seconds to
hours; more may exist in code no audit has reached. `scripts/benchmark.py` times a scan per rule.

## What this doesn't measure

- **Recall on real apps.** The recall apps above are deliberately vulnerable samples. No scanner sees
  server behavior, runtime state, or business logic, which is where many breaches happen. Every report
  has a *Residual risk* section for that reason.
- **Flutter and Kotlin Multiplatform rest on a small corpus.** Two Flutter apps (Lichess, Immich) and
  one KMP app (KotlinConf) were reviewed, so the FLT and KMP precision numbers come from few findings.
  Their fixtures cover more forms than the corpus does, but expect more false alarms there than on
  Android or iOS.
- **Your app is not the corpus.** If a rule is wrong for your code, a
  [false-positive report](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml)
  is the most useful contribution you can make.
