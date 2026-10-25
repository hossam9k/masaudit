[masaudit documentation](README.md) › Accuracy and speed

# Accuracy and speed

Developers ignore a scanner that raises many false alarms, so the maintainers measure every rule on
real apps before each release.

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
them.

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

## Speed

Every app in the corpus scans without a crash. End-to-end times for the largest, as a banking app (so
every rule runs), on an Apple M5 laptop with Python 3.14, version 0.4.1:

| App | Files | Time |
|---|---|---|
| Signal (Android) | 9,528 | 5.6 s |
| DuckDuckGo (Android) | 9,998 | 5.6 s |
| Lichess (Flutter) | 7,885 | 4.6 s |
| Signal (iOS) | 3,741 | 4.3 s |

Crafted inputs can't make a scan slow: the parsers are fuzzed in CI, and tests check that files built
to trigger worst cases (thousands of nested blocks, unclosed brackets, huge single lines) still scan in
linear time. `scripts/benchmark.py` times a scan per rule.

## What this doesn't measure

- **Recall on real apps.** The recall apps above are deliberately vulnerable samples. No scanner sees
  server behavior, runtime state, or business logic, which is where many breaches happen. Every report
  has a *Residual risk* section for that reason.
- **Your app is not the corpus.** If a rule is wrong for your code, a
  [false-positive report](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml)
  is the most useful contribution you can make.
