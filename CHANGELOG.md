# Changelog

All notable changes, newest first. Versions follow [SemVer](https://semver.org/); the rules have
their own version (`rules_version`), shown in every report.

## 0.5.0 — 2026-10-25

**Rules 2.1.0: 15 new rules (187 in total) and fixes to 20 existing ones.** Recall on apps with
planted weaknesses (OWASP MASTG demos, DIVA, InsecureBankv2, DVIA-v2) went from 70 to 126 of the 133
that a source scanner can see. The new and changed rules were written from those misses, so expect
less on unseen code; [Accuracy and speed](docs/precision.md#recall-on-apps-with-known-weaknesses) has
the method and every remaining miss. On the 19-app precision corpus they add 3 findings, all real, and
remove none.

- **New Android rules:** SSLSocket without a host-name check (AND-073), keystore keys unlocked long
  after authentication (AND-074), WebView that opens any URL (AND-075), sensitive fields the keyboard
  learns (AND-076).
- **New iOS rules:** sensitive fields the keyboard learns (IOS-043), sockets without TLS (IOS-044), a
  password field inside web-view HTML (IOS-045), secret files backups copy (IOS-046), hosts missing
  from `NSPinnedDomains` (IOS-047, *Check by hand*).
- **New cross-platform rules:** hardcoded credential checks and backdoors (XPL-043), secrets written to
  plain files (XPL-044), tokens taken from the clock (XPL-045), HTML injection in web pages (XPL-046),
  native buffer overflows from Java input (XPL-047), page data read in the page's own JavaScript world
  (XPL-048).
- **Fixed misses in existing rules,** for example: `MASTestApp` or `Contest` was taken for a test
  build; accept-all trust after a `guard let` unwrap; multi-line weak-TLS calls; bare
  `addJavascriptInterface`; plain tokens in a file that encrypts something else; cleartext and file
  access allowed by old targetSdk defaults; keys reaching `SecretKeySpec` through a helper; weak
  PBKDF2 through a wrapper; Core Data, Realm, and raw-SQL password columns.
- **False alarms removed:** a boolean extra named like a PIN, NSFileProtection comparisons, pinning
  done in an NSURLConnection delegate, a DOM read reported as a write, and `android:password="true"`
  fields.
- **Android projects are detected from their imports** when there is no manifest or Gradle file.
- **`.html` pages and Core Data models are scanned.**
- `scripts/corpus.py` downloads the precision corpus at fixed commits, scans it, and compares scans.

- **Colors work in the terminal.** Since 0.1.0, the summary printed color codes as text (` [1m`)
  instead of colors: text cleaning ran after coloring and removed the escape character. Text from
  the scanned project is now cleaned before colors are added, and it still can't add its own.
- **GitHub Action job summary:** the run's page shows the app type, the verdict, and the top fixes.
- **Skipped files are reported.** Source and config files left out for safety (over the size limit,
  hard links, symbolic links out of the folder, FIFOs, unreadable files, the 200,000-file cap) are
  listed under *Residual risk*, so a skipped manifest never looks clean.
- **At most 50 findings per rule per file,** with a note giving the total, so a generated or crafted
  file can't flood the report or the SARIF upload.
- **SARIF paths are percent-encoded** (spaces, `#`, `%`, non-ASCII), as URI references must be.
- **README demo GIF,** recorded from this release with `scripts/demo.tape`.
- **Release:** the GitHub release is created with `gh release create` instead of a third-party
  action.
- **Repository hygiene:** test fixtures use a placeholder for the fake Google API key, and the
  deliberately old dio in a fixture is marked as test data for OSV-Scanner and Scorecard.

## 0.4.3 — 2026-10-24

From an independent audit before launch (newcomer walkthrough, docs against code, production
readiness).

- **GitHub Action:**
  - Paths in code scanning and annotations are now relative to the repository root when `path` is a
    subfolder. Before, alerts in a monorepo pointed at files that don't exist.
  - New `category` input (default `masaudit`). SARIF no longer sets `automationDetails`, whose ID
    changed with the detected platforms and overrode the upload category. Alerts from 0.4.2 and
    earlier were filed under `masaudit/<platforms>`; close them once, after your first 0.4.3 scan.
  - `fail-on: none` never fails on findings, even when `.masaudit.ini` sets `fail_on`.
  - `fail_on` is read by masaudit itself, so `FAIL_ON = low` or an empty value behaves as it does
    locally.
  - A tool error (exit code 2) fails the scan step with an error annotation, instead of a later,
    unrelated upload error.
- **Safety:**
  - A FIFO or device file in the scanned folder can no longer hang the scan.
  - `--fix-safe --yes` refuses to run `git status` when the folder's own `.git/config` sets a filter
    or diff command, which git would run.
- **Fixes:** `--explain AND-002` says the safe fix applies to `AndroidManifest.xml` only; the `.pyz`
  hint says `py` on Windows; `--help` says baselined findings are accepted, not ignored.
- **Docs:** the README and the tutorial show the paths without AI and with AI side by side; the
  tutorial explains the clue and what to do when the question doesn't appear; Windows `.pyz`
  commands use the full path; many corrections from checking every claim against the code.
- **Release:** the release fails if the tag doesn't match the version; the GitHub release waits for
  the approved PyPI upload; the release `.pyz` is byte-identical to the skill's bundled copy;
  setuptools 84.1.0 for the build (GHSA-xmj3-9gf7-h52w); Dependabot watches the pinned Python tools.
- **Packaging:** the full CC BY-SA 4.0 legal text, the license expression in the plugin and
  citation, and documentation, source, issue, and changelog links on PyPI.

## 0.4.2 — 2026-10-24

- **Documentation reorganized** by what you need: a tutorial on the demo app, how-to guides (app
  type, fixing, CI, team, AI assistants), reference pages (install, command line, config file,
  output formats, rules), and explanations (how it works, accuracy and speed). Old `docs/usage.md`
  links still work.
  - New reference topics: every way to install and upgrade, environment variables, skipped folders
    and files, the SARIF severity mapping, and the `--fail-on` default.
  - Corrected: the report ends with the AI fix plan, not *Residual risk*; the pre-commit hook always
    passes `--fail-on high`; `app_type_reviewed` silences that type even for new evidence.
- **GitHub Action: new `baseline` input,** so older apps can fail CI only on new findings.
- **The terminal's "Next" hint names the command you ran:** `uvx masaudit` or `pipx run masaudit`
  instead of `masaudit`, which isn't on your PATH under uvx or pipx run.
- **The `--fix-safe` hint appears only when a safe fix would change a file.** It no longer appears
  for a debuggable release build in Gradle, which masaudit never edits.

## 0.4.1 — 2026-10-24

- **Check your app type.** When the code suggests a riskier app type than the one chosen, masaudit
  warns instead of switching silently.
  - The warning names the evidence, the type that fits, how many checks the choice skips on this
    project's platforms, and which findings it hid under *Not needed*.
  - It shows in the terminal, at the top of the report, in JSON (`profile.warnings`), in SARIF
    (`toolConfigurationNotifications`), and as a GitHub Actions annotation on the evidence file. The
    first-run question offers to switch.
  - Evidence that changes nothing stays a quiet clue: a payment SDK in a news app runs the same checks.
  - `app_type_reviewed` in `.masaudit.ini` silences a suggestion the team reviewed and decided against.
- **Clues are evidence, not words.**
  - Clues are read only from shipping code, never tests, sample apps, or comments, and matched by
    package, import, pod, or Flutter package name.
  - New kinds: payment SDKs worldwide, Google Pay and Apple Pay, open banking, identity verification,
    MDM, game engines, and smart-home APIs.
  - False clues found on 19 real apps are gone: a view controller named `cvc`, "paypal" in a list of
    websites, Android Auto in a podcast player, and `.pkpass` attachments shown in a messenger.
  - Biometric and attestation clues are removed; their rules already report what matters.
- **About 3x faster.** Signal for Android went from 17.5 s to 5.6 s end to end, with identical
  findings on all 21 test apps.
  - The lexer is 9x faster, proven identical on 41,583 files and 280,000 fuzzed inputs.
  - One shared needle index answers the literal prefilters of most rules.
  - Patterns that defeated the regex engine now jump between literals.
- **Fixed slow paths a crafted repository could trigger:**
  - code files that took 5 seconds to 4 minutes each;
  - build scripts with cubic cost;
  - a workflow parser and a comment stripper that were quadratic.

  All are linear now, with tests.
- **Fixed:** on Windows, patterns broke on files with CRLF line endings. Every rule fixture now also
  runs with CRLF in CI.
- **Docs:** a shorter README with a quick start on the first screen, real terminal output, and a
  corrected accuracy section; new [usage](docs/usage.md) and [CI](docs/ci.md) guides; speed numbers
  in docs/precision.md. A test keeps the README's numbers in sync with the code.
- The "assumed general app" note now says MAS-L1+P, as it has been since 0.2.0. Shared text helpers
  moved to `textscan.py` and `guards.py`; `scripts/benchmark.py` times a scan per rule.

## 0.4.0 — 2026-10-24

**172 rules, up from 77, measured on 19 real apps.** (79 rules fired on those apps and were reviewed;
the rest are checked by their test fixtures.)

- **New rules:**
  - 32 Android (AND-035 to AND-065, AND-072), 21 iOS (IOS-022 to IOS-042), and 32 cross-platform
    (XPL-011 to XPL-042).
  - 6 Flutter (FLT-003 to FLT-008), 3 KMP (KMP-004 to KMP-006), and AND-034.
  - They cover hardcoded keys, tokens in plain preferences, broken ciphers, weak key derivation,
    Zip Slip, Dirty Stream, debug tools and DEBUG code in release, privacy manifests and
    required-reason APIs, IDFA without ATT, screenshot and overlay protection, and more.
  - First MAS-R rules: Play Integrity, App Attest, R8 keep rules, and root, debugger, emulator, and
    hooking detection. They apply only to banking, identity, loyalty, and game apps.
- **OWASP coverage:** 52 of the 78 MASWE weaknesses (was 29), and 132 MASTG tests cited (was 55).
- **Precision:**
  - Two rounds of review on Signal, Bitwarden, Wikipedia, Nextcloud, Element, DuckDuckGo,
    Thunderbird, and 12 more apps. The second round was independent of the builders.
  - Every false positive was fixed with a test fixture. Every rule is now at 90% precision or better
    on that corpus, or marked *Check by hand*. See docs/precision.md.
  - Biggest fixes: exported components that must be public (share targets, media services, widgets),
    SQL built only from app-owned values, random numbers outside security code, comments that
    silenced the pinning check, and CI findings ranked by who owns an action.
- **Smarter scope:**
  - Exact test folders and case-sensitive test file names (ABTest.kt is production code).
  - Debug-only code under `BuildConfig.DEBUG`, `#if DEBUG`, or `kDebugMode`, and non-release
    Gradle variants and internal modules.
  - Xcode shipping configurations read from each scheme's archive action.
- **Acknowledged findings:** Android Lint `tools:ignore`, lint.xml, and zizmor.yml policies are
  shown one level lower, with the reason from the source. They are never dropped.
- **More files:** large Xcode project files (up to 16 MiB), C/C++, storyboards, xibs, podspecs, shell
  scripts, and Fastfile.
- **Breaking:** severities and buckets changed for many rules, so `rules_version` is 2.0.0. Baselines
  made with 0.3.0 still load, but some findings now show as new.

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
