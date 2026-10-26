# Changelog

All notable changes, newest first. Versions follow [SemVer](https://semver.org/); the rules have
their own version (`rules_version`), shown in every report.

## Unreleased

### Docs

- [Benchmark on unseen apps](docs/benchmark.md), round 2: 0.6.3 on 18 more apps no rule was tuned on.
  45% of the sampled app-code findings were false alarms (35% without one outlier file), worse than
  round 1; CI findings held up. The page lists the causes, the next release's work list.
  `scripts/benchmark_compare.py --round 2` repeats it.

## 0.6.3 — 2026-10-26

**Fewer false alarms and more found, measured on apps no rule was tuned on.** Rules 2.2.3. A new
[benchmark](docs/benchmark.md) scanned 21 unseen apps with masaudit, mobsfscan, Semgrep, and rnsec: about
1 in 4 of 0.6.2's app-code findings there were false alarms, against 1 in 10 on the tuned corpus. This
release fixes the causes it found, and the gaps the 0.6.2 fixtures turned up. Every change has a test;
on the 29-app corpus it removed only false alarms, and a baseline from 0.6.2 leaves nothing new open.

### False alarms fixed (from the 0.6.2 fixtures)

- KMP-003 counted only OkHttp's `CertificatePinner` as Android pinning. An unexpired `<pin-set>` in the
  network security config, which Android enforces for OkHttp and Ktor, now counts too.
- FLT-002 no longer flags `setString('locale', x).then((_) => refreshToken())`: the value now ends at the
  call's own `)`.

### Missed cases now found

- iOS:
  - IOS-003: Swift's `tlsMinimumSupportedProtocol`, Objective-C's `TLSMinimumSupportedProtocolVersion`,
    and a TLS maximum below 1.2.
  - IOS-033: the deprecated `sec_protocol_options_set_tls_min_version`.
  - IOS-023: the preference name held in a constant, and `true as NSNumber`.
  - IOS-031: Objective-C folder arguments built from nested messages.
  - IOS-032: Objective-C `openURL:` and Handoff handlers, and a host block-list, which isn't an
    allowlist.
  - IOS-035: an encoded object written straight to the App Group container.
  - IOS-040: a declared subdomain no longer covers its siblings (`api-eu.mixpanel.com` isn't
    `api.mixpanel.com`).
  - IOS-043: one view's `.autocorrectionDisabled()` no longer hides fields in other views (a view
    that contains the field still covers it).
  - IOS-044: the C Network.framework API with TLS turned off.
  - IOS-045: an HTML constant read through `Self.` or a type name.
  - IOS-046: one write excluded from backup no longer hides another write in the same file.
- Flutter:
  - FLT-001: static methods and closure variables that accept every certificate.
  - FLT-002: values across commas, such as `jsonEncode({... 'token': ...})`; and a push or device
    word now clears only that word.
  - FLT-004: webview_flutter_android's `setAllowFileAccess(true)` with JavaScript on.
  - FLT-005: the `InAppBrowser` subclass override.
- Kotlin Multiplatform:
  - KMP-002: fully qualified names in sub-packages.
  - KMP-004: a log level held in a constant.
  - KMP-005: each challenge handler is judged on its own, so a file where one function evaluates trust
    and another doesn't is reported.

### False alarms found by the benchmark

Each has a test; on the 29-app corpus the change removed only false alarms.

- Code that only runs in the IDE's preview counts as debug code: Jetpack Compose functions annotated
  `@Preview` (or a multi-preview annotation), SwiftUI `#Preview` blocks, and `PreviewProvider` structs;
  so do `mock`, `fake`, and `stub` folders in a shipping source set.
- IOS-019 skips a sample or demo Xcode project (SampleBrowser, ExampleApp) next to the real app.
- CI rules skip jobs switched off with `if: false`; CI-005 counts a Gradle task that pushes tags
  (`reckonTagPush`) as a push.
- IOS-017 rates a sign-in callback low when `ASWebAuthenticationSession`, FlutterWebAuth2, or the app's
  own web view receives it: no other app can catch the code, though one can still start a sign-in as
  yours. A redirect that goes through the OS keeps its severity.
- AND-045 reports screen protection as unknown, not missing, when a local Flutter package outside the
  scanned folder could set `FLAG_SECURE`.
- AND-050 no longer reports BouncyCastle added with `addProvider`, which puts it last; only
  `insertProviderAt(…, 1)` replaces the platform's provider.
- XPL-045 no longer reports a time passed into a function, such as a TOTP code; a hash of the time still
  counts. XPL-034 ignores enum cases and constants that name an event (`.addressAutofillPromptShown`).
- IOS-015 skips empty or log-only handler stubs; AND-015 accepts Wear OS complication and watch-face
  settings screens, which the system opens.

### Speed

- SARIF import checks whether a result's path is inside the scanned folder by name before looking it up.
  Another machine's paths (`/home/runner/...`, an automount on macOS) cost about 2 ms a result to look
  up, so a 20,000-result file took about 40 seconds.
- Debug-guard checks (`if (kDebugMode)`, `assert(...)`) and FLT-004's settings lookup read an index built
  once per file instead of rescanning the code before every hit; on crafted Dart files with thousands of
  hits that took 0.5 to 0.7 s on Python 3.9, and now under 0.1 s.
- AND-046 and AND-076 look up a button's or field's later settings from one pass per file. A file with
  thousands of buttons or text fields took 0.7 to 0.8 s (4 s on a slow CI runner); it now takes 0.2 s.

### Docs

- [Benchmark on unseen apps](docs/benchmark.md): masaudit, mobsfscan, Semgrep, and rnsec on 21 apps no
  rule was tuned on, with a judged sample and every loss; `scripts/benchmark_compare.py` repeats it.

IOS-022 still checks Podfiles and imports only: a Swift package is linked only when code imports it, and
the import check covers that.

## 0.6.2 — 2026-10-26

**Fixes from a third audit, aimed at the code the first two reached least:** iOS build settings, Flutter,
Kotlin Multiplatform, `--fix-safe`, SARIF import, and the workflow reader. Rules 2.2.2. On the 29-app
corpus (19 native, 10 React Native) every finding is unchanged, with the same fingerprints, so a baseline
from 0.6.1 keeps working.

### Crashes and hangs

- **A lone UTF-16 surrogate stopped every report** (exit 2). An Xcode project string such as `"\UD800"`
  decoded to one, and JSON, SARIF, and Markdown output couldn't encode it. Such characters are now
  replaced in every snippet, message, imported SARIF result, and file masaudit writes, and in terminal
  output. A file whose name isn't valid UTF-8 is skipped and listed under *Not scanned*.
- **xcconfig files that include each other many times** were re-read for every path through the includes:
  nine files with six includes each took 12 seconds, and more never finished. Each file is now resolved
  once per configuration, with at most 500 files. The result is the same, including where the depth limit
  and include cycles cut the chain.
- **Nine more crafted inputs** took 3 to 17 seconds on a 200 KB file and now take under 0.5 s: FLT-001,
  FLT-002, FLT-003, FLT-004, and FLT-005 (callback references, constant keys, nested calls and closures),
  KMP-004 (nested `install(Logging)` blocks), KMP-006 and Android `putString` with thousands of constant
  keys, and a 200 KB xcconfig that includes itself. `--fix-safe` on a manifest with thousands of comments
  took hours and now takes 0.01 s. Each rewrite gives the same results as before; tests compare the two.
- A deeply nested SARIF file or baseline gives a clear error instead of "internal error".

### Safety

- `--fix-safe --yes` writes the manifest the way reports are written: a new file replaces it, so a link
  planted at that path is never written through. The file keeps its permissions.
- Saving the app type replaces a hard-linked `.masaudit.ini` instead of reading it.
- The Kotlin and Java files masaudit reads to detect Android skip links, like every other read.

### Accuracy

- **`exclude` now applies to files masaudit reports by name without reading them:** keystores (CI-006),
  private key files (XPL-019), and source maps (RN-017). A lockfile or privacy manifest in an excluded
  folder still counts as present (CI-008, IOS-019). When a project has more than 200,000 files, the report
  says the name listing stopped, and CI-008 and IOS-019 don't report a file missing.
- **YAML anchors in workflows:** `permissions: *defaults` and `- *checkout` now stand for what the anchor
  marks, as GitHub reads them, so CI rules see aliased permissions and steps. Aliases can add at most 5,000
  nodes per file and nest 32 levels, so a file of aliases to aliases can't stall the scan. An unclosed `[`
  or quote in a workflow no longer hides the rest of the file.
- **SARIF import:** results for files outside the scanned folder are skipped with a note instead of being
  reported with another machine's path; a relative path under another machine's `%SRCROOT%` is read
  against the scanned folder. The 20,000-result limit now covers all runs in a file, and each source file
  is read once.
- False alarms fixed, each with a fixture: FLT-002 on constant values such as
  `setString('token_type', 'Bearer')`; FLT-008 on `--obfuscate` written on the next line of a folded
  (`run: >`) command; IOS-026 when the prompt is requested from Objective-C; IOS-040 on links to a
  vendor's help or docs site; IOS-042 on `options &= ~XML_PARSE_NOENT`; IOS-043 counted a text field built
  in a closure twice.
- Reports list the iOS notes in the same order on every run.

### Tests and docs

- 31 thinly tested Flutter, KMP, and iOS rules have a second vulnerable case and a near miss each.
- The fuzzer covers the Flutter and KMP rules, xcconfig includes, and the SARIF importer.
- [Accuracy and speed](docs/precision.md) says how small the Flutter and KMP corpus is, and that crafted
  slow inputs are fixed as audits find them rather than ruled out.
- Bug-report and pull-request templates, and CODEOWNERS.

## 0.6.1 — 2026-10-25

**A security fix for the GitHub Action, and fixes from a five-part audit of 0.6.0** (code, safety,
docs, release, and a newcomer's first run). If you run the Action on pull requests, update to v0.6.1.

### Security

- **The Action could run code from the repository it scanned.** Its Python calls ran from the checkout,
  so a pull request that added a `masaudit/` folder or a `json.py` replaced the scanner or the standard
  library: it ran with the job's token and could pass the `fail-on` gate. Every call now runs in
  Python's isolated mode with the Action's own source. CI scans a checkout with both files planted.
- **Files masaudit writes inside the scanned folder no longer follow links.** A symbolic link planted as
  `SECURITY-AUDIT.md`, the baseline, or `.masaudit.ini` made masaudit overwrite the file it pointed to.
  The link is now replaced by a new file, and a FIFO or device there is refused. A linked `.masaudit.ini`
  isn't read, so an error message can't print a line of another file.
- **Secrets next to a secret-like name are masked in every snippet,** whichever rule matched the line:
  `clientSecret = "..."`, `password=...` inside a string, `setItem('password', '...')`. Before, only the
  value the rule matched was masked, so a second secret on the line showed. Baseline fingerprints don't
  change.
- **File and folder names with control characters are skipped and listed under *Not scanned*.** A
  folder name with a newline could print a forged line, such as a GitHub `::error` command.
- **`--fix-safe --yes` ignores git submodules,** whose own config could make `git status` run a command.
- **A symbolic link to a hard link is treated as a hard link** (skipped), and a folder that can't be read
  is listed under *Not scanned* instead of being left out silently.

### React Native and Expo

- **Managed Expo apps get the protection checks.** With no `android/` or `ios/` folder, root, debugger,
  emulator, and hooking detection, forced update, screen lock, screenshot and overlay protection, Play
  Integrity, App Attest, third-party keyboards, and R8 were listed under *Checked, nothing found*. They now
  run on the app config (R8 reads expo-build-properties), and the report says that the native checks saw
  only the config, with `npx expo prebuild` for a full check.
- RN-001 treats a write inside `if (__DEV__)` as debug code.
- react-native-device-attest counts as attestation (AND-048, IOS-028, XPL-021).
- The fixes for AND-045, AND-046, AND-048, IOS-028, IOS-030, IOS-036, and XPL-021, XPL-022, XPL-038, and
  XPL-039 say what to use in React Native. XPL-029 is now "App code writes a secret into the WebView's DOM",
  since it also reads JavaScript.
- `minSdkVersion rootProject.ext.minSdkVersion`, as the React Native template writes it, is read from the
  root `ext` block instead of being reported as a value masaudit can't resolve.

### Fixes

- A Kotlin or Java string holding `putString(...)` sample code stopped the scan (exit 2).
- A form feed, U+0085, or U+2028 in a file shifted every later snippet and inline suppression by a line.
- **The baseline doesn't cover a new copy of an accepted line.** Two identical lines shared one
  fingerprint, so a pasted copy of a baselined weakness was accepted too. Each copy now has its own
  fingerprint. A baseline written before 0.6.1 keeps covering every identical line until
  `--update-baseline` rewrites it, so upgrading turns no accepted finding new.
- AND-027 reports an app module that never sets `isMinifyEnabled`: the Android Gradle plugin leaves R8 off
  by default. Flutter apps and convention plugins that set it are left alone.
- A Kotlin or Java file in a shipping source set is no longer treated as a test because its name ends in
  `Test` or `Spec`, and an iOS or JavaScript folder named Catalog, Internal, or Showcase is no longer
  treated as debug code.
- Suppressed and baselined findings no longer also appear under *Checked, nothing found*.
- Keeping your app type at the first-run question records the suggested type as reviewed, so the warning
  doesn't repeat. Saving the type replaces an existing `app_type` line instead of adding a second one, and
  a `.masaudit.ini` with a byte-order mark (Windows Notepad) is read.
- Reports say "an ecommerce app", and iOS findings name the app, not the `ios` folder.
- A malformed SARIF import and a baseline path that can't be written give a clear error instead of
  "internal error".

### Speed

Five crafted inputs took 25 seconds to hours on a 200 KB file; each now scans in under a second: a run of
`#` in Swift, `Math.random(` repeated on one line (Java, Dart), unclosed and nested calls in Kotlin, spaces
after a Gradle block name, and blank lines in an xcconfig. A test scans each one.

### Packaging and docs

- `masaudit.pyz` and the Claude Code plugin include the license texts.
- The release checks that the wheel holds every module and scans a React Native fixture before publishing.
- The fuzz job covers the React Native parsers.
- The skill points to `fixes-react-native.md`. The docs say which tests aren't reported, how a managed Expo
  app is checked, and that commands written as `masaudit` run as `uvx masaudit` with uv.

## 0.6.0 — 2026-10-25

**React Native, JavaScript and TypeScript included. Rules 2.2.0: 20 new React Native rules (207 in
total), and 32 cross-platform rules that now read JavaScript and TypeScript.** Until 0.5.0, masaudit
scanned only a React Native app's `android/` and `ios/` folders. Now it reads the app's JavaScript,
TypeScript, `package.json`, Expo config, and bundled `.env` files too, and a managed Expo app with no
native folders gets the Android and iOS checks that apply to its `app.json`. Independent reviewers
judged every finding the change adds to 10 open-source React Native apps: 57 of 63 are real (90%).
RN-007, RN-008, RN-015, and XPL-008 are under 90% there and marked *Check by hand*; XPL-036 is at 96%
across both corpora. Recall on three deliberately vulnerable React Native apps went from 6 to 21 of 28.
The 19-app native corpus doesn't change. [Accuracy and speed](docs/precision.md#react-native-precision)
has the tables.

- **New React Native rules (RN-001 to RN-020):**
  - Storage and secrets: tokens in AsyncStorage, unencrypted MMKV, or redux-persist (RN-001); secrets
    bundled through `.env`, `EXPO_PUBLIC_` variables, `@env`, or Expo `extra` (RN-002).
  - Network: request and response logging in release (RN-003); JS networking that accepts any
    certificate (RN-004); npm dependencies taken from a git branch, a plain-HTTP address, or `*`, and registries over HTTP or
    with TLS checks off (RN-019).
  - WebView: local file access (RN-005); any origin or URL scheme allowed (RN-006); a URL from
    navigation params or user input with no allowlist (RN-007, *Check by hand*); a bridge that trusts
    the page (RN-008, *Check by hand*).
  - Platform: deep-link data reaching `openURL`, `fetch`, a WebView, or navigation (RN-009); `eval` and
    `new Function` on strings (RN-010); SQLite queries joined from strings (RN-011); native modules that
    run a shell command or open a path sent from JavaScript (RN-020).
  - Auth and crypto: a biometric check that only returns a boolean (RN-012); crypto-js deriving the key
    from a passphrase string (RN-013).
  - Build and release: unsigned over-the-air updates through CodePush or expo-updates (RN-014),
    console output in release (RN-015, *Check by hand*), Hermes turned off (RN-016), a source map inside the app
    (RN-017), and debug tooling that connects in release builds (RN-018).
- **32 cross-platform rules read JavaScript and TypeScript,** among them hardcoded secrets and keys
  (XPL-001 to XPL-003, XPL-011), plain HTTP and WebSocket URLs (XPL-009), secrets in logs and on the
  clipboard (XPL-010, XPL-012), weak crypto and randomness (XPL-004, XPL-006 to XPL-008, XPL-013 to
  XPL-016, XPL-045), staging endpoints (XPL-036), OAuth flows (XPL-037), and HTML injection (XPL-046).
  The absence rules (root, debugger, emulator, and hooking detection, forced update) count React Native
  libraries and calls as evidence.
- **Android and iOS rules understand React Native and Expo:** pinning libraries count as pinning
  (AND-007, IOS-007); react-native-keychain and expo-secure-store accessibility classes (IOS-008,
  IOS-009); WebView props in JSX (AND-011, AND-013, IOS-014); and a managed Expo app's `app.json` for
  cleartext, backup, permissions, App Transport Security, and the privacy manifest. Fixes for these
  rules now say what to change in a React Native or Expo app.
- **A comparison with rnsec,** a React Native scanner, rule by rule: of its 105 rules, 61 are covered,
  14 in part, and 30 left out on purpose. See [Compared with rnsec](docs/compare-rnsec.md).
- **Foundations for JavaScript:**
  - The lexer handles template literals with nested `${...}`, regex literals, and JSX text, so strings
    and comments are found correctly in ordinary React Native files. It is checked against a reference
    implementation on 600,000 fuzzed inputs.
  - React Native is detected only from a `react-native` or `expo` dependency in `package.json`. Before,
    any Node project with an `index.js` counted.
  - Jest, Detox, and Maestro tests, mocks, and Storybook stories are scoped as test or debug code; code
    inside `if (__DEV__)` counts as debug code; a backend in `server/` or `backend/` isn't scanned as app
    code. `.expo`, `dist`, `web-build`, and `coverage` folders are skipped.
  - `.jsx`, `.mjs`, `.cjs`, `.env`, `.npmrc`, and `.yarnrc` files are read.
- **Faster on large JavaScript apps:** several app-type clues and evidence checks start with their
  literal text, which Python's regex engine finds faster. Expensify (107 MB of JavaScript) scans in about
  14 seconds instead of 21.
- **Hardening from an independent code review:** an `app.json` with a number or an object where Expo
  expects a list no longer stops the scan; `!(__DEV__)` and `false === __DEV__` count as release code; a
  Kotlin package or Swift group named `e2e` or `jest` is no longer taken for tests; and two checks that a
  minified file could make quadratic are linear again (one of them, the test-import check, predates
  0.6.0). From the final review: a native `stories` folder (a Stories feature) is no longer taken for
  Storybook and lowered as debug code; lower-case test source sets such as `src/androidtest/` count as
  tests; a JWT secret is found even when a variable named like a secret comes first in the file; an
  array literal nested hundreds of levels deep no longer stops the scan; and a long run of spaces after
  `import` no longer slows the import reader. The cache that pairs brackets in a large file was pushed
  out by short texts asked about in between, so some crafted 200 KB files took 1.7 seconds; they now
  take 0.3. The lexer finds where a regex literal ends with a few searches instead of stepping through
  each character class, so a file of unclosed `/[` lexes 3 to 6 times faster, with the same result.
- **False alarms removed after the independent review:** Apple's documented `http://maps.apple.com`
  link is not plain-HTTP traffic (XPL-009); mixed-content mode on a WebView showing inline HTML with no
  https base (AND-011); WebView file-URL switches and `originWhitelist={['*']}` when the app vets every
  navigation with `onShouldStartLoadWithRequest` (RN-005, RN-006); no pinning reported when React
  Native's HTTP client comes from a class that isn't in the repository (AND-007, now a note); and build
  scripts in an app package's own `tools/` or `scripts/` folder counted as shipping console output
  (RN-015).

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
- **Hardening from an independent code review:**
  - Two crashes fixed: a WebView client whose `= false` body starts on the next line, and a number of
    more than 4,300 digits (Python 3.11+ refuses to convert it). Every place that reads a number from
    the scanned project now rejects absurd ones, including older rules.
  - Eleven checks that a crafted file could make quadratic are linear again, three of them in rules
    older than 0.5.0 (XPL-033 layout tags, KDF constants, and the HTTP scheme constant). A test scans
    each crafted file in under 3 seconds.
  - A regex in the new IOS-004 unwrap check could backtrack exponentially (found by CodeQL).
  - The AND-076 fix snippet set an OTP field to a phone keyboard; it now shows `number` and
    `textNoSuggestions` separately.
- **React Native is named in the README and the docs:** masaudit scans the native `android/` and `ios/`
  folders; the JavaScript isn't scanned yet.
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
