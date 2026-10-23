# Beyond the scanner: what to check by hand

A static scanner reads files one pattern at a time. It can't see the server, follow a token through
its life, or tell whether a biometric prompt protects anything. Tools alone can't complete a MASVS
verification; someone has to understand the architecture and business logic ([§3.3]). This file is
that someone's checklist, ordered by value for a typical app.

For each area: **look for** (code patterns), **ask** (the question code can't answer), and **a
finding** (what to write). Skip areas the profile doesn't need ([profiles.md](profiles.md)). When the
fix is on a server you can't see, write a backend ticket, not code ([workflow-fix.md](workflow-fix.md)).

## Contents

1. [The server is the arbiter](#1-the-server-is-the-arbiter)
2. [Tokens: storage, refresh, logout, binding](#2-tokens-storage-refresh-logout-binding)
3. [Deep link parameters](#3-deep-link-parameters)
4. [WebView bridges](#4-webview-bridges)
5. [Biometric binding](#5-biometric-binding)
6. [Attestation, verified on the server](#6-attestation-verified-on-the-server)
7. [Privacy and SDK data flows](#7-privacy-and-sdk-data-flows)
8. [AI features](#8-ai-features)
9. [Kotlin Multiplatform actuals](#9-kotlin-multiplatform-actuals)
10. [CI settings outside the repository](#10-ci-settings-outside-the-repository)

## 1. The server is the arbiter

The client proposes; the server decides. These rules have no "it depends" caveat ([§12.1]).

- **Look for:** request bodies that carry `price`, `amount`, `discount`, `quantity`, `userId`, `role`,
  or entitlement flags; paywall or premium checks that exist only in the app; code that decodes a JWT
  to read a role or user ID and then decides what to allow ([Chapter 0.3]); endpoints that take an
  object ID (`/orders/{id}`).
- **Ask:** Does the server recompute prices and derive the user from the session token? Does it check
  that each object belongs to the caller (BOLA, the top OWASP API risk) ([Chapter 0.3])? For each
  high-value endpoint: if an attacker replays a valid request from a different device, what stops
  them ([§12.4])? Token binding, attestation assertions, and nonce or counter checks are the answers
  that count.
- **Finding:** "`CheckoutApi.kt:52` sends `price` from the client. If the server trusts it, anyone with
  a proxy sets their own price ([§12.1]). Confirm with the backend team." Treat attestation as one
  input to a risk score, never as the only gate ([§12.2]).

## 2. Tokens: storage, refresh, logout, binding

The refresh token is the most valuable thing the app holds ([Chapter 0.3]).

- **Look for (storage):** tokens written to `SharedPreferences`, plain DataStore, or `UserDefaults`.
  DataStore alone isn't encrypted ([§6.3]). `EncryptedSharedPreferences` is deprecated ([§6.1]). With
  Tink's `AndroidKeysetManager`, check `isUsingKeystore()`: if the Keystore self-test fails, Tink stores
  the keyset in cleartext ([§6.3]). On iOS, check every `kSecAttrAccessible` value; `kSecAttrAccessibleAlways`
  is deprecated and readable before first unlock ([§4.4]). Access tokens persisted to disk instead of
  held in memory ([§6.4]).
- **Look for (sign-in):** a login page in a WebView instead of the system browser (`AuthTabIntent`,
  Custom Tabs, `ASWebAuthenticationSession`); a `client_secret` in the app; no PKCE with `S256`; a
  custom-scheme redirect such as `myapp://callback` instead of a verified `https` one ([Chapter 0.3]).
- **Look for (logout):** code that only deletes local tokens. Logout must revoke on the server (RFC
  7009) and clear cached data, databases, WebView cookies and storage, and per-user keys ([Chapter 0.3]).
- **Ask the backend:** Are refresh tokens rotated with reuse detection, or sender-constrained? RFC 9700
  requires one or the other for public clients such as mobile apps ([Chapter 0.3]). If DPoP is used,
  does the server check `typ`, `alg`, signature, `htm`, `htu`, `iat`, `jti`, `ath`, and the key
  thumbprint against `cnf.jkt` ([§12.6])? Android's and iOS's signing APIs return DER-encoded ECDSA
  signatures, but `ES256` needs raw `R || S`; a missing conversion fails every proof ([§12.6]).
- **Finding:** follow the book's worked example: a refresh token in plaintext, valid for 90 days, not
  bound to the device, and not revoked at logout ([§23.4]). Calibrate to the profile: `MASWE-0001` is
  tagged L2 ([§3.2]), yet the book still gives long-lived refresh tokens real protection ([§6.4]).

## 3. Deep link parameters

A verified link proves the link reached your app. It says nothing about the parameters, which anyone
can craft ([§17.5]).

- **Look for:** custom `android:scheme` values; `https` intent filters without `android:autoVerify="true"`;
  handlers that read `intent.data` or `getQueryParameter(...)`; on iOS, `onOpenURL`,
  `application(_:open:options:)`, and `NSUserActivity` handlers; the `applinks:` entitlement. Trace each
  parameter to where it is used.
- **Ask:** Can a link start a sensitive action without confirmation and step-up? Can a parameter become
  a URL loaded in a WebView? Does `assetlinks.json` carry the Play *app signing* key fingerprint, not
  the upload key ([§17.5])?
- **Finding:** "`DeepLinkRouter.kt:30` passes the `url` parameter to `webView.loadUrl()` unchecked. An
  attacker sends a link and chooses what runs in the WebView, the same chain as the TikTok case
  ([§17.5], [§16.4])." A host check with `contains("mydomain.com")` is not a fix; parse the URL and
  compare the host against an exact `https` allowlist ([§16.4]).

## 4. WebView bridges

Any JavaScript in a WebView with a bridge can call your native code ([§16.2]).

- **Look for:** `addJavascriptInterface` (every frame, iframes included, can call it); `postWebMessage`
  with a `*` target origin; `WebViewCompat.addWebMessageListener` and its `allowedOriginRules` (the
  recommended form); on iOS, `WKScriptMessageHandler` code that never checks `message.frameInfo.isMainFrame`
  or `securityOrigin`, and replies sent through `evaluateJavaScript` instead of
  `WKScriptMessageHandlerWithReply`; generic `invoke(methodName, args)` gateways ([§16.2]).
- **Ask:** What can this WebView load: a third-party page, an ad, an iframe, a deep-link URL? What does
  each bridge method do? Does it read files, return tokens, or act without server authorization?
- **Finding:** "`@JavascriptInterface fun getToken()` in `WebBridge.kt:18` returns the session token to
  any frame. An injected script or iframe can read it ([§16.2])." An origin check doesn't stop a script
  injected into your own page; validate every argument anyway ([§16.2]). Clear WebView state on logout
  ([§16.6]).

## 5. Biometric binding

A biometric callback is a boolean an attacker controls with Frida. Real protection ties the prompt to
a key that signs something the server verifies ([§11.1]).

- **Look for (Android):** `BiometricPrompt.authenticate(promptInfo)` with no `CryptoObject`; an
  `onAuthenticationSucceeded` body that never uses `result.cryptoObject`; `BIOMETRIC_WEAK` for payments
  ([Chapter 11]). On the key: `setUserAuthenticationRequired(true)` missing; `setInvalidatedByBiometricEnrollment(false)`;
  a positive validity duration, or `AUTH_DEVICE_CREDENTIAL` in `setUserAuthenticationParameters`; either
  one removes the enrollment-invalidation guarantee ([§11.3]).
- **Look for (iOS):** a LocalAuthentication result that only flips a flag, with no Keychain or Secure
  Enclave key whose `SecAccessControl` requires biometry ([§11.1]); `.biometryAny` instead of
  `.biometryCurrentSet` ([§11.3]).
- **Ask:** When the user confirms a transfer, what does the server verify? It should check a signature
  over a one-time server challenge with the enrolled public key. An AES key only protects local data
  ([Chapter 11]). Does the fallback set `authenticated = true` ([§11.4])?
- **Finding:** "`PaymentConfirm.kt:61` unlocks the transfer on `onAuthenticationSucceeded` alone. A
  hooked callback completes the transfer with no fingerprint (`MASWE-0020`) ([§11.1])."

## 6. Attestation, verified on the server

Attestation is worth something only because the server checks it ([Chapter 9], [Chapter 10]).

- **Look for (Android):** `IntegrityManagerFactory.createStandard`, `prepareIntegrityToken`, and
  `setRequestHash`. The hash should cover the exact request bytes the server receives ([§9.6]). Any
  SafetyNet Attestation code is dead: the API is gone ([Chapter 9]).
- **Look for (iOS):** `DCAppAttestService`, `attestKey`, `generateAssertion`. Store the key ID in the
  Keychain with a `ThisDeviceOnly` class, and handle `invalidKey` by re-attesting ([Chapter 10]).
- **Ask (Play Integrity):** Does the server decode each token exactly once? Repeated decodes return
  cleared verdicts ([§9.2]). Does it check `requestDetails` (package, `requestHash`, timestamp) before any
  verdict ([§9.1], [§9.6])? Was it rolled out report-only first, with remediation dialogs ([§9.4])? Is
  `MEETS_STRONG_INTEGRITY` used as a bonus, never a baseline ([§9.3])?
- **Ask (App Attest):** Does the server validate the chain to Apple's root, the nonce, the `RP ID`, and
  the environment (`aaguid`), and reject a key already registered to another user? On every assertion,
  is the challenge single-use and the counter strictly increasing, updated atomically ([§10.2])? Does it
  accept new keys from reinstalls as re-registration rather than fraud ([§10.3])?
- **Finding:** "The backend verifies assertion signatures but never checks the counter. A captured
  assertion can be replayed ([§10.2])." Attestation proves the app and device, not the user ([§10.6]).

## 7. Privacy and SDK data flows

An SDK runs with your permissions, and its network calls are your data flows ([§18.4]).

- **Look for:** permissions in the *merged* manifest that came from libraries ([§18.1]); analytics or ad
  calls that pass emails, names, or locations; hardware identifiers used for tracking; ad identifiers
  without consent or App Tracking Transparency ([§18.2]); a missing or stale `PrivacyInfo.xcprivacy`;
  `NSPrivacyTrackingDomains`; account creation without in-app deletion ([§18.3]).
- **Ask:** Does the Play Data safety form or the privacy manifest match what actually leaves the device?
  You can't know from code alone. Recommend a traffic capture (`MASTG-TEST-0206`) and, on Android, a
  debug-only `AppOpsManager.OnOpNotedCallback` to log which SDK touches what ([§18.3], [§18.4]).
- **Finding:** "The analytics SDK adds `ACCESS_FINE_LOCATION` through the merged manifest. The app's
  features don't use it. Remove it with `tools:node="remove"` ([§18.1])."

## 8. AI features

Treat model output like WebView content: untrusted ([§20.1]).

- **Look for:** a model provider API key in the app; it is public and billed per token ([§20.3]).
  Tools or App Intents with side effects (money, messages, posting, deletion) that run without user
  confirmation, `requestConfirmation()`, or `authenticationPolicy` ([§20.1]). Model output rendered as
  Markdown or HTML, which lets an injected image link exfiltrate data ([§20.1]). Secrets or rules in
  the system prompt ([§20.3]). Prompts and completions sent to logging ([§20.6]).
- **Ask:** Which user data goes to a third-party provider, and does the compliance owner know ([§20.2])?
  Is the inference endpoint behind attestation, per-account and per-device rate limits, and token caps
  ([§20.4])?
- **Finding:** "`ChatAgent.kt:40` lets the model call `sendPayment` with no confirmation. A poisoned
  document can trigger a payment ([§20.1])."

## 9. Kotlin Multiplatform actuals

Shared code gets read by everyone; platform code often by one person ([§21.3]).

- **Look for:** `expect` declarations or shared interfaces named after one platform's mechanism, such
  as `getKeystoreKey`, instead of an intent such as `storeToken(token, requiringUserAuth)` ([§21.2]);
  `iosMain` Keychain items whose `kSecAttrAccessible` is not a `…ThisDeviceOnly` class, or is
  `kSecAttrAccessibleAlways` ([§21.3]); Ktor pinning set on one engine only ([§21.3]); Keystore,
  biometrics, attestation, or network trust moved into common code ([§21.1]).
- **Ask:** Who from each platform reviews `androidMain` and `iosMain` changes ([§21.3])?
- **Finding:** "`iosMain/TokenStore.kt:22` stores the refresh token with `kSecAttrAccessibleAlways`; the
  Android side uses a Keystore key. The iOS token is readable before first unlock ([§4.4], [§21.3])."

## 10. CI settings outside the repository

The scanner reads workflow files. It can't read the settings around them ([§15.3]).

- **Ask:** Is the default `GITHUB_TOKEN` read-only in *Settings → Actions → General*? Older
  organizations may still grant read-write. Is "Require actions to be pinned to a full-length commit
  SHA" on? Do `CODEOWNERS` rules on `.github/workflows/` require code-owner approval? Can self-hosted
  runners pick up public pull requests? Is the cloud OIDC trust policy scoped to repository, branch,
  and environment, and trusted publishing to the exact workflow file ([§15.3])? Is push protection or
  another blocking secret scan on ([§15.2])?
- **Finding:** "Workflows set no `permissions:` block, and the organization default is unknown. Set
  `permissions: {}` at workflow level and grant the minimum per job ([§15.3])."

[Chapter 0.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/00-foundations.md#chapter-03-authentication-sessions-and-tokens
[§3.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/01-understanding-the-threat.md#32-the-levels-that-are-not-levels-any-more
[§3.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/01-understanding-the-threat.md#33-what-owasp-will-not-do-for-you
[§4.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/02-data-at-rest.md#44-data-protection-classes-the-decision-you-keep-getting-wrong
[§6.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/02-data-at-rest.md#61-encryptedsharedpreferences-is-dead
[§6.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/02-data-at-rest.md#63-what-to-use-instead
[§6.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/02-data-at-rest.md#64-the-uncomfortable-question-nobody-asked
[Chapter 9]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-9-play-integrity--what-it-proves-and-what-it-does-not
[§9.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#91-the-shape-of-the-thing
[§9.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#92-standard-or-classic--choosing-properly
[§9.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#93-reading-the-verdicts-like-an-engineer-not-a-bouncer
[§9.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#94-how-to-roll-it-out-without-breaking-your-users
[§9.6]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#96-how-to-implement-it
[Chapter 10]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-10-app-attest--apples-model
[§10.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#102-what-your-server-must-do
[§10.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#103-what-changed-in-2026
[§10.6]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#106-the-shared-limit
[Chapter 11]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-11-biometrics-done-so-they-cannot-be-bypassed
[§11.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#111-decorative-versus-real
[§11.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#113-the-enrollment-problem-nobody-thinks-about
[§11.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#114-fallbacks-and-the-tension-inside-them
[§12.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#121-the-non-negotiables
[§12.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#122-attestation-as-a-signal-not-a-switch
[§12.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#124-one-test-for-any-design
[§12.6]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#126-sender-constrained-tokens-with-dpop-worked-through
[§15.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/06-the-build-and-release-pipeline.md#152-secrets-classify-then-protect
[§15.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/06-the-build-and-release-pipeline.md#153-hardening-the-workflow
[§16.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#162-the-javascript-bridge-and-why-its-the-sharpest-edge
[§16.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#164-loading-untrusted-content
[§16.6]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#166-cleanup-and-hygiene
[§17.5]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#175-deep-links-and-the-verification-that-makes-them-safe
[§18.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#181-permissions-ask-for-less-later-and-explain-why
[§18.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#182-identifiers-and-tracking
[§18.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#183-transparency-and-control
[§18.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#184-third-party-sdks-are-your-responsibility
[§20.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#201-if-the-user-can-influence-the-prompt-what-can-the-prompt-influence
[§20.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#202-what-must-never-leave-the-device
[§20.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#203-where-does-the-model-key-live
[§20.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#204-can-you-distinguish-a-real-client-from-a-script
[§20.6]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#206-what-are-you-logging
[§21.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#211-the-line-and-the-reasoning-behind-it
[§21.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#212-the-mistake-that-will-bite-you
[§21.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#213-two-practical-cautions
[§23.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/08-practice.md#234-write-the-report
