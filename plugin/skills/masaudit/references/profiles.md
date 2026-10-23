# App types and what each one needs

The app type decides the advice. A control that protects a banking app can add risk to a news app.
This file maps each masaudit app type to its OWASP MAS profiles and to the controls that matter.
Every claim links to the book section that explains it.

## Contents

- [The four MAS profiles](#the-four-mas-profiles)
- [What every app needs](#what-every-app-needs)
- [App types at a glance](#app-types-at-a-glance)
- [What not to recommend, by type](#what-not-to-recommend-by-type)
- [Required or advisable](#required-or-advisable)
- [Fix order](#fix-order)
- [How to tell the type from code](#how-to-tell-the-type-from-code)
- [When the user's answer conflicts with the code](#when-the-users-answer-conflicts-with-the-code)

## The four MAS profiles

The old "MASVS L1/L2/R" levels are gone from MASVS. They are now MASTG *testing profiles*. Say
"the MAS-L2 profile", never "MASVS L2" ([§3.2]). Each profile assumes a different attacker:

| Profile | Assumes | Recommended for |
|---|---|---|
| MAS-L1 | The OS is trusted; other apps are the adversary | Every app, as a baseline |
| MAS-L2 | The OS can't be trusted (rooted or jailbroken); attackers may have physical access | High-risk data or sensitive functions: health, finance |
| MAS-R | The device's user is the adversary: reverse engineers, cheaters | Apps protecting their own logic or assets. Always on top of L1 or L2, never alone |
| MAS-P | Not attacker-centric; personal-data handling | Every app that handles user-sensitive data |

Profiles combine. A banking app is typically L2+P+R; a news app L1+P. Setting the profile first stops
you from reporting a missing anti-debugging control on a content app that never needed one
([§23.1]). The same idea from the attacker side: a news app worries about the opportunist; a banking
app worries about all four attacker groups ([§1.3]).

The profile also changes what "unencrypted storage" means. `MASWE-0001` (sensitive data unencrypted in
*private* storage) is tagged L2, not L1, because the L1 baseline trusts the app sandbox ([§3.2], [§6.4]).

## What every app needs

These apply to all eleven types, `general` included.

- **Server-side rules.** Validate prices, entitlements, and limits on the server. Derive the user from
  the session token, never from a request field. These rules carry no "it depends" caveat ([§12.1]).
  Check that every object request belongs to the caller (BOLA) ([Chapter 0.3]).
- **TLS done right.** No cleartext, no user-added CAs in release, no `proceed()` on TLS errors ([§7.1]).
- **No restricted secrets in the app.** Anything in the package is public. Keys with cost or quota go
  behind your backend ([§15.2]).
- **Cheap hygiene.** R8 minification and resource shrinking (Android) or stripped symbols (iOS); no
  release logging; `debuggable` false; WebView debugging off in release; screenshot protection on
  sensitive screens; current signing schemes and `minSdkVersion`; sensible session timeouts. The book
  says to do all of them ([§14.1]).
- **Privacy (MAS-P),** for any app that handles user-sensitive data: fewer permissions, accurate store
  declarations, and knowing what your SDKs send ([§3.2], [Chapter 18]).
- **Detection, if any, reports and never blocks.** Send root, hook, and debugger signals to the backend
  as risk inputs and let the session continue. Local blocks are one hook away from removal, punish real
  users, and destroy your intelligence ([§14.2]).

Session timeout starting points (the book marks them as reasoned): 15 minutes for banking and payments,
30 for health and enterprise, hours or none for content and social. A timeout must invalidate the
session on the server, not only show a login screen ([§14.5]).

## App types at a glance

"Required" means the type's profile calls for it: a miss is a real finding. "Advisable" means worth it
when the stated condition holds. "Not needed" means masaudit reports it under *Not needed for your app*.

| App type | MAS profiles | Required beyond the baseline | Advisable | Not needed |
|---|---|---|---|---|
| `banking` | L1, L2, R, P | Keystore/Keychain-protected refresh tokens ([§6.4]); SPKI pinning on an intermediate with a backup, plus CT monitoring ([§8.8]); biometrics bound to a key for transfers and payee changes ([§11.1], [§11.5]); attestation as a server-side signal on login, payment, and password change ([§10.5], [§12.2]); tamper and hook detection that reports to the backend ([§14.2]) | Strong integrity as a bonus signal, never a baseline ([§9.3]); passkeys for sign-in ([§11.7]) | A hard local block on root. If an offline feature needs a local response, degrade only that feature and still report ([§14.2]) |
| `fintech` | L1, L2, R, P | Same as banking: the book groups banking, fintech, and trading ([§8.8]) | Same as banking | Same as banking |
| `health` | L1, L2, P | Protected token storage ([§6.4]); pinning as for banking, because patient data is high-value and long-lived ([§8.8]); step-up for sensitive actions ([Chapter 0.3]) | Attestation on login and account changes ([§10.5]) | Anti-tamper and obfuscation beyond the [§14.1] basics (MAS-R is not in the profile) |
| `ecommerce-cards` | L1, L2, P | Card handling puts you in the banking category for pinning ([§8.8]); attestation on checkout and "add payment method" ([§10.5]) | Tokenize payments through a provider: the cheapest compliance decision you'll make ([Chapter 30]) | Anti-tamper beyond the basics |
| `ecommerce` | L1, P | Strict TLS plus CT monitoring is a reasonable position when a payment SDK handles cards ([§8.8]) | Attestation on checkout ([§10.5]) | Pinning; anti-tamper |
| `marketplace` | L1, P | Strict TLS, CT monitoring, backend fraud detection ([§8.8]); rate limits and risk scoring against fraudsters ([§1.3]) | Attestation on login and payment ([§10.5]) | Pinning: payment is usually tokenized, and the overhead buys little ([§8.8]); anti-tamper |
| `social` | L1, P | Platform defaults with a strict configuration ([§8.8]); privacy and SDK data flows ([Chapter 18]) | End-to-end encryption protects content with its own keys, so TLS pinning isn't its main defense ([§8.8]) | Pinning; anti-tamper; biometrics on every launch ([§11.5]) |
| `content` | L1, P | Platform defaults with a strict configuration ([§8.8]); privacy ([Chapter 18]) | Attestation only on an endpoint worth abusing, such as metered AI inference ([§20.4]) | Pinning: it "adds risk and no security" to a news feed ([§8.8]); anti-debugging and anti-tamper ([§23.1]); encrypting non-secret preferences ([§6.4]) |
| `enterprise` | L1, L2, P | Trust your private CA explicitly ([§8.8]); protected token storage ([§6.4]) | Pinning only if you control both client and server ([§8.8]) | Pinning when a customer's MDM inspects traffic: it breaks your own deployment ([§8.8]); anti-tamper |
| `game` | L1, R, P | Server-side entitlement, attestation, and signature checks against cloners ([§1.3]); detection that reports, not blocks ([§14.2]); obfuscation that protects detection logic ([§14.3]) | Strong integrity as a bonus signal for high-value actions ([§9.3]) | Pinning (masaudit flags it only for banking, fintech, health, and ecommerce-cards) |
| `general` | L1 | Baseline only | Ask the profile question again if code clues appear | Everything outside L1 |

Pinning anywhere carries a condition: only if the team can run a pin set for years without locking
users out. That needs a rotation runbook, backup pins, failure alerts, CT monitoring, a protected kill
switch, and an agreement with whoever manages certificates ([§8.3], [§8.7]). If the answer is no, say
"don't pin" plainly rather than pinning badly.

## What not to recommend, by type

Don't recommend these. If the scanner flags them, leave them in *Not needed for your app* with the reason.

- **content, social:** certificate pinning ([§8.8]); root, jailbreak, hook, or debugger detection and
  obfuscation beyond R8 ([§23.1], [§3.2]); biometrics on cold start or for reading ([§11.5]); short
  banking-style timeouts ([§14.5]).
- **ecommerce (payment SDK), marketplace:** pinning ([§8.8]); anti-tamper ([§3.2]).
- **enterprise:** pinning where MDM inspection is legitimate ([§8.8]).
- **health, ecommerce-cards, enterprise:** MAS-R controls such as anti-debugging (not in the profile).
- **game:** pinning (no row in [§8.8]; reason from the threat); L2 storage encryption by reflex ([§6.4]).
- **general:** anything beyond the L1 baseline, until the user confirms a riskier type.
- **Every type:** a hard local block on rooted devices for an ordinary online app ([§14.2]); `MEETS_STRONG_INTEGRITY` as a
  baseline gate, because on Android 13+ a missing strong label usually means an unpatched phone, not an
  attacker ([§9.3]).

## Required or advisable

Some controls are mandatory because a regulator or a store demands them. Label those "required" and
defend the rest on their merits; proposals that mix the two get cut wholesale ([§30.3]). Examples:
protecting personal and payment data at rest and in transit (GDPR, PCI DSS, HIPAA, DORA, CRA), strong
authentication for sensitive actions (PCI DSS, DORA), and store declarations that match behavior
([§30.4]). For banking, pinning is often a compliance requirement ([§8.8]). You can't see the user's
regulators from code: ask who owns compliance before calling a control legally required ([§30.3]).

## Fix order

Recommend fixes in the book's phase order. Each phase makes the next one cheaper ([§32.1], [§32.2]):

1. **Foundations:** secrets out of the app and repository, tokens in Keystore/Keychain-backed storage,
   TLS configuration, and the pinning decision written down. Nothing else matters while a credential
   is exposed.
2. **Verification:** Play Integrity and App Attest in report-only mode, verdicts checked on the
   backend, risk scoring, and token binding.
3. **Authentication:** biometrics bound to keys, step-up, and keys invalidated on enrollment change.
4. **Hardening, last:** tamper and hook detection reporting to the backend, obfuscation, release
   logging removed, and screenshot protection. Lowest risk reduced per effort; cut it first if squeezed.

For L1-only types, phases 2–4 shrink to what the table above lists.

## How to tell the type from code

masaudit looks for these clues and reports them. They only *suggest* a higher-risk type.

| Clue in code | Suggests |
|---|---|
| `com.stripe`, `StripePaymentSheet`, Braintree, Adyen, Checkout.com, PayPal | `ecommerce` (a payment SDK handles cards) |
| `HealthKit`, `HKHealthStore`, `androidx.health.connect` | `health` |
| Fields named `cardNumber`, `card_number`, `pan`, `cvv`, `cvc` | `ecommerce-cards` (the app touches card numbers) |
| `BiometricPrompt`, `LAContext` | No type; check biometric binding ([Chapter 11]) |
| Play Integrity, `DCAppAttestService` | No type; check server verification ([Chapter 9], [Chapter 10]) |

Read clues with care. A payment SDK means cards go to the provider, which is the lower-risk e-commerce
case ([§8.8]). Card-number fields mean the app handles cards itself, which is the higher-risk case.

## When the user's answer conflicts with the code

The user's answer wins until they change it. Never re-profile silently.

1. **State the evidence.** "You said `content`, but `CardEntryForm.kt:40` collects a card number and CVV."
2. **Ask one question.** "Does the app handle card numbers itself? If so, `ecommerce-cards` fits better."
3. **If they confirm,** suggest re-running with the right `--app-type` rather than overriding findings
   yourself.
4. **If they decline,** keep their type. Note the clue and the open question in the report, and don't
   reopen it.

In a headless run, use `.masaudit.ini` or `general`, and state the assumption and any clues at the top
of the report.

[Chapter 0.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/00-foundations.md#chapter-03-authentication-sessions-and-tokens
[§1.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/01-understanding-the-threat.md#13-who-is-actually-attacking-you
[§3.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/01-understanding-the-threat.md#32-the-levels-that-are-not-levels-any-more
[§6.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/02-data-at-rest.md#64-the-uncomfortable-question-nobody-asked
[§7.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/03-data-in-transit.md#71-the-baseline
[§8.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/03-data-in-transit.md#83-the-honest-synthesis-contested
[§8.7]: https://github.com/hossam9k/mobile-app-security/blob/main/book/03-data-in-transit.md#87-what-pinning-costs-you-operationally
[§8.8]: https://github.com/hossam9k/mobile-app-security/blob/main/book/03-data-in-transit.md#88-the-decision-by-application-type
[Chapter 9]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-9-play-integrity--what-it-proves-and-what-it-does-not
[§9.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#93-reading-the-verdicts-like-an-engineer-not-a-bouncer
[Chapter 10]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-10-app-attest--apples-model
[§10.5]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#105-limits-and-when-to-actually-check
[Chapter 11]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#chapter-11-biometrics-done-so-they-cannot-be-bypassed
[§11.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#111-decorative-versus-real
[§11.5]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#115-where-to-spend-the-friction
[§11.7]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#117-passkeys-when-the-biometric-should-prove-something-to-your-server
[§12.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#121-the-non-negotiables
[§12.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/04-proving-who-is-calling.md#122-attestation-as-a-signal-not-a-switch
[§14.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/05-resilience.md#141-the-cheap-things-which-you-should-simply-do
[§14.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/05-resilience.md#142-detection-report-never-block
[§14.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/05-resilience.md#143-where-obfuscation-genuinely-helps
[§14.5]: https://github.com/hossam9k/mobile-app-security/blob/main/book/05-resilience.md#145-the-hygiene-controls-in-code
[§15.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/06-the-build-and-release-pipeline.md#152-secrets-classify-then-protect
[Chapter 18]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#chapter-18-permissions-and-privacy
[§20.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/07-platform-surfaces-and-new-frontiers.md#204-can-you-distinguish-a-real-client-from-a-script
[§23.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/08-practice.md#231-scope-it-first
[Chapter 30]: https://github.com/hossam9k/mobile-app-security/blob/main/book/11-making-the-case-and-running-the-programme.md#chapter-30-the-regulatory-landscape
[§30.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/11-making-the-case-and-running-the-programme.md#303-how-to-use-this-chapter
[§30.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/11-making-the-case-and-running-the-programme.md#304-where-the-plan-meets-the-rules
[§32.1]: https://github.com/hossam9k/mobile-app-security/blob/main/book/11-making-the-case-and-running-the-programme.md#321-why-this-order
[§32.2]: https://github.com/hossam9k/mobile-app-security/blob/main/book/11-making-the-case-and-running-the-programme.md#322-the-phases
