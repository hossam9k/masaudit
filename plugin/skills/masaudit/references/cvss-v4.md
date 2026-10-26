# Scoring a finding with CVSS v4.0

Use this when a finding goes into a formal report or a pentest deliverable. For everyday triage,
masaudit's own severity is enough (see [the legend](#masaudit-severity-and-how-it-differs)).

## Contents

- [What CVSS v4.0 is, and what it isn't](#what-cvss-v40-is-and-what-it-isnt)
- [The metrics that matter on mobile](#the-metrics-that-matter-on-mobile)
- [How to score, step by step](#how-to-score-step-by-step)
- [Three worked examples from the book](#three-worked-examples-from-the-book)
- [masaudit severity, and how it differs](#masaudit-severity-and-how-it-differs)

## What CVSS v4.0 is, and what it isn't

CVSS v4.0 is FIRST's severity-scoring standard, published in November 2023 and still current in
October 2026 ([§23.3]). Pick one scale and apply it to every finding so ratings are comparable. If the
organization already uses the OWASP Risk Rating method or an internal scale, use that instead:
consistency matters more than the choice ([§23.3]).

Severity combines two questions ([§23.3]):

- **Impact: what does the attacker gain?** Reading their own cached data, reading another user's
  account, and moving money are three different results.
- **Likelihood: what does the attack require?** A remote attack with no special access is far more
  likely than one that needs a rooted device and physical possession.

A Base score measures **severity, not risk**. FIRST's user guide says to enrich it with the Threat and
Environmental metrics before calling something a priority. A High Base score on a finding that needs
physical possession of an unlocked device is a number, not a decision ([§23.3]).

## The metrics that matter on mobile

| Metric | Values and when to use them |
|---|---|
| Attack Vector (AV) | `N` reachable over the internet; `A` same network; `L` needs on-device code or a shell; `P` the attacker must physically hold the device ([§23.3]) |
| Attack Requirements (AT) | `P` (Present) when the attack needs specific conditions, such as a rooted device or a race window. **"Requires root" goes here**, not in AV ([§23.3]) |
| Privileges Required (PR) | `N` when the attacker needs no account. If you model malware that already holds root, that is `PR:H`, not `AT:P` ([§23.4]) |
| Vulnerable System impact (VC/VI/VA) | Confidentiality, integrity, and availability of the app and device ([§23.3]) |
| Subsequent System impact (SC/SI/SA) | The backend or other systems the app reaches. This is how you say "reading this token lets the attacker act on the server" ([§23.3]) |

Two mobile rules to remember ([§23.3]):

- A plaintext token on disk is usually `AV:P` or `AV:L`. That is a mitigating factor. State it; don't
  hide it.
- "Requires root" is a real mitigating factor. Stating it honestly builds trust, and so does refusing to
  use it to dismiss a finding that matters.

## How to score, step by step

1. **Write the attack path in one sentence.** If there are several paths, score the one you
   reproduced and name the alternatives. The book's example does exactly this: "Say which model you
   scored" ([§23.4]).
2. **Pick each metric and write one line of why,** as in the book's table for F-03 below.
3. **Compute the score with a CVSS v4.0 calculator** (FIRST publishes one). Don't estimate it.
4. **Record the full vector string** with the score, so a reader can check your reasoning, not only the
   number ([§23.3]).
5. **Describe impact in business terms** next to the score. The book shows one bug written two ways; only the
   version that spells out account takeover gets prioritized ([§23.4]).
6. **Don't inflate.** Readers ignore a report in which everything is critical ([§23.3]).

## Three worked examples from the book

The vectors and scores below are copied exactly from the book. Nothing here is recomputed.

### Example 1: physical access, no other requirement

The book's example vector in [§23.3], given next to its point about physical possession:

`CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, which scores **5.1**.

Read it as: the attacker must hold the device (`AV:P`); nothing else stands in the way (`AC:L`, `AT:N`,
`PR:N`, `UI:N`); data on the device is disclosed (`VC:H`); no other system is affected (`SC/SI/SA:N`).

### Example 2: F-03, refresh token in plaintext, rooted device

The book's worked finding ([§23.4]): a refresh token stored in plaintext in `SharedPreferences`,
reproduced with the phone in hand on an emulator with `adb root`. The token works against the backend.

`CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`, Base score **5.8 (Medium)**.

| Metric | Value | The book's reason, shortened |
|---|---|---|
| AV | `P` | The reproduced path needs the phone in hand |
| AC | `L` | Once the file is readable, no key to recover and no race |
| AT | `P` | The device must be rooted, or the attacker needs a root exploit |
| PR | `N` | The attacker needs no account of their own |
| UI | `N` | The victim does nothing |
| VC/VI/VA | `H`/`N`/`N` | The token and cached profile are disclosed; nothing on the device changes |
| SC/SI/SA | `H`/`H`/`N` | The token works on the backend: read the account and act as the user |

The book's remediation notes that the fix that changes the severity is on the server: bind the token
to a device key with DPoP and rotate it on every use, so a copied token is useless alone ([§23.4]).

### Example 3: the same finding, scored as malware

The same F-03 entry scores a second attack path, malware on a phone the user has rooted ([§23.4]):

- Scored with `AV:L`: **7.0 (High)**.
- Modeling the malware as already holding root puts it in `PR:H`, not `AT:P`: `AV:L/AT:N/PR:H` scores
  **8.2**.

The book gives only the changed metrics for these two scores. If you use them, take the remaining
metrics from F-03's vector and confirm the score in a calculator before publishing. The lesson: one bug
can honestly score 5.8, 7.0, or 8.2 depending on the attack you model. Name the model you chose.

## masaudit severity, and how it differs

masaudit uses five levels. They are the tool's own convention, not a CVSS rating. Each rule carries a
base severity for apps whose profile includes the weakness; masaudit then calibrates it for this app.

| Level | Report bucket | How to read it |
|---|---|---|
| `critical` | Fix before release | The highest base severity a rule can carry |
| `high` | Fix before release | A serious weakness for this app's profile |
| `medium` | Fix soon | A real weakness with a narrower impact or a harder path |
| `low` | Fix soon | Worth fixing; small impact or demanding preconditions |
| `info` | Notes, or *Not needed for your app* | Context, or a control this app's profile doesn't need |

Two exceptions: a finding from a `manual`-confidence rule goes to *Check by hand*, and a protection the
app has nowhere (`kind: hardening`) to the *Hardening checklist*, whatever its level. Neither fails
`--fail-on`.

The last column is a reading guide. Each finding's `why` text states the specific risk.

How calibration works:

- **Profile.** If the app's MAS profiles share nothing with the rule's profiles, or the rule applies only
  to some app types (pinning, for example), the finding becomes `info` under *Not needed for your app*.
  It is never dropped. See [profiles.md](profiles.md).
- **Location.** A hit in debug code drops two levels; a hit in test code drops four. Nothing drops below
  `info`.

How it differs from CVSS:

| | masaudit severity | CVSS v4.0 |
|---|---|---|
| Unit | A rule, adjusted for app type and code location | One finding and one attack path |
| Input | The rule's base severity | Metrics you choose: AV, AC, AT, PR, UI, and impacts |
| Knows the app type | Yes, through MAS profiles | Only through Environmental metrics you add ([§23.3]) |
| Output | A level and a bucket | A vector string and a 0–10 score |
| Use it for | Ordering the work in `SECURITY-AUDIT.md` | Formal reports that others must compare and defend ([§23.3]) |

Don't convert one into the other mechanically. A masaudit `high` is not a CVSS score. When a finding
goes into a formal report, score it fresh with the steps above and keep the full vector.

[§23.3]: https://github.com/hossam9k/mobile-app-security/blob/main/book/08-practice.md#233-rate-what-you-find
[§23.4]: https://github.com/hossam9k/mobile-app-security/blob/main/book/08-practice.md#234-write-the-report
