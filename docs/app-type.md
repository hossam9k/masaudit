[masaudit documentation](README.md) › Choose your app type

# Choose your app type

The app type decides which advice your app gets. A banking app needs certificate pinning and root
detection; a news app doesn't, and masaudit lists those findings as *Not needed* with the reason.
This page shows how to pick a type, set it, and handle the "Check your app type" warning.

## Pick a type

Pick the row that matches what your app protects. If two fit, pick the riskier one: the one with
more MAS profiles. If they tie, pick the type that matches the most sensitive thing your app does.

| App type | For | MAS profiles |
|---|---|---|
| `banking` | Banking, payments, wallets, crypto, lending, or insurance | L1, L2, R, P |
| `identity` | Digital ID, government, password manager, VPN, or carrier | L1, L2, R, P |
| `health` | Health, medical, or mental-health data | L1, L2, P |
| `ecommerce-cards` | Shop where your own code handles card numbers | L1, L2, P |
| `ecommerce` | Shop, food ordering, or booking (payment SDK takes cards) | L1, P |
| `loyalty` | Loyalty points, coupons, gift cards, tickets (no cards) | L1, R, P |
| `marketplace` | Marketplace, ride-hailing, delivery, jobs, or listings | L1, P |
| `social` | Social, messaging, dating, or community | L1, P |
| `content` | News, video, music, reading, or learning | L1, P |
| `device-control` | Controls real things: smart locks, home devices, or cars | L1, L2, P |
| `enterprise` | Internal app for your company's own staff | L1, L2, P |
| `game` | Game (cheating and tampering matter) | L1, R, P |
| `general` | Something else: a tool, notes, photos, maps (or not sure) | L1, P |

Common names work too, for example `news` for `content`, `fintech` for `banking`, `restaurant` for
`ecommerce`, and `smart-home` for `device-control`. The profiles come from OWASP MAS;
[How masaudit works](how-it-works.md#app-types-map-to-owasp-mas-profiles) explains each one and how it
decides a finding's bucket.

## Set the app type

Use the method that matches how you run masaudit. If you use more than one, the command line
overrides `.masaudit.ini`, and the file overrides the question.

- **Answer the question** on the first run. masaudit offers to save the answer in `.masaudit.ini`.
- **Pass it on the command line:** `masaudit . --app-type banking`.
- **Commit it in `.masaudit.ini`,** so local runs, CI, and the pre-commit hook all agree:

  ```ini
  [masaudit]
  app_type = banking
  ```

Without any of these, for example in CI, masaudit assumes `general` and says so. Always set a type
in CI.

## When masaudit says "Check your app type"

masaudit looks for evidence of the app's real risk in code that ships, such as payment and
identity-verification SDKs, card-number fields, Apple Pay and Google Pay, open banking, crypto
wallets, passport NFC reading, health data, smart-home APIs, MDM, game engines, Google Wallet passes,
and loyalty code. Tests, sample apps, and comments don't count. If the evidence points to a riskier
type than yours, masaudit warns instead of switching on its own:

```text
WARNING: Check your app type.
  You chose:  content
  The code:   app/src/main/java/com/news/Checkout.kt has card-number fields.
  Suggests:   ecommerce-cards, which adds 19 checks for this project.
  Hidden:     1 finding is under Not needed: No certificate pinning (needed for high-risk apps)
  To fix:     run again with --app-type ecommerce-cards.
  Keeping content on purpose? Add app_type_reviewed = ecommerce-cards to .masaudit.ini.
```

Then do one of these:

- **The code is right:** switch to the suggested type, with `--app-type` or in `.masaudit.ini`.
- **Your type is right** (the evidence is old code, or a feature that doesn't ship): add
  `app_type_reviewed = <suggested type>` to `.masaudit.ini`. masaudit stops warning about that type,
  even for new evidence of it. Evidence for a different, riskier type still warns.

The warning appears only when the suggested type would run more checks. A payment SDK in a news app
stays a quiet clue, because both types run the same checks. You see the warning in the terminal, at
the top of the report, in JSON and SARIF, as an annotation on GitHub Actions runs, and during the
first-run question, which offers to switch.

## Next steps

- **Read the results for your app type:** [Read and fix the report](fixing.md).
- **Use the same type everywhere:** [Use masaudit in CI](ci.md).
