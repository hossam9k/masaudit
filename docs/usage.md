[masaudit documentation](README.md) ›

# Using masaudit

This guide covers everything the README leaves out: install options, app types, every option, the
config file, and team features. For CI, see [ci.md](ci.md).

## Install or run

You need Python 3.9 or later. Check with `python3 --version` (on Windows, `py --version`).

| Way | Command | Notes |
|---|---|---|
| uv | `uvx masaudit .` | Needs [uv](https://docs.astral.sh/uv/) and network access the first time. |
| pipx, one run | `pipx run masaudit .` | Needs [pipx](https://pipx.pypa.io/). |
| pipx, installed | `pipx install masaudit`, then `masaudit .` | Keeps the `masaudit` command on your PATH. |
| pip | `pip install masaudit` | Use it inside a virtual environment. |
| Single file | `python3 masaudit.pyz .` (Windows: `py masaudit.pyz .`) | Download `masaudit.pyz` from the [latest release](https://github.com/hossam9k/masaudit/releases/latest). Works offline, needs nothing else. |

masaudit has no dependencies outside Python's standard library. To check that a downloaded file
came from this repository's release workflow, see [Verify a download](../SECURITY.md#verify-a-download).

The examples below use `masaudit`. If you run it another way, type `uvx masaudit` or
`python3 masaudit.pyz` instead.

## Choose your app type

The app type decides which advice applies. The first run asks **"What kind of app is this?"** and
offers to save your answer in `.masaudit.ini`. To skip the question, pass `--app-type`.

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

The MAS profiles come from OWASP MAS and appear in every report:

- **L1** is the baseline for every app.
- **L2** adds protection for sensitive data.
- **R** makes the app resist tampering.
- **P** covers privacy.

Tips:

- **If two types fit, pick the riskier one.**
- **Common names work too.** For example, `news` means `content`, `fintech` means `banking`,
  `restaurant` means `ecommerce`, and `smart-home` means `device-control`.
- **Without an answer** (in CI, for example), masaudit assumes `general` and lists higher-risk checks
  as *Not needed*. Set `--app-type` in CI, or commit `.masaudit.ini`.

### "Check your app type"

If the code suggests a riskier type than the one you chose, masaudit warns you instead of switching
on its own:

```text
WARNING: Check your app type.
  You chose:  content
  The code:   app/src/main/java/com/news/Checkout.kt has card-number fields.
  Suggests:   ecommerce-cards, which adds 19 checks for this project.
  Hidden:     1 finding is under Not needed: No certificate pinning (needed for high-risk apps)
  To fix:     run again with --app-type ecommerce-cards.
  Keeping content on purpose? Add app_type_reviewed = ecommerce-cards to .masaudit.ini.
```

- **It warns only when it matters.** A payment SDK in a news app stays a quiet clue, because both
  types run the same checks. Choosing a riskier type than the evidence never warns.
- **Evidence comes from code that ships:** payment and identity-verification SDKs, card-number fields,
  Apple Pay and Google Pay, open banking, crypto wallets, health data, smart-home APIs, MDM, game
  engines, and loyalty code. Tests, sample apps, and comments don't count.
- **Where it shows:** the terminal, the top of the report, JSON (`profile.warnings`), SARIF
  (`toolConfigurationNotifications`), an annotation on GitHub Actions runs, and the first-run
  question, which offers to switch.
- **Reviewed it and keeping your type?** Add `app_type_reviewed = <suggested type>` to
  `.masaudit.ini`. That suggestion stops warning; new evidence still warns.

## Read the report

`SECURITY-AUDIT.md` starts with a verdict and the top fixes (up to 3), then has these sections:

1. **Fix before release** and **Fix soon**: each finding with why it matters, a paste-ready fix, how
   to verify it, how long it takes, its OWASP IDs (MASWE and MASVS), and the book section.
2. **Notes**.
3. **Not needed for your app (and why)**: real findings your app type doesn't need, each with the reason.
4. **Checked, nothing found**: the checks that ran and passed.
5. **Residual risk**: what a source scanner can't see, and anything it couldn't decide.
6. **Fix plan for your AI assistant**: paste it into any chat assistant.

Findings marked *Check by hand* need a person or an AI assistant to confirm them.

Fix the top fixes first, scan again, then [add masaudit to CI](ci.md).

## Options

```bash
masaudit . --app-type loyalty                          # set the app type (see the table above)
masaudit . --format sarif --output masaudit.sarif      # SARIF: the format GitHub code scanning reads
masaudit . --format json --output masaudit.json        # JSON for your own tools
masaudit . --format text                               # summary on screen only
masaudit . --fail-on high                              # exit 1 on open high or critical findings
masaudit --explain AND-004                             # what a rule checks and how to fix it, offline
masaudit --list-rules                                  # every rule
masaudit . --fix-safe                                  # preview safe fixes as a diff; changes nothing
```

Run `masaudit --help` for the full list, including `--no-color` and `--sarif-include-not-needed`
(adds *Not needed* findings to SARIF as notes).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished; nothing at or above `--fail-on` |
| 1 | Open findings at or above `--fail-on` |
| 2 | Tool error |

### Preview and apply safe fixes

`--fix-safe` applies only fixes that can't change how a correct app behaves. Today that's one:
removing `android:debuggable="true"` from the main manifest. Every other finding has a paste-ready fix
in the report.

```bash
masaudit . --fix-safe                  # print the diff; changes nothing
masaudit . --fix-safe --write-patch    # also save it as masaudit-fixes.patch
masaudit . --fix-safe --yes            # apply the fixes in place (needs a clean git tree)
```

## Config file: `.masaudit.ini`

Put `.masaudit.ini` in the folder you scan to set per-project defaults:

```ini
[masaudit]
app_type = banking
fail_on = high
exclude = vendor/*, third_party/**
```

- `app_type`: any app type or alias from the table above.
- `app_type_reviewed`: app types the code suggested that your team reviewed and decided against,
  comma-separated. They no longer raise "Check your app type".
- `fail_on`: `critical`, `high`, `medium`, or `low`.
- `exclude`: comma-separated globs for paths not to scan.

Command-line options win over the file, and the file wins over the first-run question. Unknown
sections or keys are an error, so a typo never silently changes what gets checked.

## Team features

### Suppress a finding, with a reason

Put a comment on the line, or on the line above:

- Kotlin, Java, or Swift: `// masaudit:ignore AND-004 test server only, never in release`
- XML: `<!-- masaudit:ignore AND-015 reachable only with our signature permission -->`

A suppression without a reason is ignored and reported.

### Accept today's findings in an older app

```bash
masaudit . --update-baseline                        # saves findings to .masaudit-baseline.json
masaudit . --baseline .masaudit-baseline.json       # shows them as Accepted; fails only on new ones
```

### Bring your other tools

```bash
masaudit . --import-sarif lint.sarif mobsfscan.sarif
```

This sorts Android Lint, mobsfscan, Semgrep, and zizmor results by the same app type.
