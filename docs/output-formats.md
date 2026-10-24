[masaudit documentation](README.md) › Output formats reference

# Output formats reference

Choose a format with `--format`, and a file with `--output`.

| Format | Use it for | Default file |
|---|---|---|
| (none) | People: a terminal summary plus the Markdown report | `SECURITY-AUDIT.md` |
| `md` | The Markdown report only | Printed, or `--output` |
| `json` | Your own tools and dashboards | Printed, or `--output` |
| `sarif` | GitHub code scanning and other SARIF viewers | Printed, or `--output` |
| `text` | The terminal summary only | Printed, or `--output` |

Every format includes the masaudit and rules versions, and masks secret values in snippets.

## Markdown

The human report. It opens with a **verdict** for your app type and the **top fixes** (up to three),
then these sections, in this order:

| Section | What it holds | What to do |
|---|---|---|
| **Fix before release** | Critical and high findings for your app type | Fix before you ship. |
| **Fix soon** | Medium and low findings | Schedule them. |
| **Notes** | Informational findings | Read; act if they apply. |
| **Not needed for your app (and why)** | Real findings your app type doesn't need | Nothing, unless your app type is wrong. |
| **Accepted earlier (not counted)** | Findings suppressed with a reason, or in a baseline | Review them before each release. |
| **Checked, nothing found** | Checks that ran and passed | Nothing. |
| **Residual risk** | What a source scanner can't see, and what it couldn't decide | Check these by hand. |
| **Fix plan for your AI assistant** | The open findings, ready to paste into a chat assistant | Optional. |

*Accepted earlier* appears only when you have suppressions or a baseline. In the fix plan, code from
your project is marked as data. [Read and fix the report](fixing.md) shows how to work through it.

## JSON

Top-level fields:

| Field | Content |
|---|---|
| `schema_version` | The JSON layout version. |
| `tool`, `rules_version`, `generated` | masaudit's version, the rules version, and the scan date (UTC; set `SOURCE_DATE_EPOCH` for a fixed date). |
| `project` | The project name and the platforms detected. |
| `profile` | `app_type`, `mas_profiles`, `source` (`flag`, `config`, `prompt`, or `default`), `description`, `suggestions` (code clues), and `warnings` ("Check your app type"). |
| `summary` | Counts per bucket: `fix-before-release`, `fix-soon`, `notes`, `not-needed`, `suppressed`, `baselined`. |
| `findings` | One object per finding (below). |
| `unknowns` | What the scanner couldn't decide. |
| `notes` | Messages about the run, such as imports or baselines. |

Each finding has:

- **Identity:** `rule_id`, `title`, `platform`, `path`, `line`, `snippet`, `message`, and a stable
  `fingerprint`.
- **Rating:** `severity` (the rule's), `effective_severity` (after your app type and the file's scope),
  `bucket`, `bucket_reason`, `confidence` (`high`, `medium`, or `manual` for *Check by hand*), and
  `scope` (`main`, `build-script`, `ci`, `debug`, `test`, or `unknown`).
- **Status:** `status` (`open`, `suppressed`, or `baselined`), `suppression_reason`, and
  `acknowledged` (a decision recorded for another tool, such as Lint's `tools:ignore`).
- **Advice:** `why`, `fix`, `verify`, `effort`, `safe_fix`, and the references `maswe`, `masvs`,
  `mastg`, `book`, and `book_url`.
- `imported`: whether it came from `--import-sarif`.

Each `profile.warnings` item has `chosen`, `source`, `suggested`, `evidence` (`label` and `path`),
`extra_checks`, `hidden` (the rules it hid under *Not needed*), and a one-line `message`.

## SARIF

SARIF 2.1.0, ready for GitHub code scanning (the [GitHub Action](ci.md) uploads it for you).

- **Rules** carry the title, the full explanation as help text, MASWE and MASVS IDs as tags, a
  `precision` property, and a `security-severity` score that GitHub uses to rank alerts.
- **Results** carry the location, `security-severity` for your app type, the `bucket`, the `scope`,
  and a `partialFingerprints` entry (`masaudit/v1`) that keeps alerts stable across scans.
- **Severity mapping:**

  | masaudit severity | SARIF `level` | `security-severity` |
  |---|---|---|
  | critical | `error` | 9.5 |
  | high | `error` | 7.5 |
  | medium | `warning` | 5.0 |
  | low | `note` | 3.0 |
  | info | `note` | 1.0 |

- `automationDetails.id` is `masaudit/` plus the detected platforms, for example
  `masaudit/android+ios`. It changes when the detected platforms change.
- *Not needed* findings are left out unless you pass `--sarif-include-not-needed`, which adds them as
  notes.
- Suppressed findings carry an `inSource` suppression and baselined ones an `external` suppression,
  both accepted, so code scanning shows them as dismissed rather than open.
- "Check your app type" warnings appear as `toolConfigurationNotifications`, pointing at the evidence
  file.
