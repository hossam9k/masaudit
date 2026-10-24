[masaudit documentation](README.md) › Config file reference

# Config file reference: `.masaudit.ini`

Put `.masaudit.ini` in the folder you scan to set per-project defaults. masaudit can create it for
you when you answer the first-run question.

```ini
[masaudit]
app_type = content
fail_on = high
exclude = vendor/*, third_party/**
app_type_reviewed = ecommerce-cards
```

## Keys

| Key | Value | Effect |
|---|---|---|
| `app_type` | An app type or alias, such as `banking` or `news` | The app type, as if passed with `--app-type`. See [Choose your app type](app-type.md). |
| `fail_on` | `critical`, `high`, `medium`, or `low` | The `--fail-on` level when the command line doesn't set one. |
| `exclude` | Comma-separated globs, such as `vendor/*` | Paths not to scan. A path is skipped if it matches a glob, or sits under a folder that does. Some folders are always skipped; see [What masaudit reads](how-it-works.md#what-masaudit-reads-and-what-it-doesnt). |
| `app_type_reviewed` | Comma-separated app types | App types your team reviewed and decided against. masaudit doesn't raise "Check your app type" for them again. Evidence for any other riskier type still warns. See [Choose your app type](app-type.md#when-masaudit-says-check-your-app-type). |

## How masaudit reads the file

- The file has one section, `[masaudit]`.
- Unknown sections, unknown keys, and invalid values are an error (exit code 2), so a typo never
  silently changes what gets checked. `fail_on` has no `none` value; leave the key out instead.
- The command line overrides the file, and the file overrides the first-run question.
- The GitHub Action and the pre-commit hook read the same file, so commit it. The pre-commit hook
  passes its own `--fail-on high`, which overrides `fail_on`; see [pre-commit](ci.md#pre-commit).
