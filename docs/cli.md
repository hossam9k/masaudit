[masaudit documentation](README.md) › Command-line reference

# Command-line reference

```text
masaudit [PATH] [options]
```

`PATH` is the project folder to scan; it defaults to the current folder. If you run masaudit another
way, type `uvx masaudit`, `pipx run masaudit`, or `python3 masaudit.pyz` in place of `masaudit`. See
[Install and upgrade](install.md).

## Scan options

| Option | What it does |
|---|---|
| `--app-type TYPE` | The app type. See [Choose your app type](app-type.md) for the list. |
| `--format md\|json\|sarif\|text` | Output format. Without it, masaudit prints a summary and writes `SECURITY-AUDIT.md`. |
| `--output FILE` | Write the report to this file instead of the default. |
| `--fail-on critical\|high\|medium\|low` | Exit with code 1 if an open finding to fix is at or above this severity. Default: `fail_on` in `.masaudit.ini`; if neither is set, findings never change the exit code. |
| `--import-sarif FILE [FILE ...]` | Add results from Android Lint, mobsfscan, Semgrep, or zizmor SARIF files. |
| `--sarif-include-not-needed` | With `--format sarif`: include *Not needed* findings, as notes. |
| `--no-color` | No colors in terminal output. |

## Baselines

| Option | What it does |
|---|---|
| `--update-baseline` | Write the current findings to the baseline file (default `.masaudit-baseline.json`). |
| `--baseline FILE` | Treat findings listed in this baseline as accepted. A relative path is relative to the current folder. |

## Safe fixes

| Option | What it does |
|---|---|
| `--fix-safe` | Print a diff of the safe fixes. Changes nothing, and exits 0. |
| `--write-patch [FILE]` | With `--fix-safe`: also save the diff (default `masaudit-fixes.patch`). |
| `--yes` | With `--fix-safe`: apply the fixes in place. Needs a clean git tree. |

## Rules and version

| Option | What it does |
|---|---|
| `--explain RULE-ID` | Print what a rule checks, why it matters, and how to fix it. Works offline. |
| `--list-rules` | List every rule. |
| `--version` | Print the masaudit and rules versions. |
| `-h`, `--help` | Print the options. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan finished, and no open finding is at or above the `--fail-on` level (or no level is set). |
| `1` | At least one open finding is at or above `--fail-on`. masaudit prints how many. |
| `2` | Tool error: for example a missing folder, an invalid `.masaudit.ini` or option, an unknown rule ID in `--explain`, `--yes` on a folder that isn't a clean git tree, or an internal error. |

## Where settings come from

The command line overrides `.masaudit.ini`, and `.masaudit.ini` overrides the first-run question. See
the [config file reference](config.md).

## Environment variables

| Variable | Effect |
|---|---|
| `NO_COLOR`, or `TERM=dumb` | No colors in terminal output, like `--no-color`. |
| `CI` | Never ask the first-run question. Without an app type, masaudit uses `general` and says so. |
| `GITHUB_ACTIONS=true` | Also print "Check your app type" as a GitHub Actions annotation. |
| `SOURCE_DATE_EPOCH` | Use this date, in seconds since 1970, as the report date, for reproducible reports. |
