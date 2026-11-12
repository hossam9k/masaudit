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
| `--format md\|json\|sarif\|text` | Output format. Without it, masaudit prints a summary and writes `SECURITY-AUDIT.md` in the scanned folder. |
| `--output FILE` | Write the report to this file instead of the default. A relative path is relative to the current folder. |
| `--fail-on critical\|high\|medium\|low\|none` | Exit with code 1 if an open finding to fix is at or above this severity. Default: `fail_on` in `.masaudit.ini`; if neither is set, findings never change the exit code. `none` never fails on findings, even when `.masaudit.ini` sets `fail_on`. |
| `--fail-on-incomplete`, `--no-fail-on-incomplete` | Exit with code 1 if a file of a scanned type wasn't read: too large, binary content under a source file's name, a link, or past the file limit. Files your `exclude` setting leaves out don't count. Default: `fail_on_incomplete` in `.masaudit.ini`, else off. |
| `--import-sarif FILE [FILE ...]` | Add results from Android Lint, mobsfscan, Semgrep, zizmor, osv-scanner, or another tool's SARIF files. |
| `--sarif-include-not-needed` | With `--format sarif`: include *Not needed* findings, as notes. |
| `--no-color` | No colors in terminal output. |

## Baselines

| Option | What it does |
|---|---|
| `--update-baseline` | Write the current findings to the baseline file: the `--baseline` file if you give one, else `.masaudit-baseline.json` in the scanned folder. |
| `--baseline FILE` | Treat findings listed in this baseline as accepted. A relative path is relative to the current folder, not the scanned folder. A missing file is an error (exit code 2). Entries that match no finding, and entries past their `expires` date, are listed in the report. |
| `--baseline-reason TEXT` | With `--update-baseline`: the reason recorded on each new entry, shown wherever its finding is listed as accepted. Entries already in the file keep theirs. |
| `--baseline-expires YYYY-MM-DD` | With `--update-baseline`: after this date the new entries' findings count again. |

## Safe fixes

| Option | What it does |
|---|---|
| `--fix-safe` | Print a diff of the safe fixes. Changes nothing, and exits 0. |
| `--write-patch [FILE]` | With `--fix-safe`: also save the diff (default `masaudit-fixes.patch`). |
| `--yes` | With `--fix-safe`: apply the fixes in place. Needs a clean git tree; untracked files, including `SECURITY-AUDIT.md`, count as changes. Refuses if the repository's own `.git/config` sets a filter or diff command, because `git status` would run it. |

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
| `1` | At least one open finding is at or above `--fail-on`, or, with `--fail-on-incomplete`, a file of a scanned type wasn't read. masaudit prints which. |
| `2` | Tool error: for example a missing folder, an invalid `.masaudit.ini` or option, an unknown rule ID in `--explain`, `--yes` on a folder that isn't a clean git tree, or an internal error. |

## Where settings come from

The command line overrides `.masaudit.ini`, and `.masaudit.ini` overrides the first-run question. See
the [config file reference](config.md).

## Environment variables

| Variable | Effect |
|---|---|
| `NO_COLOR`, or `TERM=dumb` | No colors in terminal output, like `--no-color`. |
| `CI` | Set to any value, even `false`: never ask the first-run question. masaudit also skips the question when standard input isn't a terminal. Without an app type, it uses `general` and says so. |
| `GITHUB_ACTIONS=true` | Also print "Check your app type" as a GitHub Actions annotation. |
| `SOURCE_DATE_EPOCH` | Use this date, in seconds since 1970, as the report date, for reproducible reports. |
