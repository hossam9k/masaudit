[masaudit documentation](README.md) ›

# Running masaudit in CI

## GitHub Action

Add this file as `.github/workflows/masaudit.yml`:

```yaml
name: masaudit
on: [push, pull_request]
permissions: {}
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write          # to show results in GitHub code scanning
    steps:
      - uses: actions/checkout@<commit-sha>
        with:
          persist-credentials: false
      - uses: hossam9k/masaudit@<commit-sha> # v0.4.1
        with:
          app-type: banking
          fail-on: high
```

### Pin to a commit, not a tag

Replace each `<commit-sha>` with the full 40-character commit ID of the release you want:

1. Open the action's Releases page.
2. Click the tag.
3. Copy the commit ID.

A tag can be moved to other code; a commit ID can't. Dependabot keeps the IDs current.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Project folder to scan. |
| `app-type` | `app_type` in `.masaudit.ini`, else `general` | The app type. See [Choose your app type](usage.md#choose-your-app-type). |
| `fail-on` | `fail_on` in `.masaudit.ini`, else `high` | Fail the job on findings at or above `critical`, `high`, `medium`, or `low`. Use `none` to never fail. |
| `upload-sarif` | `true` | Upload results to GitHub code scanning. Needs `security-events: write`. |

### What the Action does

- The scan runs from the Action's own pinned source: it downloads nothing and makes no network calls.
- Results appear in the repository's **Security** tab. Pull requests from forks skip the upload.
- It also writes `SECURITY-AUDIT.md` in the job's working folder.
- If the code suggests a riskier app type than the one set, the run shows a
  "check your app type" annotation.

## pre-commit

To scan before every commit, add this to `.pre-commit-config.yaml`
([pre-commit](https://pre-commit.com/)):

```yaml
repos:
  - repo: https://github.com/hossam9k/masaudit
    rev: v0.4.1
    hooks:
      - id: masaudit
        args: [--app-type, banking]
```

The hook runs `masaudit --fail-on high --format text` and stops the commit on high or critical
findings.

## Other CI systems

Run the command line directly. For example:

```bash
pipx run masaudit . --app-type banking --format sarif --output masaudit.sarif --fail-on high
```

The exit code is 1 when open findings reach `--fail-on`, and 2 on a tool error. See
[Exit codes](usage.md#exit-codes).

Tip: commit a `.masaudit.ini` with `app_type` and `fail_on`, so the Action, the pre-commit hook, and
local runs all use the same settings.
