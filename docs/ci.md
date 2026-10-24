[masaudit documentation](README.md) › Use masaudit in CI

# Use masaudit in CI

This page shows how to scan every push and pull request with the GitHub Action, scan before each
commit with pre-commit, or run masaudit in another CI system.

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
      - uses: hossam9k/masaudit@<commit-sha> # v0.4.2
        with:
          app-type: banking
          fail-on: high
```

In a private repository, also grant `actions: read`. If code scanning isn't available for the
repository, set `upload-sarif: false`.

### Pin to a commit, not a tag

A tag can be moved to other code; a commit ID can't. Replace each `<commit-sha>` with the full
40-character commit ID of the release you want:

1. Find the commit ID of the tag. For masaudit, run:

   ```bash
   git ls-remote https://github.com/hossam9k/masaudit 'refs/tags/v0.4.2^{}'
   ```

   For `actions/checkout`, run the same command with its repository and tag.
2. Paste the ID after the `@`.
3. Keep the version as a comment after the ID, for example `# v0.4.2`.

If you turn on Dependabot version updates for GitHub Actions, Dependabot updates the commit IDs and
the version comments.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Project folder to scan. |
| `app-type` | `app_type` in `.masaudit.ini`, else `general` | The app type. See [Choose your app type](app-type.md). |
| `fail-on` | `fail_on` in `.masaudit.ini`, else `high` | Fail the job on findings at or above `critical`, `high`, `medium`, or `low`. Use `none` to never fail. |
| `baseline` | None | A baseline file from `masaudit --update-baseline`, relative to the repository root. Its findings are accepted and don't fail the job. See [Adopt masaudit in an older app](team.md#adopt-masaudit-in-an-older-app). |
| `upload-sarif` | `true` | Upload results to GitHub code scanning. Needs `security-events: write`. |

### What the Action does

- The scan runs from the Action's own pinned source: it downloads nothing and makes no network calls.
- Results appear in the repository's **Security** tab. Pull requests from forks skip the upload.
- It also writes `SECURITY-AUDIT.md` in the job's working folder.
- If the code suggests a riskier app type than the one set, the run shows a
  "Check your app type" annotation.

## pre-commit

To scan before every commit, add this to `.pre-commit-config.yaml`
([pre-commit](https://pre-commit.com/)):

```yaml
repos:
  - repo: https://github.com/hossam9k/masaudit
    rev: v0.4.2
    hooks:
      - id: masaudit
        args: [--app-type, banking]
```

The hook runs `masaudit --fail-on high --format text` and stops the commit on high or critical
findings. A `--fail-on` in `args` replaces `high`. To pin the hook to a commit, run
`pre-commit autoupdate --freeze`.

## Other CI systems

Run the command line directly. For example:

```bash
pipx run masaudit . --app-type banking --format sarif --output masaudit.sarif --fail-on high
```

The exit code is 1 when open findings reach `--fail-on`, and 2 on a tool error. Without `--fail-on`
or `fail_on`, findings never fail the job. See [Exit codes](cli.md#exit-codes).

## Share settings between CI and local runs

Commit a `.masaudit.ini` with `app_type` and `fail_on`, so the Action and local runs use the same
settings. The pre-commit hook reads `app_type` and `exclude` from the file, but it always passes
`--fail-on high`. To use another level in the hook, add it to `args`, for example
`args: [--app-type, banking, --fail-on, medium]`.
