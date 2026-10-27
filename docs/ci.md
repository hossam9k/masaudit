[masaudit documentation](README.md) › Use masaudit in CI

# Use masaudit in CI

This page shows how to scan every push and pull request with the GitHub Action, scan before each
commit with pre-commit, or run masaudit in another CI system: Bitrise, CircleCI, GitLab CI/CD,
Travis CI, or Docker.

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
      - uses: actions/checkout@<commit-sha> # v7
        with:
          persist-credentials: false
      - uses: hossam9k/masaudit@<commit-sha> # v0.7.0
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
   git ls-remote https://github.com/hossam9k/masaudit 'refs/tags/v0.7.0^{}'
   ```

   For `actions/checkout`, run the same command with its repository and tag.
2. Paste the ID after the `@`.
3. Keep the version as a comment after the ID, for example `# v0.7.0`.

If you turn on Dependabot version updates for GitHub Actions, Dependabot updates the commit IDs and
the version comments.

### Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Project folder to scan. |
| `app-type` | `app_type` in `.masaudit.ini`, else `general` | The app type. See [Choose your app type](app-type.md). |
| `fail-on` | `fail_on` in `.masaudit.ini`, else `high` | Fail the job on findings at or above `critical`, `high`, `medium`, or `low`. Use `none` to never fail on findings, whatever `.masaudit.ini` says. |
| `baseline` | None | A baseline file from `masaudit --update-baseline`, relative to the repository root. Its findings are accepted and don't fail the job. See [Adopt masaudit in an older app](team.md#adopt-masaudit-in-an-older-app). |
| `upload-sarif` | `true` | Upload results to GitHub code scanning. Needs `security-events: write`. |
| `category` | `masaudit` | The code-scanning category. If you scan several folders in one repository, give each `path` its own category. |

### What the Action does

- The scan runs from the Action's own pinned source: it downloads nothing and makes no network calls.
- Results appear in the repository's **Security** tab. Pull requests from forks skip the upload.
- File paths in results and annotations are relative to the repository root, even when `path` is a
  subfolder.
- It writes `SECURITY-AUDIT.md` in the job's working folder, and puts the verdict and top fixes in
  the job summary, on the run's page.
- If the scan itself fails (exit code 2), the step fails with an error annotation.
- It runs with the runner's `python3` (3.9 or later); GitHub-hosted runners include it.
- If the code suggests a riskier app type than the one set, the run shows a
  "Check your app type" annotation.

## pre-commit

To scan before every commit, add this to `.pre-commit-config.yaml`
([pre-commit](https://pre-commit.com/)):

```yaml
repos:
  - repo: https://github.com/hossam9k/masaudit
    rev: v0.7.0
    hooks:
      - id: masaudit
        args: [--app-type, banking]
```

The hook runs `masaudit --fail-on high --format text` and stops the commit on high or critical
findings to fix (findings under *Check by hand* and the *Hardening checklist* never stop it). It reads every key in `.masaudit.ini`, but its `--fail-on high` overrides `fail_on`. To use
another level, add it to `args`, for example `args: [--app-type, banking, --fail-on, medium]`. To pin
the hook to a commit, run `pre-commit autoupdate --freeze`.

## Other CI systems

Any CI that has Python 3.9 or later can run masaudit: install it from PyPI and run the command line.
masaudit needs no other package and no network access while it scans. Pin the version, so a new
release changes your results only when you update it:

```bash
python3 -m pip install masaudit==0.7.0
python3 -m masaudit . --app-type banking --format sarif --output masaudit.sarif --fail-on high
```

The exit code is 1 when open findings reach `--fail-on`, and 2 on a tool error. Without `--fail-on`
or `fail_on`, findings never fail the job. See [Exit codes](cli.md#exit-codes).

Paths in the SARIF file are relative to the scanned folder. To upload it to GitHub code scanning
after scanning a subfolder, use the GitHub Action, which makes them relative to the repository root.

The examples below save a Markdown report you can open from the build page. Use `--format sarif` when
another tool reads the report.

### Bitrise

Add a Script step to your workflow in `bitrise.yml`. The Bitrise macOS and Linux stacks come with
Python 3. *Deploy to Bitrise.io* attaches the report to the build's artifacts:

```yaml
- script@1:
    title: masaudit
    inputs:
    - content: |
        set -e
        python3 -m pip install --quiet masaudit==0.7.0
        python3 -m masaudit . --app-type banking --format md \
          --output "$BITRISE_DEPLOY_DIR/masaudit.md" --fail-on high
- deploy-to-bitrise-io@2: {}
```

### CircleCI

In `.circleci/config.yml`; `when: always` keeps the report when the scan fails the job:

```yaml
version: 2.1
jobs:
  masaudit:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run: python3 -m pip install --quiet masaudit==0.7.0
      - run: python3 -m masaudit . --app-type banking --format md --output masaudit.md --fail-on high
      - store_artifacts:
          path: masaudit.md
          when: always
workflows:
  scan:
    jobs:
      - masaudit
```

### GitLab CI/CD

In `.gitlab-ci.yml`; `when: always` keeps the report when the scan fails the job, and it shows under the
job's artifacts:

```yaml
masaudit:
  image: python:3.12-slim
  script:
    - python3 -m pip install --quiet masaudit==0.7.0
    - python3 -m masaudit . --app-type banking --format md --output masaudit.md --fail-on high
  artifacts:
    when: always
    paths:
      - masaudit.md
```

### Travis CI

In `.travis.yml`. Travis has no artifact store of its own, so the report goes to the job log:

```yaml
language: python
python: "3.12"
install: python3 -m pip install --quiet masaudit==0.7.0
script: python3 -m masaudit . --app-type banking --fail-on high
```

### Docker

There is no masaudit image: run it in the official Python image, with your project mounted. The report
is written to the project folder:

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim sh -c \
  "pip install --quiet masaudit==0.7.0 && masaudit . --app-type banking --format md --output masaudit.md --fail-on high"
```

The same command runs in any CI that runs Docker steps, such as Jenkins.

## Share settings between CI and local runs

Commit a `.masaudit.ini` with `app_type` and `fail_on`, so the Action, the pre-commit hook, and local
runs use the same settings. The hook's own `--fail-on high` overrides `fail_on`; see
[pre-commit](#pre-commit).

## Next steps

- **Fail only on new findings in an older app:** [Adopt masaudit in an older app](team.md#adopt-masaudit-in-an-older-app).
- **Every option and exit code:** [Command-line reference](cli.md).
