[masaudit documentation](README.md) › Use masaudit in a team

# Use masaudit in a team

These features let a team share settings, record decisions, adopt masaudit in an older app without
fixing everything at once, and bring in results from other tools.

Commands on this page start with `masaudit`. If you run it with uv, type `uvx masaudit` instead;
[Install and upgrade](install.md) lists the other ways.

## Share one configuration

Commit a `.masaudit.ini` in the folder you scan, so every developer and CI use the same settings. The
pre-commit hook overrides `fail_on`; see [pre-commit](ci.md#pre-commit).

```ini
[masaudit]
app_type = banking
fail_on = high
exclude = vendor/*, third_party/**
```

Every key is described in the [config file reference](config.md).

## Suppress a finding, with a reason

When a finding doesn't apply, put a comment on its line or on the line above, with a reason your team
can review later:

- Kotlin, Java, or Swift: `// masaudit:ignore AND-004 test server only, never in release`
- XML: `<!-- masaudit:ignore AND-015 reachable only with our signature permission -->`
- YAML, such as a workflow: `# masaudit:ignore CI-001 internal action, reviewed 2026-10`

To suppress several rules on one line, separate the IDs with commas. Block comments (`/* */`) work
too.

A finding without a line number, such as *No certificate pinning* on iOS, can't be suppressed with a
comment. Accept it with a [baseline](#adopt-masaudit-in-an-older-app) instead.

A suppression without a reason is ignored and reported. Suppressed findings move to *Accepted earlier
(not counted)* in the report, with the reason.

masaudit also respects decisions you already recorded for other tools: Android Lint's `tools:ignore`
and `lint.xml`, and `zizmor.yml` policies. It lowers those findings one level and shows the reason,
without hiding them.

## Adopt masaudit in an older app

An older app may have many findings. To fail CI only on new ones, record today's findings as a
baseline:

```bash
masaudit . --update-baseline                        # saves findings to .masaudit-baseline.json
masaudit . --baseline .masaudit-baseline.json       # shows them as Accepted; fails only on new ones
```

Commit `.masaudit-baseline.json` and fix the accepted findings over time. In CI, pass the file with
`--baseline`, or with the Action's `baseline` input:

```yaml
- uses: hossam9k/masaudit@<commit-sha> # v0.7.1
  with:
    app-type: banking
    baseline: .masaudit-baseline.json
```

A finding stays accepted while its file path and the text of its line stay the same.

Say why each finding is accepted, and until when. The reason appears wherever the finding is listed as
accepted: in the report, the SARIF suppression, and the Action's job summary, where a pull request's
reviewer sees it.

```bash
masaudit . --update-baseline --baseline-reason SEC-142 --baseline-expires 2027-03-31   # a ticket that tracks the fix
```

Each entry in the file can also be edited by hand:

```json
"9f2c...": {"rule": "AND-001", "path": "app/src/main/AndroidManifest.xml", "line": 3,
            "reason": "legacy login, removed in 3.0", "expires": "2027-03-31"}
```

- **`reason`:** kept when you run `--update-baseline` again; new entries get this run's
  `--baseline-reason`.
- **`expires`:** after this date the finding counts again and the report says the entry expired.
  `--update-baseline` never moves the date: renew it on purpose, with a new reason.
- **Stale entries:** an entry whose finding is gone (fixed, moved, or excluded) is listed in the
  report and the JSON `baseline.stale` count. Run `--update-baseline` to remove it.

Files from earlier versions (without `reason` or `expires`) still work.

## Bring results from other tools

```bash
masaudit . --import-sarif lint.sarif mobsfscan.sarif
```

masaudit reads SARIF files from Android Lint, mobsfscan, Semgrep, zizmor, and other tools, and sorts their
results into the same buckets for your app type, in one report. Text from an imported file is treated
as untrusted: it is masked, kept to one line, and can't add links or headings to the report.

### Known vulnerabilities in dependencies

masaudit never uses the network, so it doesn't look up vulnerabilities in the versions your lockfiles
pin. [osv-scanner](https://github.com/google/osv-scanner) does; import its results so they're sorted
with everything else:

```bash
osv-scanner scan source --format sarif --output osv.sarif .
masaudit . --import-sarif osv.sarif
```

Each vulnerable package becomes a finding on its lockfile, with the advisory's severity and a link to
it, under the book's section on [dependencies and build inputs](https://github.com/hossam9k/mobile-app-security/blob/main/book/06-the-build-and-release-pipeline.md#154-dependencies-and-build-inputs).

## Next steps

- **Every setting:** [Config file reference](config.md).
- **Scan every pull request:** [Use masaudit in CI](ci.md).
