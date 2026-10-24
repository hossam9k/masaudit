[masaudit documentation](README.md) › Use masaudit in a team

# Use masaudit in a team

These features let a team share settings, record decisions, adopt masaudit in an older app without
fixing everything at once, and bring in results from other tools.

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
- uses: hossam9k/masaudit@<commit-sha> # v0.4.3
  with:
    app-type: banking
    baseline: .masaudit-baseline.json
```

A finding stays accepted while its file path and the text of its line stay the same.

## Bring results from other tools

```bash
masaudit . --import-sarif lint.sarif mobsfscan.sarif
```

masaudit reads SARIF files from Android Lint, mobsfscan, Semgrep, and zizmor, and sorts their results
into the same buckets for your app type, in one report.

## Next steps

- **Every setting:** [Config file reference](config.md).
- **Scan every pull request:** [Use masaudit in CI](ci.md).
