[masaudit documentation](README.md) › Read and fix the report

# Read and fix the report

After a scan, masaudit writes `SECURITY-AUDIT.md`. This page shows how to read it, what to fix first,
and how to check each fix.

## What's in the report

The report opens with a **verdict** for your app type and the **top fixes** (up to three), then one
section per bucket. [Output formats](output-formats.md#markdown) lists every section and what to do
with it.

Each finding shows where it is (file and line), why it matters, how to fix it (often with
paste-ready code), how to verify the fix, roughly how long it takes, its OWASP IDs, and the book
section that explains it. Findings marked *Check by hand* need a person or an AI assistant to confirm
them.

A finding in test or debug code is still listed, at a lower severity, because that code usually
doesn't ship. The *Accepted earlier* section appears only when you have suppressions or a baseline.

## Fix in this order

1. **Top fixes,** from the start of the report.
2. The rest of **Fix before release**.
3. **Fix soon,** in the order listed.

After each fix, run the finding's **How to verify** step, then scan again to confirm the finding is
gone and nothing new appeared.

## Look up a rule

To read what a rule checks, why it matters, and how to fix it, offline:

```bash
masaudit --explain AND-004
masaudit --list-rules
```

Every rule is also in the [rules reference](rules.md).

## Let masaudit apply a safe fix

masaudit applies only fixes that can't change how a correct app behaves. Today that's one: removing
`android:debuggable="true"` from the `<application>` tag of every `AndroidManifest.xml` that isn't
debug-only.

```bash
masaudit . --fix-safe                  # print the diff; changes nothing
masaudit . --fix-safe --write-patch    # also save it as masaudit-fixes.patch
masaudit . --fix-safe --yes            # apply it in place (needs a clean git tree)
```

`--yes` needs a clean git tree, and an untracked `SECURITY-AUDIT.md` counts as a change. Commit the
report, delete it, or add it to `.gitignore` before you run `--yes`.

masaudit never edits Gradle files. For `isDebuggable = true` in a Gradle release build type, the
report's fix tells you the change to make by hand.

Every other finding has a fix in the report for you to apply, or an
[AI assistant](ai-assistants.md) can apply it with you, one finding at a time.

## When a finding is wrong for your code

If a finding doesn't apply, suppress it with a written reason (see
[Suppress a finding](team.md#suppress-a-finding-with-a-reason)). If the rule itself is wrong, send
a [false-positive report](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).

## Next steps

- **Scan every pull request:** [Use masaudit in CI](ci.md).
- **Fix an older app over time:** [Adopt masaudit in an older app](team.md#adopt-masaudit-in-an-older-app).
