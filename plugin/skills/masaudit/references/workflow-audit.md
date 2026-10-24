# Audit a project

Goal: a `SECURITY-AUDIT.md` the engineer can act on today, with every finding confirmed or clearly
marked as needing a human look.

## 1. Scan

From the project root (replace `TYPE` with the app type from the profile question):

```bash
masaudit . --app-type TYPE --format json --output masaudit.json
masaudit . --app-type TYPE --format md --output SECURITY-AUDIT.md
```

(or `python3 <skill-folder>/scripts/masaudit.pyz ...` with the same arguments)

Read `masaudit.json`: each finding has `rule_id`, `path`, `line`, `effective_severity` (for this app
type and file; `severity` is the rule's default), `bucket` (`fix-before-release`, `fix-soon`,
`notes`, `not-needed`), `status` (`open`, `suppressed`, `baselined`), `confidence`, and the rule's
`why`/`fix`.
`unknowns` lists things the scanner couldn't decide.

If other tools already ran (Android Lint, mobsfscan, Semgrep, zizmor), pass their SARIF with
`--import-sarif FILE` so their results are calibrated too.

## 2. Triage, most severe first

For each finding with `status: open` in `fix-before-release` and `fix-soon`, most severe
`effective_severity` first:

1. Open the file at the line. Read enough around it to understand the context.
2. Decide: **confirmed** (the risk is real here), **false positive** (explain why in one line), or
   **check by hand** (you can't tell without runtime or server information; say what to check).
3. Findings with `confidence: manual` need this step most. `high` ones are usually right, but
   still look: a debug-only path or a test helper changes the answer.

Don't re-litigate `not-needed` findings unless the code shows the profile is wrong (for example, a
"content" app that stores card numbers). If it is wrong, tell the user and suggest re-running
with the right type rather than overriding the scanner yourself.

## 3. Look beyond the scanner

Spend real attention here: it's where you add value over the tool. Follow
[beyond-the-scanner.md](beyond-the-scanner.md), focusing on what the profile needs: how tokens are
stored and refreshed, whether biometric prompts are bound to keys, whether the client decides
anything the server should, how deep links are handled, and what the app sends to analytics or AI
services. Report anything you find as an extra finding with the same evidence standard: a file,
a line, and why it matters.

## 4. Finish the report

Keep the scanner's `SECURITY-AUDIT.md` structure and append a section:

```markdown
## AI triage notes

Reviewed by an AI assistant using the masaudit skill on <date>. Profile: <type>.

| Finding | Verdict | Note |
|---|---|---|
| AND-015 app/src/main/AndroidManifest.xml:12 | Confirmed | Exported without a permission; handles payment intents. |
| XPL-007 core/Crypto.kt:40 | False positive | MD5 is used for a cache key, not for security. |

### Additional findings (not detected by the scanner)
...
```

Then tell the user, in a few lines: the top 3 fixes, how long they'll take, and that you can apply
them (the fix workflow). Delete `masaudit.json` unless they want to keep it.
