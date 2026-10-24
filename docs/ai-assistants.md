[masaudit documentation](README.md) › Use masaudit with an AI assistant

# Use masaudit with an AI assistant

masaudit works on its own; an assistant is optional. With one, you get a second pass: the
assistant confirms each finding in your real code, looks for what a scanner can't see, and applies
fixes one at a time with you.

## Claude Code

Install the plugin once:

```text
/plugin marketplace add hossam9k/masaudit
/plugin install masaudit@masaudit
```

If the `/masaudit:` commands don't appear, restart Claude Code.

Then use a command, or ask in your own words, for example *"Is my app ready for a pentest?"*

| Command | What it does |
|---|---|
| `/masaudit:scan [app type]` | Audits the project and writes `SECURITY-AUDIT.md`, scaled to the app's risk. |
| `/masaudit:fix [rule ID or all]` | Fixes the findings in `SECURITY-AUDIT.md` one at a time, verifying each. |
| `/masaudit:review [PR number, branch, or staged]` | Reviews a pull request, a branch, or staged changes. |
| `/masaudit:explain <rule ID>` | Explains a rule or a finding in plain language, for example `AND-004`. |

## Codex, GitHub Copilot, Cursor, Gemini CLI, and other tools

Any tool that reads [Agent Skills](https://agentskills.io) can use masaudit. Copy the
[skill folder](https://github.com/hossam9k/masaudit/tree/main/plugin/skills/masaudit) into your
tool's skills folder (your tool's documentation says where that is):

```bash
git clone --depth 1 https://github.com/hossam9k/masaudit
cp -R masaudit/plugin/skills/masaudit <your tool's skills folder>/
```

The skill bundles the scanner (`scripts/masaudit.pyz`), so it works offline. It needs Python 3.9 or
later.

## Any chat assistant

Every `SECURITY-AUDIT.md` ends with a *Fix plan for your AI assistant*. Paste it into the chat. The
plan marks code from your project as data, not instructions, but a chat assistant can still be misled
by text in your code. Review every change it suggests before you apply it.

## What the assistant does, and doesn't do

- **Confirms each finding in context,** so you fix real issues first.
- **Looks for what a scanner can't see,** such as server-side trust, biometric flows, and how tokens
  are handled.
- **Fixes one finding at a time,** then runs masaudit again to confirm the finding is gone and
  nothing new appeared, and tells you how to verify it in the app.
- **Asks before any fix that changes behavior,** such as turning off cleartext traffic.
- **Never commits** and never pushes. You review every change.
- **Respects your app type.** If the code suggests a riskier one, it says why and asks; it doesn't
  switch on its own.

## Next steps

- **Read the report yourself:** [Read and fix the report](fixing.md).
- **What a scanner can't see:** [How masaudit works](how-it-works.md#what-masaudit-reads-and-what-it-doesnt).
