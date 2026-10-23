---
description: Fix the findings in SECURITY-AUDIT.md one at a time, verifying each
argument-hint: "[rule ID or 'all']"
---
Use the masaudit skill to fix findings, following its fix workflow
(`${CLAUDE_PLUGIN_ROOT}/skills/masaudit/references/workflow-fix.md`).

Which findings: $ARGUMENTS (default: all confirmed findings, most severe first).
Ask before any behavior-changing fix. Never commit or push.
