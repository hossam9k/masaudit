---
description: Audit this mobile project and write SECURITY-AUDIT.md, scaled to the app's risk
argument-hint: "[app type, e.g. banking or news]"
---
Use the masaudit skill to audit this project, following its audit workflow
(`${CLAUDE_PLUGIN_ROOT}/skills/masaudit/references/workflow-audit.md`).

App type from the user, if given: $ARGUMENTS
If no app type was given and there's no `.masaudit.ini`, ask the profile question first.
