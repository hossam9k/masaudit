# Explain a rule or finding

Goal: the engineer understands the risk well enough to decide for themselves, in under a minute.

1. Get the rule text: `masaudit --explain RULE-ID` (works offline), or find it in
   [rules.md](rules.md).
2. Answer in this order, in plain words:
   - **What it is**, in one sentence, with no jargon (define any term you must use).
   - **What an attacker gains**, concretely, for *this* app's profile. If the profile doesn't need
     the control, say so and why: that answer is as valuable as a fix.
   - **The fix**, with the paste-ready snippet if there is one.
   - **How to verify** the fix worked.
   - **Read more**: the book section link from the rule.
3. If they push back ("we don't need this"), take it seriously: check the profile and the code. The
   scanner can be wrong about context; the book's reasoning for each control says when it applies.

To score a finding for a formal report, use [cvss-v4.md](cvss-v4.md).
