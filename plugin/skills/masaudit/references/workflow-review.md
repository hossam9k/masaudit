# Review a diff or pull request

Goal: catch security regressions before they merge, with comments a reviewer can paste.

1. **Get the change.** A PR number (`gh pr diff <n>`), a branch (`git diff main...HEAD`), or staged
   changes (`git diff --cached`). List the changed files.
2. **Scan the whole project, then filter.** Run masaudit as in the audit workflow and keep only
   findings in changed files and lines. A finding on an untouched line is pre-existing: mention it
   once at the end, not as a review comment.
3. **Read every changed hunk** with the profile in mind. Look hardest at: storage of tokens or
   personal data, network configuration and TLS handling, WebView settings and JavaScript bridges,
   manifest changes (exported components, permissions, backup, deep links), biometric and
   authentication flows, new third-party SDKs, logging, and `.github/workflows/` changes.
4. **Write comments** in this shape, one per issue:

   > **[High] Exported activity without a permission** (`AND-0xx`, app/src/main/AndroidManifest.xml:42)
   > Any app on the device can start `PaymentActivity` with crafted extras. Add
   > `android:exported="false"`, or require a signature-level permission if another app of yours
   > needs it. Why: book §17.1.

5. **End with a verdict:** approve, approve with comments, or request changes, plus one line on
   what the change does well (a review that only lists problems gets ignored).

Severity follows the profile: don't block a news app's PR for missing pinning.
