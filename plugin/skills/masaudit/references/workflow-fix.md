# Fix what the audit found

Goal: each confirmed finding fixed, verified, and explained, without breaking the app.

## Before you start

- You need an audit (`SECURITY-AUDIT.md`). If there isn't one, run the audit workflow first.
- Check the git state (`git status`). If there are uncommitted changes, ask whether to continue:
  mixing your edits with theirs makes review harder.
- Never commit or push. The engineer reviews and commits.

## One finding at a time, most severe first

For each confirmed finding:

1. **Read the fix.** Start from the rule's `fix` and `fix_code` (in the report, `rules.md`, or the
   `fixes-*.md` files). These snippets are verified against the book and licensed MIT-0, so they can
   go into any app.
2. **Classify the change.**
   - *Mechanical, no behavior change* (removing `android:debuggable="true"` from a production
     manifest): you can apply it. `masaudit . --fix-safe` previews exactly these as a diff.
   - *Behavior-affecting* (turning off cleartext, `FLAG_IMMUTABLE`, un-exporting a component,
     adding pins, raising minSdk, tightening workflow permissions): explain what could break and ask
     first. Example: "Turning off cleartext breaks any `http://` endpoint. I found these three; are
     they all moved to HTTPS?"
   - *Server-side* (authorization, token binding, attestation verification): don't write backend
     code you can't see. Write a ticket the user can hand to the backend team: the problem, the
     risk, the fix, and how to verify it, with the book link.
3. **Make the smallest correct edit.** Match the project's style. Don't refactor nearby code.
4. **Verify.** Re-run `masaudit` and confirm the finding is gone and nothing new appeared. If the
   project has tests or a build and the user agreed, run them. Otherwise say exactly how to verify
   (the rule's `verify` text).
5. **Record it.** Keep a short running list: finding, file, what changed, how it was verified.

## Pinning: extra care

Pinning done badly locks every user out until a store update. Only add pins when the profile needs
them (banking, identity, health, apps that handle cards) and the team agrees to operate them:
pin the SPKI of an intermediate, ship a backup pin at a second CA, set an expiration on Android,
and document the rotation runbook (new pin ships long before the new key serves traffic).
See [fixes-android.md](fixes-android.md) and [fixes-ios.md](fixes-ios.md).

## When you're done

Summarize: what's fixed (with files), what's waiting on the user's decision, what needs the backend
team, and the commands to verify everything. Suggest a commit message, but don't commit.
