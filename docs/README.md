# masaudit documentation

masaudit is a free mobile security scanner for Android, iOS, Kotlin Multiplatform, and Flutter source
code. It scales its advice to your app's risk. New here? Start with the
[quick start](https://github.com/hossam9k/masaudit#quick-start-no-ai-needed), then come back.

## Guides, in the order you'll need them

1. **[Install and run](usage.md#install-or-run):** every way to run masaudit, including a single
   offline file.
2. **[Choose your app type](usage.md#choose-your-app-type):** the one question masaudit asks, what each
   type means, and the ["Check your app type"](usage.md#check-your-app-type) warning.
3. **[Read the report](usage.md#read-the-report):** what each section of `SECURITY-AUDIT.md` tells you.
4. **[Fix findings](usage.md#preview-and-apply-safe-fixes):** paste-ready fixes, and the one fix
   masaudit can apply for you.
5. **[Options and exit codes](usage.md#options):** every command-line option.
6. **[Config file](usage.md#config-file-masauditini):** per-project settings in `.masaudit.ini`.
7. **[CI and pre-commit](ci.md):** the GitHub Action, pinning it safely, and other CI systems.
8. **[Team features](usage.md#team-features):** suppressions with reasons, baselines for older apps, and
   results from Android Lint, mobsfscan, Semgrep, and zizmor.
9. **[AI assistants](ai-assistants.md):** Claude Code commands, other tools that read Agent Skills,
   and any chat assistant.

## Reference

- **[Rules](rules.md):** all rules, each with why it matters, the fix, how to verify it, OWASP IDs, and
  the book section.
- **[Accuracy and speed](precision.md):** how every rule was measured on 19 open-source apps.
- **Sample reports:** the same demo app as a [banking app](sample-report-banking.md) and as a
  [news app](sample-report-news.md).
- **[Writing a rule](writing-rules.md)** and
  [CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md).
- **[Security policy](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md):** reporting a
  vulnerability, and checking that a download is genuine.
- **[Changelog](https://github.com/hossam9k/masaudit/blob/main/CHANGELOG.md).**
- **The book:** [*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security),
  which every rule cites.

## Questions people ask first

**Do I need AI, an account, or the internet?**
No. masaudit runs on your machine with Python 3.9 or later. The single-file `masaudit.pyz` works fully
offline. An [AI assistant](ai-assistants.md) is optional.

**Does it upload my code, or run it?**
No. It makes no network calls (a test enforces it), sends no telemetry, and never builds or runs your
code. It only reads files.

**Which projects does it scan?**
Android, iOS, Kotlin Multiplatform, and Flutter source code, plus GitHub Actions workflows. In a React
Native app it scans the `android/` and `ios/` folders but not the JavaScript code yet. It doesn't read
built APK or IPA files; [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) does that,
and the two work well together.

**Does it work on Windows?**
Yes. CI tests it on Linux, macOS, and Windows with Python 3.9 to 3.14.

**Which app type should I pick?**
The one that matches what your app protects. If two fit, pick the riskier one. If the code suggests a
riskier type than your choice, masaudit tells you. See
[Choose your app type](usage.md#choose-your-app-type).

**Why does the report say a finding is "Not needed"?**
Some protections only pay off for high-risk apps. Certificate pinning, for example, helps a banking
app but adds outage risk to a news app. masaudit still lists these findings, with the reason, so you
can decide.

**A finding is wrong for my code. What do I do?**
Suppress it with a written reason (see [Team features](usage.md#team-features)) and, if the rule
itself is wrong, send a
[false-positive report](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).
It's the most useful contribution you can make.

**Is it free?**
Yes. The code is Apache-2.0, and the fix snippets are MIT-0, so you can paste them into any app.
