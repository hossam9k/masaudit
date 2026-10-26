# masaudit documentation

masaudit is a free mobile security scanner for Android, iOS, React Native, Kotlin Multiplatform, and
Flutter source code. It scales its advice to your app's risk. Everything works without AI or an account.

**New here?** Start with [Getting started](getting-started.md): your first scan and first fix, in
about ten minutes.

## Learn

- **[Getting started](getting-started.md):** install, run your first scan, read it, fix one finding.

## How-to guides

Step-by-step answers for a task:

- **[Choose your app type](app-type.md),** and handle the "Check your app type" warning.
- **[Read and fix the report](fixing.md):** what to fix first, how to verify, and safe fixes.
- **[Use masaudit in CI](ci.md):** the GitHub Action, pinning it safely, pre-commit, other CI.
- **[Use masaudit in a team](team.md):** shared settings, suppressions, baselines, other tools' results.
- **[Use masaudit with an AI assistant](ai-assistants.md):** Claude Code, Agent Skills tools, any chat.

## Reference

Facts to look up:

- **[Install and upgrade](install.md):** every way to run masaudit, and how to upgrade it.
- **[Command line](cli.md):** every option, exit code, and environment variable.
- **[Config file](config.md):** every `.masaudit.ini` key.
- **[Output formats](output-formats.md):** Markdown, JSON, and SARIF.
- **[Rules](rules.md):** every rule, with why, fix, verify, OWASP IDs, and the book section.
- **Sample reports:** the demo app as a [banking app](sample-report-banking.md) and as a
  [news app](sample-report-news.md).

## Explanation

Background, to understand the results:

- **[Benchmark on unseen apps](benchmark.md):** masaudit and three other free scanners on 21 apps no
  rule was tuned on, with every loss.
- **[How masaudit works](how-it-works.md):** app types, OWASP MAS profiles, how a finding gets its
  bucket, and what masaudit never does.
- **[Accuracy and speed](precision.md):** how the rules were measured on 19 open-source apps and 10 React Native apps, and how fast scans are.
- **[Compared with rnsec](compare-rnsec.md):** each rule of rnsec, a React Native scanner, mapped to masaudit.

## Contributing and project

- **[Writing a rule](writing-rules.md)** and
  [CONTRIBUTING.md](https://github.com/hossam9k/masaudit/blob/main/CONTRIBUTING.md).
- **[Security policy](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md):** report a
  vulnerability, or check that a download is genuine.
- **[Changelog](https://github.com/hossam9k/masaudit/blob/main/CHANGELOG.md).**
- **The book** every rule cites:
  [*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security).

## Questions people ask first

**Do I need AI, an account, or the internet?**
No. masaudit runs on your machine with Python 3.9 or later. The single-file `masaudit.pyz` works fully
offline. An [AI assistant](ai-assistants.md) is optional.

**Does it upload my code, or run it?**
No. It makes no network calls (a test enforces it), sends no telemetry, and never builds or runs your
code. It writes only its own report, plus `.masaudit.ini`, a baseline, a patch, or a safe fix when
you ask for one. See
[Safe to run on any code](how-it-works.md#safe-to-run-on-any-code).

**Which projects does it scan?**
Android, iOS, React Native (including Expo), Kotlin Multiplatform, and Flutter source code, plus GitHub
Actions workflows. In a React Native app it reads the JavaScript and TypeScript and the native
`android/` and `ios/` folders. It doesn't read built APK or IPA files. See [What masaudit reads](how-it-works.md#what-masaudit-reads-and-what-it-doesnt).

**Does it work on Windows?**
Yes. See [Install and upgrade](install.md).

**Which app type should I pick?**
The one that matches what your app protects. If two fit, pick the riskier one. If the code suggests a
riskier type than your choice, masaudit tells you. See [Choose your app type](app-type.md).

**Why does the report say a finding is "Not needed"?**
Some protections are worth their cost only in high-risk apps. Certificate pinning, for example, helps a banking
app but adds outage risk to a news app. masaudit still lists these findings, with the reason, so you
can decide. See [How a finding gets its bucket](how-it-works.md#how-a-finding-gets-its-bucket).

**A finding is wrong for my code. What do I do?**
Suppress it with a written reason (see [Use masaudit in a team](team.md#suppress-a-finding-with-a-reason))
and, if the rule itself is wrong, send a
[false-positive report](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).
It's the most useful contribution you can make.

**Is it free?**
Yes. The code is Apache-2.0, and the fix snippets are MIT-0, so you can paste them into any app.
