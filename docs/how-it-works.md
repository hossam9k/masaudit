[masaudit documentation](README.md) › How masaudit works

# How masaudit works

This page explains the ideas behind masaudit's results: why the app type matters, how a finding
lands in its bucket, and what masaudit never does.

## Most scanners give every app the same list

A debug flag left on, a test server that accepts any certificate, a token written to the log: most
mobile security problems are settings and code that got past review. Many scanners find them. But
they give a news app and a bank the same list, so a news app is told to pin certificates and detect
rooted phones. Those controls add cost and outage risk for no gain, and the team learns to ignore the
tool.

masaudit's answer is to ask first what the app protects, then scale the advice to it.

## App types map to OWASP MAS profiles

OWASP's Mobile Application Security project defines four testing profiles:

| Profile | Assumes | For |
|---|---|---|
| **L1** | The phone's OS can be trusted; other apps are the attackers | Every app |
| **L2** | The OS can't be trusted (rooted or jailbroken phones, physical access) | Sensitive data or functions: health, finance |
| **R** | The app's own user is the attacker: reverse engineers, cheaters | Apps protecting their own logic or assets |
| **P** | Personal data handling (privacy) | Every app that handles user data |

Each [app type](app-type.md) maps to a set of these profiles. A news app is L1 and P; a banking app is
all four. Each rule belongs to one or more profiles. A few rules, such as certificate pinning, apply
only to listed app types.

## How a finding gets its bucket

1. **Does your app need it?** If none of the rule's profiles is in your app type, or the rule is
   limited to other app types, the finding goes to **Not needed for your app**, with the reason. It is
   never dropped, so you can disagree.
2. **How severe is it here?** The rule's severity is the starting point (a detector can rate one hit
   higher or lower, and the finding says why). A finding in code that
   usually doesn't ship is lowered: two levels in debug code, four in tests. A finding your team
   already marked as intentional for another tool, such as Android Lint's `tools:ignore`, is lowered
   one level and shows that decision.
3. **Which bucket?** Critical and high go to **Fix before release**; medium and low to **Fix soon**;
   informational to **Notes**.
4. **Accepted?** A suppression with a reason, or a baseline entry, moves the finding to *Accepted
   earlier*. It stays visible but doesn't count.

## When the code disagrees with your app type

masaudit also reads evidence of risk in code that ships, such as card-number fields or a health data
API. If the evidence suggests a riskier type whose checks yours skips, it warns you instead of
changing the type: only you know whether that code ships and what the app protects. See
[Check your app type](app-type.md#when-masaudit-says-check-your-app-type).

## What masaudit reads, and what it doesn't

masaudit reads source and configuration: manifests, Gradle files, `Info.plist`, Xcode projects and
schemes, entitlements, Kotlin, Java, Swift, Objective-C, Dart, and C or C++ code, and GitHub workflows.
Code rules run after comments are removed, so a comment never triggers a finding.

- **React Native:** masaudit scans the `android/` and `ios/` folders, but not the JavaScript code yet.
- **Built apps:** it doesn't read APK or IPA files. To test a built app and the running app, use a
  tool such as [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) alongside masaudit.
- **Skipped folders:** build output, dependencies, and tool folders are never scanned: `build`, `out`,
  `generated`, `intermediates`, `.cxx`, `.externalNativeBuild`, `.gradle`, `DerivedData`, `Pods`,
  `Carthage`, `node_modules`, `.dart_tool`, `.build`, `.swiftpm`, `xcuserdata`, version-control and
  IDE folders, and Python virtual environments. A source folder with one of these names is skipped
  too. To skip more, use `exclude` in the [config file](config.md).
- **Skipped files:** files over 2 MiB (16 MiB for `project.pbxproj`), hard links, symbolic links to
  folders, symbolic links to files outside the folder, and anything that isn't a regular file, such
  as a FIFO. A scan reads at most 200,000 files; in a
  larger repository, scan each app's folder separately.
- **Where it runs:** see [Install and upgrade](install.md).

It can't see your server, how the app behaves at runtime, or your business logic, which is where many
breaches happen. Every report has a *Residual risk* section for that reason.

In the terminal and JSON output, *Profile* shows your app type and its MAS profiles.

## Safe to run on any code

masaudit treats the project it scans as untrusted:

- It never builds or runs your code, and never follows a symbolic link out of the folder it scans.
- It makes **no network calls** (a test enforces it) and sends no telemetry.
- It refuses XML entity tricks, caps file sizes, and scans crafted files in linear time, so a hostile
  repository can't stall it.
- It masks secret values in every output.

To report a vulnerability in masaudit, see the
[security policy](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md).

## Where the rules come from

Every rule cites a section of the free book
[*Mobile Application Security: A Study Book for Engineers*](https://github.com/hossam9k/mobile-app-security),
and OWASP's catalog IDs: MASWE (weaknesses), MASVS (controls), and MASTG (tests). How each rule was
checked on real apps is in [Accuracy and speed](precision.md).
