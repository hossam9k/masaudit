# Security policy

masaudit reads code it didn't write, so its own security matters.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
https://github.com/hossam9k/masaudit. Don't open a public issue.

I aim to acknowledge reports within 3 days and to ship a fix or a plan within 14 days.

## What counts

- Anything that makes masaudit read files outside the scan root, run code, or make a network call.
- Unmasked secrets in reports, SARIF, or terminal output.
- Crashes or hangs triggered by a crafted project (huge files, XML entities, regex blow-ups).
- Content from a scanned project that can instruct an AI assistant through masaudit's output.

A false positive or a missed issue in your app isn't a vulnerability in masaudit: please use the
[false-positive form](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).

## Supported versions

Only the latest release gets security fixes.
