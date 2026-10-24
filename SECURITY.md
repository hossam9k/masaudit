# Security policy

masaudit reads code it didn't write, so its own security matters.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on
https://github.com/hossam9k/masaudit. Don't open a public issue.

I aim to acknowledge reports within 3 days and to ship a fix or a plan within 14 days.

## What counts

- Anything that makes masaudit read files outside the scan root, run code, or make a network call.
- Unmasked secrets in reports, SARIF, or terminal output.
- Crashes or hangs triggered by a crafted project (huge files, XML entities, regex blow-ups).
- Content from a scanned project that can instruct an AI assistant through masaudit's output.

A false positive or a missed issue in your app isn't a vulnerability in masaudit: use the
[false-positive form](https://github.com/hossam9k/masaudit/issues/new?template=false-positive.yml).

## Supported versions

Only the latest release gets security fixes.

## Verify a download

Every release is built by GitHub Actions from a tagged commit, with signed build provenance.
To check that a file you downloaded came from this repository's release workflow:

```bash
gh attestation verify masaudit.pyz --repo hossam9k/masaudit
```

`gh attestation verify` needs the [GitHub CLI](https://cli.github.com/), signed in with `gh auth login`.
Without it, check the file against the release's `SHA256SUMS` (download both into the same folder):

```bash
shasum -a 256 -c --ignore-missing SHA256SUMS      # macOS; on Linux: sha256sum -c --ignore-missing SHA256SUMS
```

Each release includes `SHA256SUMS`. Releases after 0.1.1 also include the signed provenance bundle,
`masaudit.sigstore.json`.
