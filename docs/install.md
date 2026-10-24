[masaudit documentation](README.md) › Install and upgrade

# Install and upgrade

masaudit needs Python 3.9 or later and nothing else: it uses only Python's standard library. CI tests
it on Linux, macOS, and Windows with Python 3.9 to 3.14.

## Ways to run it

| Way | Run | Upgrade | Notes |
|---|---|---|---|
| uv, no install | `uvx masaudit .` | `uvx masaudit@latest .` | Needs [uv](https://docs.astral.sh/uv/). Downloads masaudit the first time. |
| pipx, no install | `pipx run masaudit .` | `pipx run --no-cache masaudit .` | Needs [pipx](https://pipx.pypa.io/). Reuses a cached copy for a few days. |
| pipx, installed | `pipx install masaudit`, then `masaudit .` | `pipx upgrade masaudit` | Keeps the `masaudit` command on your PATH. |
| pip | `pip install masaudit` | `pip install --upgrade masaudit` | Use it inside a virtual environment. |
| Single file | `python3 ~/Downloads/masaudit.pyz .` | Download the new file | Works offline. On Windows, run `py masaudit.pyz .`. |

The single file, `masaudit.pyz`, is on the
[latest release](https://github.com/hossam9k/masaudit/releases/latest) page. Keep it outside your
project, and give its full path when you run it.

In this documentation, commands start with `masaudit`. If you run it another way, type
`uvx masaudit`, `pipx run masaudit`, or `python3 masaudit.pyz` in place of `masaudit`.

## Check that a download is genuine

Every release is built by GitHub Actions from a tagged commit, with signed build provenance and a
`SHA256SUMS` file. To check a downloaded file, see
[Verify a download](https://github.com/hossam9k/masaudit/blob/main/SECURITY.md#verify-a-download).

## Other places masaudit runs

- **GitHub Actions:** the masaudit Action runs from its own pinned source. See [Use masaudit in CI](ci.md).
- **pre-commit:** see [pre-commit](ci.md#pre-commit). To upgrade the hook, run `pre-commit autoupdate`.
- **AI assistants:** the masaudit skill bundles the scanner. See
  [Use masaudit with an AI assistant](ai-assistants.md).
