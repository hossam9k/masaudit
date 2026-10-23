# SPDX-License-Identifier: Apache-2.0
"""CI and build-input detectors: GitHub Actions workflows, signing material, wrapper and lockfiles.

Workflows are read with the stdlib-only reader in parsers/workflows.py. Book: §15.3–15.6.
"""

from __future__ import annotations

import os
import re
from typing import Iterable, List, Tuple

from masaudit import safety
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.parsers import workflows
from masaudit.parsers.workflows import Scalar, Workflow

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _workflow_files(ctx: Context) -> List[str]:
    return [f for f in ctx.files(".yml", ".yaml") if f.startswith(".github/workflows/")]


def _workflows(ctx: Context) -> Iterable[Tuple[str, Workflow]]:
    for path in _workflow_files(ctx):
        text = ctx.text(path)
        if text is None:
            continue
        wf = workflows.parse_workflow(text)
        if wf is None:
            ctx.note_unknown(f"Couldn't read {path} as a GitHub workflow.")
            continue
        yield path, wf


def _hit(ctx: Context, path: str, line: int, message: str) -> Hit:
    return Hit(path, line, ctx.snippet(path, line), message)


# ---------------------------------------------------------------------------- CI-001


@detector("ci_unpinned_action")
def unpinned_action(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        refs = [j.uses for j in wf.jobs if j.uses] + [s.uses for j in wf.jobs for s in j.steps if s.uses]
        for uses in refs:
            value = str(uses).strip()
            if value.startswith("./") or "${{" in value:
                continue
            if value.startswith("docker://"):
                if "@sha256:" not in value:
                    yield _hit(ctx, path, uses.line,
                               f"`{value}` uses a container tag, which can be moved. Pin it with @sha256:<digest>.")
                continue
            name, _, ref = value.rpartition("@")
            if not name:
                yield _hit(ctx, path, uses.line, f"`{value}` has no version at all, so it runs whatever is newest.")
            elif not SHA40.match(ref):
                yield _hit(ctx, path, uses.line,
                           f"`{name}` is pinned to `{ref}`, a tag or branch its owner can move to different code.")


# ---------------------------------------------------------------------------- CI-002


def _is_write_all(node) -> bool:
    return isinstance(node, Scalar) and str(node).strip() == "write-all"


@detector("ci_token_permissions")
def token_permissions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        if _is_write_all(wf.permissions):
            yield _hit(ctx, path, wf.permissions_line,
                       "The workflow grants `write-all`: every job's token can write to the whole repository.")
        for job in wf.jobs:
            if _is_write_all(job.permissions):
                line = job.permissions.line if isinstance(job.permissions, Scalar) else job.line
                yield _hit(ctx, path, line, f"Job `{job.id}` grants `write-all` to its token.")
        if wf.permissions is None and wf.jobs:
            # Precision: if every job sets its own permissions, the token is already scoped.
            if all(j.permissions is not None for j in wf.jobs):
                continue
            line = wf.jobs_line or 1
            yield _hit(ctx, path, line,
                       "No top-level `permissions:`, so jobs get the repository's default token, "
                       "which is read-write on many older organizations.")


# ---------------------------------------------------------------------------- CI-003

PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref")


@detector("ci_prt_checkout")
def prt_checkout(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        if "pull_request_target" not in wf.triggers:
            continue
        for job in wf.jobs:
            for step in job.steps:
                if step.uses and str(step.uses).split("@")[0].lower() == "actions/checkout":
                    for key in ("ref", "repository"):
                        val = step.with_.get(key)
                        if isinstance(val, Scalar) and PR_HEAD.search(val):
                            line = step.with_.key_lines.get(key, step.line)
                            yield _hit(ctx, path, line,
                                       "This `pull_request_target` job checks out the pull request's own code, "
                                       "which then runs with your secrets and a write token.")
                            break
                if step.run is not None:
                    for idx, text in enumerate(str(step.run).split("\n")):
                        if re.search(r"\bgh\s+pr\s+checkout\b", text) or (
                                re.search(r"\bgit\s+(?:fetch|checkout|switch)\b", text) and PR_HEAD.search(text)):
                            line = step.run.line_map[min(idx, len(step.run.line_map) - 1)]
                            yield _hit(ctx, path, line,
                                       "This `pull_request_target` job fetches the pull request's code in a script.")


# ---------------------------------------------------------------------------- CI-004

EXPR = re.compile(r"\$\{\{(.*?)\}\}")
UNTRUSTED = re.compile(r"github\.event\.[A-Za-z0-9_.\-*\[\]'\"]+|github\.head_ref")
# Fields an outsider can't fill with text: numbers, IDs, SHAs, timestamps, booleans.
SAFE_TAIL = re.compile(
    r"\.(?:number|id|node_id|sha|before|after|run_id|run_number|run_attempt|size|additions|deletions|"
    r"changed_files|commits|comments|draft|merged|locked|forced|created|deleted|[a-z_]+_at|[a-z_]+_count)$"
)


@detector("ci_script_injection")
def script_injection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        for job in wf.jobs:
            for step in job.steps:
                if step.run is None:
                    continue
                for idx, text in enumerate(str(step.run).split("\n")):
                    for expr in EXPR.finditer(text):
                        bad = [m.group(0) for m in UNTRUSTED.finditer(expr.group(1))
                               if not SAFE_TAIL.search(m.group(0))]
                        if bad:
                            line = step.run.line_map[min(idx, len(step.run.line_map) - 1)]
                            yield _hit(ctx, path, line,
                                       f"`{bad[0]}` is pasted into the script before it runs, so text an outsider "
                                       "controls can become shell commands.")
                            break


# ---------------------------------------------------------------------------- CI-005


@detector("ci_persist_credentials")
def persist_credentials(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        for job in wf.jobs:
            for step in job.steps:
                if not step.uses or str(step.uses).split("@")[0].lower() != "actions/checkout":
                    continue
                val = step.with_.get("persist-credentials")
                if isinstance(val, Scalar) and str(val).strip().lower() == "false":
                    continue
                if isinstance(val, Scalar) and "${{" in val:
                    ctx.note_unknown(f"{path}:{val.line}: persist-credentials is set by an expression.")
                    continue
                yield _hit(ctx, path, step.uses.line,
                           "`actions/checkout` leaves the job token in .git/config for every later step.")


# ---------------------------------------------------------------------------- tree inventory

# safety.walk only lists text files worth reading. Signing material and lockfiles have other
# extensions, so these rules list names (never contents) with the same pruning rules.
def _all_names(ctx: Context) -> List[str]:
    cached = getattr(ctx, "_ci_all_names", None)
    if cached is not None:
        return cached
    root = os.path.abspath(ctx.root)
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in safety.SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            out.append(os.path.relpath(full, root).replace(os.sep, "/"))
            if len(out) >= safety.MAX_FILES:
                break
    ctx._ci_all_names = out  # type: ignore[attr-defined]
    return out


# ---------------------------------------------------------------------------- CI-006

KEY_FILE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx", ".p8")
# Android's debug keystore is generated by the SDK and signs nothing that ships.
HARMLESS_KEYS = {"debug.keystore"}
PASSWORD_LINE = re.compile(
    r"^[ \t]*(storePassword|keyPassword|[A-Z_]*(?:KEYSTORE|STORE|KEY)_PASSWORD)[ \t]*[=:][ \t]*(\S.*)$", re.MULTILINE
)


@detector("ci_signing_material")
def signing_material(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in _all_names(ctx):
        base = path.rsplit("/", 1)[-1]
        if base.lower().endswith(KEY_FILE_SUFFIXES) and base.lower() not in HARMLESS_KEYS:
            if "/test/" in "/" + path.lower() or "/fixtures/" in "/" + path.lower():
                continue
            yield Hit(path, 0, base, f"`{base}` looks like a signing key or certificate with its private key.")
    for path in ctx.files(".properties"):
        base = path.rsplit("/", 1)[-1]
        if base not in ("key.properties", "keystore.properties", "signing.properties", "gradle.properties"):
            continue
        text = ctx.text(path) or ""
        for m in PASSWORD_LINE.finditer(text):
            value = m.group(2).strip()
            if not value or value.startswith(("$", "<")) or value.lower() in ("changeme", "none", "null"):
                continue
            line = ctx.line_of(text, m.start(1))
            # Short passwords escape the generic masker, so build the snippet ourselves.
            yield Hit(path, line, f"{m.group(1)}=…[masked]",
                      f"`{base}` holds a signing password in source control.")


# ---------------------------------------------------------------------------- CI-007


@detector("ci_wrapper_checksum")
def wrapper_checksum(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(name="gradle-wrapper.properties"):
        text = ctx.text(path)
        if text is None:
            continue
        if re.search(r"^\s*distributionSha256Sum\s*=\s*[0-9a-fA-F]{64}\s*$", text, re.MULTILINE):
            continue
        m = re.search(r"^\s*distributionUrl\s*=", text, re.MULTILINE)
        line = ctx.line_of(text, m.start()) if m else 1
        yield _hit(ctx, path, line, "The Gradle download isn't checked against a known SHA-256.")


# ---------------------------------------------------------------------------- CI-008


def _is_gradle_root(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in ("settings.gradle", "settings.gradle.kts")


@detector("ci_missing_lockfile")
def missing_lockfile(ctx: Context, rule: Rule) -> Iterable[Hit]:
    names = _all_names(ctx)
    bases = {p.rsplit("/", 1)[-1] for p in names}
    gradle_roots = [p for p in ctx.files() if _is_gradle_root(p)]
    if gradle_roots and not any(b.endswith(".lockfile") for b in bases):
        uses_locking = any("dependencyLocking" in (ctx.text(p) or "")
                           for p in ctx.files(".gradle", ".gradle.kts"))
        if not uses_locking:
            yield Hit(gradle_roots[0], 0, "", "No `gradle.lockfile` was found, so builds can resolve "
                                              "different dependency versions over time.")
    spm = [p for p in ctx.files(name="Package.swift")]
    spm += [p for p in ctx.files(".pbxproj") if "XCRemoteSwiftPackageReference" in (ctx.text(p) or "")]
    if spm and "Package.resolved" not in bases:
        yield Hit(spm[0], 0, "", "No `Package.resolved` was found, so Swift packages can resolve "
                                 "different versions over time.")
