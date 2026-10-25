# SPDX-License-Identifier: Apache-2.0
"""CI and build-input detectors: GitHub Actions workflows, signing material, wrapper and lockfiles.

Workflows are read with the stdlib-only reader in parsers/workflows.py. Book: §15.3–15.6.

Severity is tiered per hit (Hit.severity) where the rule's own severity would overstate the
risk, for example a GitHub-owned action on a tag, or a debug keystore. A setting the repository
wrote down on purpose (a zizmor.yml policy, `persist-credentials: true`) sets Hit.acknowledged,
which lowers the finding one level but never hides it.
"""

from __future__ import annotations

import os
import re
import stat
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from masaudit import safety
from masaudit.engine import Context, Hit, detector
from masaudit.model import SEVERITY_RANK, Rule
from masaudit.parsers import workflows
from masaudit.parsers.workflows import Scalar, Step, Workflow

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


def _hit(ctx: Context, path: str, line: int, message: str, severity: str = "", acknowledged: str = "") -> Hit:
    return Hit(path, line, ctx.snippet(path, line), message, severity=severity, acknowledged=acknowledged)


# A public action reference: owner/repo[/path]@ref. It names code anyone can read, never a secret.
ACTION_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_./-]{1,200}(?:@[A-Za-z0-9_./+-]{1,200})?$")


def _uses_snippet(ctx: Context, path: str, uses: Scalar) -> str:
    """The `uses:` line, masked as usual except for the action reference itself: the secret masker
    otherwise hides a public name such as `someone/base64Secret-action`."""
    value = str(uses).strip()
    lines = (ctx.text(path) or "").split("\n")
    raw = lines[uses.line - 1] if 0 < uses.line <= len(lines) else ""
    if not ACTION_REF.match(value) or raw.count(value) != 1:
        return ctx.snippet(path, uses.line)
    masked = safety.mask(raw.replace(value, "ACTIONREF"))
    return masked.replace("ACTIONREF", value, 1)[:160] if "ACTIONREF" in masked else ctx.snippet(path, uses.line)


def _action_name(uses: Optional[Scalar]) -> str:
    return str(uses).split("@")[0].strip().lower() if uses else ""


def _read_head(ctx: Context, rel: str, limit: int, max_size: Optional[int] = None) -> Optional[str]:
    """First `limit` bytes of a regular file under the root (no symlinks, no hard links), as text."""
    root = os.path.abspath(ctx.root)
    full = os.path.join(root, rel)
    try:
        st = os.lstat(full)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or not safety.is_within(root, full)
                or (max_size is not None and st.st_size > max_size)):
            return None
        # O_NOFOLLOW and a second check on the open file close the gap between lstat and open.
        fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            opened = os.fstat(fh.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                return None
            data = fh.read(limit)
    except OSError:
        return None
    return data.decode("utf-8", "replace")


# ---------------------------------------------------------------------------- repository identity


def _self_repo(ctx: Context) -> Optional[Tuple[str, str]]:
    """(owner, repo) of the scanned repository, lower-case, or None when it can't be told.

    Read from the `origin` remote in <root>/.git/config (plain text, never followed). On a GitHub
    runner, GITHUB_REPOSITORY is used only when the scan root is the workspace itself.
    """
    cached = getattr(ctx, "_ci_self_repo", False)
    if cached is not False:
        return cached
    found = None
    root = os.path.abspath(ctx.root)
    git_dir = os.path.join(root, ".git")
    if os.path.isdir(git_dir) and not os.path.islink(git_dir):
        text = _read_head(ctx, ".git/config", 65536, max_size=65536)
        if text is not None:
            found = workflows.github_origin(text)
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    if found is None and workspace and os.path.realpath(workspace) == os.path.realpath(root):
        env = os.environ.get("GITHUB_REPOSITORY", "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}", env):
            owner, repo = env.lower().split("/", 1)
            found = (owner, repo)
    ctx._ci_self_repo = found  # type: ignore[attr-defined]
    return found


# ---------------------------------------------------------------------------- CI-001

ZIZMOR_FILES = (".github/zizmor.yml", ".github/zizmor.yaml", "zizmor.yml", "zizmor.yaml", ".zizmor.yml")
GITHUB_OWNED = ("actions", "github")        # OpenSSF Scorecard's IsGitHubOwnedAction
VERSIONISH = re.compile(r"^v?\d{1,9}(?:\.\d{1,9}){0,3}(?:[-+][0-9A-Za-z.-]{1,64})?$")


def _zizmor_policies(ctx: Context) -> Dict[str, str]:
    cached = getattr(ctx, "_ci_zizmor", None)
    if cached is not None:
        return cached
    policies: Dict[str, str] = {}
    for path in ZIZMOR_FILES:
        text = ctx.text(path)
        if text is not None:
            policies = workflows.unpinned_uses_policies(text)
            break
    ctx._ci_zizmor = policies  # type: ignore[attr-defined]
    return policies


def _policy_for(name: str, policies: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """zizmor's order, most specific first: exact path or repo, then owner/repo/*, owner/*, *."""
    if not policies:
        return None
    parts = name.lower().split("/")
    owner, repo = parts[0], parts[1] if len(parts) > 1 else ""
    for pattern in (name.lower(), f"{owner}/{repo}/*", f"{owner}/*", "*"):
        if pattern in policies:
            return pattern, policies[pattern]
    return None


def _uses_hits(ctx: Context, path: str, refs: Sequence[Scalar]) -> Iterable[Hit]:
    me = _self_repo(ctx)
    policies = _zizmor_policies(ctx)
    for uses in refs:
        value = str(uses).strip()
        if value.startswith(("./", "$/")) or "${{" in value:     # local, or $/ self-repository syntax
            continue
        if value.startswith("docker://"):
            if "@sha256:" not in value:
                yield _hit(ctx, path, uses.line,
                           f"`{value}` uses a container tag, which can be moved. Pin it with @sha256:<digest>.")
            continue
        name, _, ref = value.rpartition("@")
        if not name:
            name, ref = value, ""
        elif SHA40.match(ref):
            continue
        parts = name.lower().split("/")
        owner, repo = parts[0], parts[1] if len(parts) > 1 else ""
        kind = "tag" if VERSIONISH.match(ref) else "branch"
        if ref and me is not None and (owner, repo) == me:
            local = "./" + "/".join(parts[2:])
            yield _hit(ctx, path, uses.line,
                       f"`{name}` is this repository's own code, referenced by the {kind} `{ref}`. Whoever can "
                       f"move it can already edit this workflow, so it adds no new trust. Write it as `{local}` "
                       "(or `$/…`) so GitHub's SHA-pinning policy accepts it.", severity="info")
            continue
        severity = ""
        if not ref:
            message = f"`{value}` has no version at all, so it runs whatever is newest."
        elif me is not None and owner == me[0]:
            severity = "medium"
            message = (f"`{name}` comes from your own organization but is pinned to the {kind} `{ref}`: whoever "
                       "can push there can change what this workflow runs.")
        elif owner in GITHUB_OWNED:
            severity = "medium"
            message = (f"`{name}` is GitHub-owned but pinned to the {kind} `{ref}`, which GitHub can move. Lower "
                       "risk than a third-party action, but pin it too.")
        else:
            message = f"`{name}` is pinned to `{ref}`, a {kind} its owner can move to different code."
        acknowledged = ""
        policy = _policy_for(name, policies)
        if policy and (policy[1] == "any" or (policy[1] == "ref-pin" and ref)):
            acknowledged = f"zizmor.yml unpinned-uses policy `{policy[0]}: {policy[1]}`"
        yield Hit(path, uses.line, _uses_snippet(ctx, path, uses), message, severity=severity,
                  acknowledged=acknowledged)


def _action_files(ctx: Context) -> List[str]:
    return [f for f in ctx.files(name="action.yml") + ctx.files(name="action.yaml")
            if not f.startswith(".github/workflows/")]


@detector("ci_unpinned_action")
def unpinned_action(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        refs = [j.uses for j in wf.jobs if j.uses] + [s.uses for j in wf.jobs for s in j.steps if s.uses]
        yield from _uses_hits(ctx, path, refs)
    # Composite actions run their own `uses:` steps inside every workflow that calls them.
    for path in _action_files(ctx):
        text = ctx.text(path)
        action = workflows.parse_action(text) if text is not None else None
        if action is None:
            continue
        if action.using == "composite":
            yield from _uses_hits(ctx, path, [s.uses for s in action.steps if s.uses])
        elif action.using == "docker" and action.image and str(action.image).strip().startswith("docker://"):
            yield from _uses_hits(ctx, path, [action.image])


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
            if set(wf.triggers) == {"workflow_call"}:
                yield _hit(ctx, path, line,
                           "This reusable workflow sets no `permissions:`, so it runs with whatever its callers "
                           "grant. Check the callers; `permissions: {}` here would cap it.", severity="info")
                continue
            yield _hit(ctx, path, line,
                       "No top-level `permissions:`, so jobs get the repository's default token, "
                       "which is read-write on many older organizations.")


# ---------------------------------------------------------------------------- CI-003

PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref|"
                     r"github\.event\.pull_request\.merge_commit_sha|refs/pull/")
# A job condition that keeps fork pull requests out.
SAME_REPO_GATE = re.compile(
    r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*(?:github\.repository\b|'[^']+')|"
    r"(?:github\.repository\b|'[^']+')\s*==\s*github\.event\.pull_request\.head\.repo\.full_name|"
    r"!\s*github\.event\.pull_request\.head\.repo\.fork\b|"
    r"github\.event\.pull_request\.head\.repo\.fork\s*==\s*false"
)
# A step condition that is true for forks (paired with `exit 1`, it stops the job for them).
FORK_TEST = re.compile(r"github\.event\.pull_request\.head\.repo\.full_name\s*!=\s*github\.repository\b|"
                       r"github\.event\.pull_request\.head\.repo\.fork\s*(?:==\s*true\s*)?(?:\}\}|$)")
FAILS_JOB = re.compile(r"\bexit\s+[1-9]")
GATED = (" The job only runs for branches of this repository, so outsiders can't reach it; a collaborator's "
         "branch still runs with the write token.")
GATED_IDLE = (" The job only runs for branches of this repository, and no later step runs the checked-out code, so "
              "the risk is a future step that does.")


# A step that runs code from the checkout: a repository script, a build tool that reads its build files,
# a package manager that runs install hooks, or a local action.
RUNS_CHECKOUT = re.compile(r"(?:^|[\s;&|(])(?:\./|bash\s+[\w./-]+\.sh|sh\s+[\w./-]+\.sh|python3?\s+[\w./-]+\.py)|"
                           r"\b(?:gradlew|gradle|npm|npx|yarn|pnpm|make|cmake|bundle|pod|fastlane|mvn|cargo|go\s+(?:run|build|"
                           r"test|generate)|pip3?\s+install|poetry|tox|nox|dotnet|swift\s+(?:build|test|run)|"
                           r"xcodebuild|flutter|dart|melos|rake|composer|node)\b")


def _runs_checkout(steps: Sequence[Step]) -> bool:
    for s in steps:
        if s.uses is not None and str(s.uses).strip().startswith("./"):
            return True
        if s.run is not None and RUNS_CHECKOUT.search(str(s.run)):
            return True
    return False


def _stops_forks(step: Step) -> bool:
    return bool(step.if_ and FORK_TEST.search(step.if_) and step.run is not None and FAILS_JOB.search(step.run))


@detector("ci_prt_checkout")
def prt_checkout(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        if "pull_request_target" not in wf.triggers:
            continue
        for job in wf.jobs:
            gated = bool(job.if_ and SAME_REPO_GATE.search(job.if_))
            for i, step in enumerate(job.steps):
                gated = gated or _stops_forks(step)
                severity, extra = ("high", GATED) if gated else ("", "")
                if gated and not _runs_checkout(job.steps[i + 1:]):
                    severity, extra = "medium", GATED_IDLE
                if _action_name(step.uses) == "actions/checkout":
                    for key in ("ref", "repository"):
                        val = step.with_.get(key)
                        if isinstance(val, Scalar) and PR_HEAD.search(val):
                            line = step.with_.key_lines.get(key, step.line)
                            yield _hit(ctx, path, line,
                                       "This `pull_request_target` job checks out the pull request's own code, "
                                       "which then runs with your secrets and a write token." + extra,
                                       severity=severity)
                            break
                if step.run is not None:
                    for idx, text in enumerate(str(step.run).split("\n")):
                        if re.search(r"\bgh\s+pr\s+checkout\b", text) or (
                                re.search(r"\bgit\s+(?:fetch|checkout|switch)\b", text) and PR_HEAD.search(text)):
                            line = step.run.line_map[min(idx, len(step.run.line_map) - 1)]
                            yield _hit(ctx, path, line,
                                       "This `pull_request_target` job fetches the pull request's code in a script."
                                       + extra, severity=severity)


# ---------------------------------------------------------------------------- CI-004

EXPR = re.compile(r"\$\{\{(.*?)\}\}")
UNTRUSTED = re.compile(r"github\.event\.[A-Za-z0-9_.\-*\[\]'\"]+|github\.head_ref")
# Fields an outsider can't fill with text: numbers, IDs, SHAs, timestamps, booleans, GitHub-built URLs.
SAFE_TAIL = re.compile(
    r"\.(?:number|id|node_id|sha|[a-z_]+_sha|before|after|run_id|run_number|run_attempt|size|additions|"
    r"deletions|changed_files|commits|comments|draft|merged|locked|forced|created|deleted|[a-z_]+_at|"
    r"[a-z_]+_count|html_url)$"
)
# Values GitHub picks from a fixed set, or that only repository admins can set.
SAFE_EXACT = {"github.event.action", "github.event.repository.default_branch"}
SAFE_LINK = re.compile(r"\._links\.[a-z_]+\.href$")
# GitHub limits logins to [A-Za-z0-9-] and repository names to [A-Za-z0-9._-]: no shell syntax fits.
STRUCTURED = re.compile(r"\.(?:full_name|login)$|\.repo\.name$")
DISPATCH_INPUT = re.compile(r"^github\.event\.inputs(?:\.([A-Za-z0-9_-]+)|\[['\"]([A-Za-z0-9_-]+)['\"]\])$")
FIXED_INPUT_TYPES = {"choice", "boolean", "number", "environment"}


def _classify(wf: Workflow, expr: str) -> Optional[Tuple[str, str]]:
    """None when the value can't carry shell syntax; else (severity, reason). "" = the rule's severity."""
    if expr in SAFE_EXACT or SAFE_TAIL.search(expr) or SAFE_LINK.search(expr):
        return None
    m = DISPATCH_INPUT.match(expr)
    if m:
        types = wf.input_types.get(m.group(1) or m.group(2), [])
        if types and all(t in FIXED_INPUT_TYPES for t in types):
            return None
        return ("medium", "only people with write access can start this workflow, but any of them (or a stolen "
                          "token) can turn this input into commands that run with its secrets")
    if STRUCTURED.search(expr):
        return ("info", "GitHub restricts this value to letters, digits, `-`, `_` and `.`, so it can't carry "
                        "shell syntax; pass it through `env:` anyway")
    return ("", "text an outsider controls can become shell commands")


@detector("ci_script_injection")
def script_injection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        for job in wf.jobs:
            for step in job.steps:
                if step.run is None:
                    continue
                for idx, text in enumerate(str(step.run).split("\n")):
                    worst: Optional[Tuple[int, str, str, str]] = None
                    for expr in EXPR.finditer(text):
                        for m in UNTRUSTED.finditer(expr.group(1)):
                            found = _classify(wf, m.group(0))
                            if found is None:
                                continue
                            rank = SEVERITY_RANK[found[0] or rule.severity]
                            if worst is None or rank < worst[0]:
                                worst = (rank, found[0], m.group(0), found[1])
                    if worst:
                        line = step.run.line_map[min(idx, len(step.run.line_map) - 1)]
                        yield _hit(ctx, path, line, f"`{worst[2]}` is pasted into the script before it runs: "
                                                    f"{worst[3]}.", severity=worst[1])


# ---------------------------------------------------------------------------- CI-005

PUSHING_ACTIONS = {
    "stefanzweifel/git-auto-commit-action", "endbug/add-and-commit", "ad-m/github-push-action",
    "korthout/backport-action", "tibdex/backport", "sqren/backport-github-action",
    "devops-infra/action-commit-push", "peter-evans/create-pull-request",
}
# `git push`, with global options such as `-c key=value` or `-C dir` before the subcommand.
GIT_PUSH = re.compile(r"\bgit(?:\s+-{1,2}[\w.=/:-]+(?:\s+[^\s-]\S*)?)*\s+push\b")
GIT_TAG = re.compile(r"\bgit\s+tag\b")
PUSH_WORD = re.compile(r"\bpush\b")
DEFAULT_TOKEN = re.compile(r"^\$\{\{\s*(?:github\.token|secrets\.GITHUB_TOKEN)\s*\}\}$")
# zizmor's artipacked "dangerous" upload paths: the workspace itself.
WORKSPACE_UPLOAD = re.compile(r"^(?:\.|\./|\.\.|\.\./)$|github\.workspace")
VERSION_COMMENT = re.compile(r"#\s*v?(\d{1,4})(?:\.\d{1,9}){0,3}\b")
MAX_SCRIPT_LINE = 8192


# A fastlane lane named for a push, a tag or a git-flow finish runs git with the checkout's credentials.
# (The gh CLI merges and creates releases through the API with GH_TOKEN, so it doesn't count.)
FASTLANE_LANE = re.compile(r"\bfastlane\s+(?:(?:android|ios|mac)\s+)?(?P<lane>[A-Za-z][\w-]{0,100})")
FASTLANE_PUSH_WORDS = {"push", "tag", "hotfix", "finish"}


def _fastlane_pushes(line: str) -> bool:
    """`fastlane tag_and_push_release`, `fastlane android hotfix-finish`: a lane named for pushing."""
    m = FASTLANE_LANE.search(line)
    return bool(m) and bool(set(re.split(r"[_-]", m.group("lane").lower())) & FASTLANE_PUSH_WORDS)


# `git remote set-url origin https://${{ secrets.X }}@github.com/...`: the token goes into .git/config.
TOKEN_REMOTE = re.compile(r"\bgit\s+remote\s+(?:set-url|add)\b[^\n]{0,200}?https://[^\s@]{0,100}\$\{\{\s*"
                          r"(secrets\.\w+|github\.token)\s*\}\}[^@\s]{0,100}@")


def _token_remote(steps: Sequence[Step]) -> Optional[str]:
    """The secret a step writes into the remote URL, if any."""
    for s in steps:
        if s.run is None:
            continue
        for line in str(s.run).split("\n"):
            if len(line) <= MAX_SCRIPT_LINE:
                m = TOKEN_REMOTE.search(line)
                if m:
                    return m.group(1)
    return None


def _pushes(text: str) -> bool:
    for line in text.split("\n"):
        if len(line) > MAX_SCRIPT_LINE:
            continue
        if GIT_PUSH.search(line) or _fastlane_pushes(line) or TOKEN_REMOTE.search(line):
            return True
        tag = GIT_TAG.search(line)
        rest = line[tag.end():] if tag else ""
        if "&&" in rest and PUSH_WORD.search(rest, rest.index("&&")):
            return True
    return False


def _job_pushes(steps: Sequence[Step]) -> bool:
    return any(_action_name(s.uses) in PUSHING_ACTIONS or (s.run is not None and _pushes(s.run)) for s in steps)


def _uploads_workspace(steps: Sequence[Step]) -> bool:
    for s in steps:
        if _action_name(s.uses) == "actions/upload-artifact":
            p = s.with_.get("path")
            if isinstance(p, Scalar) and any(WORKSPACE_UPLOAD.search(x.strip()) for x in p.split("\n")):
                return True
    return False


def _checkout_major(ctx: Context, path: str, uses: Scalar) -> Optional[int]:
    """The checkout's major version: from the tag, or from a SHA pin's `# vN` comment (unverified)."""
    ref = str(uses).rpartition("@")[2].strip()
    if SHA40.match(ref):
        lines = (ctx.text(path) or "").split("\n")
        raw = lines[uses.line - 1] if 0 < uses.line <= len(lines) else ""
        m = VERSION_COMMENT.search(raw)
    else:
        m = re.match(r"^v?(\d{1,4})(?:\.|$)", ref)
    return int(m.group(1)) if m else None


@detector("ci_persist_credentials")
def persist_credentials(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, wf in _workflows(ctx):
        for job in wf.jobs:
            for i, step in enumerate(job.steps):
                if _action_name(step.uses) != "actions/checkout":
                    continue
                val = step.with_.get("persist-credentials")
                setting = str(val).strip().lower() if isinstance(val, Scalar) else None
                if setting == "false":
                    continue
                if isinstance(val, Scalar) and "${{" in val:
                    ctx.note_unknown(f"{path}:{val.line}: persist-credentials is set by an expression.")
                    continue
                later = job.steps[i + 1:]
                pushes = _job_pushes(later)
                token = step.with_.get("token")
                custom = isinstance(token, Scalar) and bool(token.strip()) and not DEFAULT_TOKEN.match(token.strip())
                line = step.uses.line
                if setting == "true" and pushes:
                    yield _hit(ctx, path, line, "`persist-credentials: true` is set on purpose and this job pushes. "
                                                "Every later step can still read the token.", severity="info")
                elif setting == "true":
                    yield _hit(ctx, path, line,
                               "`persist-credentials: true` keeps the token on disk, but nothing in this job pushes. "
                               "Set it to false unless a later step needs git credentials.",
                               severity="high" if custom else "", acknowledged="persist-credentials: true")
                elif pushes and _token_remote(later):
                    yield _hit(ctx, path, line,
                               f"This job pushes, and a step writes `{_token_remote(later)}` into the remote URL, so the "
                               "token stays in .git/config whatever `persist-credentials` says, and every later step "
                               "(third-party actions included) can read it. Pass the token only to the push, for "
                               "example in an `http.extraheader` for that one command.",
                               severity="high" if custom else "")
                elif pushes:
                    yield _hit(ctx, path, line, "This job pushes, so it needs the token: say so with "
                                                "`persist-credentials: true`, or set it to false and pass the token "
                                                "only to the push.", severity="low")
                elif custom:
                    yield _hit(ctx, path, line,
                               "`actions/checkout` stores the `token:` you passed (a PAT or app token, usually broader "
                               "than GITHUB_TOKEN) on disk for every later step, and nothing in this job pushes.",
                               severity="high")
                elif (_checkout_major(ctx, path, step.uses) or 0) >= 6 and not _uploads_workspace(later):
                    yield _hit(ctx, path, line, "`actions/checkout` v6+ keeps the job token in a file under "
                                                "$RUNNER_TEMP that every later step can read.", severity="low")
                else:
                    yield _hit(ctx, path, line,
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
            rel = os.path.relpath(full, root)
            if os.path.islink(full) or safety.has_control(rel):
                continue
            out.append(rel.replace(os.sep, "/"))
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
TEST_DIR = re.compile(r"^(?:tests?|testing|testdata|test-data|test-resources|fixtures|testfixtures|androidtest|"
                      r"unittests?|[a-z0-9_-]*tests)$", re.IGNORECASE)
DEBUG_WORD = re.compile(r"(?:^|[^a-z])debug(?:[^a-z]|$)", re.IGNORECASE)
NON_RELEASE_WORD = re.compile(r"(?:^|[^a-z])(?:nightly|qa|alpha|beta|staging|dev|internal|ci)(?:[^a-z]|$)",
                              re.IGNORECASE)
# The nearest enclosing signing block: getByName("debug") / create("release") / debug { ... }.
SIGNING_BLOCK = re.compile(r"""(?:getByName|create|register|maybeCreate)\(\s*["'](\w+)["']\s*\)|^[ \t]*(\w+)[ \t]*\{""")
# Android's public debug password, in a .properties file that names the keystore.
ANDROID_PASSWORD = re.compile(r"^[ \t]*[\w.]*(?:store|key)[._]?pass(?:word)?[ \t]*[=:][ \t]*[\"']?android[\"']?[ \t]*$",
                              re.IGNORECASE | re.MULTILINE)
BLOCK_LOOKBACK = 15


def _in_debug_signing_block(text: str, base: str) -> bool:
    lines = text.split("\n")
    for n, line in enumerate(lines):
        if base not in line:
            continue
        for back in range(n, max(-1, n - BLOCK_LOOKBACK), -1):
            m = SIGNING_BLOCK.search(lines[back])
            if m:
                if (m.group(1) or m.group(2)).lower() == "debug":
                    return True
                break
    return False


# Where a build or workflow says what unlocks a keystore.
KEYSTORE_PASSWORD = re.compile(
    r"\b(?:storePassword|keyPassword|store_?pass\w*|key_?pass\w*)\b[\"']?\s*(?:=|:|\(|\s)\s*(?P<v1>[^\n,)]+)"
    r"|--(?:ks|key)-pass\s+(?P<v2>\S+)|-(?:storepass|keypass)\s+(?P<v3>\S+)", re.IGNORECASE)
EXTERNAL_VALUE = re.compile(r"getenv|System\.env|secrets\.|\benv\.|environmentOrGradleValue|findProperty|"
                            r"getProperty|properties\s*\[|providers\.|project\.property|\$|^\s*(?:env|file):", re.IGNORECASE)
LITERAL_VALUE = re.compile(r"""^\s*(?:pass:)?(?:"[^"$\n]+"|'[^'$\n]+'|[^\s"'$(){}]+)\s*$""")
PASSWORD_WINDOW = 15


def _same_block(lines: List[str], n: int) -> List[str]:
    """Lines near line n that belong to its Gradle signing block: the window stops at another block's
    header or a closing brace, so the debug config's password never speaks for the release keystore."""
    out = [lines[n]]
    for k in range(n - 1, max(-1, n - PASSWORD_WINDOW - 1), -1):
        if SIGNING_BLOCK.search(lines[k]) or lines[k].strip().startswith("}"):
            break
        out.append(lines[k])
    for k in range(n + 1, min(len(lines), n + PASSWORD_WINDOW + 1)):
        if SIGNING_BLOCK.search(lines[k]) or lines[k].strip().startswith("}"):
            break
        out.append(lines[k])
    return out


def _keystore_password(ctx: Context, base: str) -> str:
    """"literal" when a build file or workflow that names the keystore holds its password in the clear,
    "external" when the password comes from the environment or CI secrets, "" when masaudit can't tell."""
    found = set()
    for p in ctx.files(".gradle", ".kts", ".yml", ".yaml", ".sh", ".properties"):
        text = ctx.text(p) or ""
        if base not in text:
            continue
        lines = text.split("\n")
        for n, line in enumerate(lines):
            if base not in line:
                continue
            for near in _same_block(lines, n):
                if len(near) > MAX_SCRIPT_LINE:
                    continue
                for m in KEYSTORE_PASSWORD.finditer(near):
                    value = (m.group("v1") or m.group("v2") or m.group("v3") or "").strip()
                    if not value:
                        continue
                    if EXTERNAL_VALUE.search(value):
                        found.add("external")
                    elif LITERAL_VALUE.match(value) and value.strip("\"'").lower() not in ("null", "none", ""):
                        found.add("literal")
    if "literal" in found:
        return "literal"
    return "external" if found else ""


def _debug_keystore(ctx: Context, base: str) -> bool:
    if DEBUG_WORD.search(base):
        return True
    for p in ctx.files(".gradle", ".gradle.kts"):
        text = ctx.text(p) or ""
        if base in text and _in_debug_signing_block(text, base):
            return True
    for p in ctx.files(".properties"):
        text = ctx.text(p) or ""
        if base in text and ANDROID_PASSWORD.search(text):
            return True
    return False


@detector("ci_signing_material")
def signing_material(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in _all_names(ctx):
        base = path.rsplit("/", 1)[-1]
        if not base.lower().endswith(KEY_FILE_SUFFIXES) or base.lower() in HARMLESS_KEYS:
            continue
        if any(TEST_DIR.match(seg) for seg in path.split("/")[:-1]):
            continue
        if _debug_keystore(ctx, base):
            yield Hit(path, 0, base, f"`{base}` is a debug keystore (a debug signing config or Android's public "
                                     "`android` password). It signs nothing that ships.", severity="info")
            continue
        password = _keystore_password(ctx, base)
        kept_out = (" Its password is kept out of the repository (environment or CI secrets), but the keystore can "
                    "still be brute-forced offline.")
        if NON_RELEASE_WORD.search(base.rsplit(".", 1)[0]):
            yield Hit(path, 0, base, f"`{base}` looks like a signing key for a non-release build (nightly, QA, "
                                     "beta). Anyone who has it can sign builds your testers install as you."
                                     + (kept_out if password == "external" else ""),
                      severity="medium" if password == "external" else "high")
            continue
        if password == "external":
            yield Hit(path, 0, base, f"`{base}` looks like a signing key or certificate with its private key."
                                     + kept_out, severity="high")
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

VERIFY_METADATA = re.compile(r"<verify-metadata>\s{0,64}true\s{0,64}</verify-metadata>")


def _is_gradle_root(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in ("settings.gradle", "settings.gradle.kts")


def _gradle_verified(ctx: Context) -> bool:
    """Gradle dependency verification with `<verify-metadata>true`: an unlisted version fails the build.

    The file is often over safety.MAX_FILE_BYTES, so it is found by name and only its first 16 KiB,
    where <configuration> sits, are read.
    """
    for p in _all_names(ctx):
        if p == "gradle/verification-metadata.xml" or p.endswith("/gradle/verification-metadata.xml"):
            head = _read_head(ctx, p, 16384)
            if head and VERIFY_METADATA.search(head):
                return True
    return False


@detector("ci_missing_lockfile")
def missing_lockfile(ctx: Context, rule: Rule) -> Iterable[Hit]:
    names = _all_names(ctx)
    bases = {p.rsplit("/", 1)[-1] for p in names}
    gradle_roots = [p for p in ctx.files() if _is_gradle_root(p)]
    if gradle_roots and not any(b.endswith(".lockfile") for b in bases):
        uses_locking = any("dependencyLocking" in (ctx.text(p) or "")
                           for p in ctx.files(".gradle", ".gradle.kts"))
        if not uses_locking and not _gradle_verified(ctx):
            yield Hit(gradle_roots[0], 0, "", "No `gradle.lockfile` was found, so builds can resolve "
                                              "different dependency versions over time.")
    spm = [p for p in ctx.files(name="Package.swift")]
    spm += [p for p in ctx.files(".pbxproj") if "XCRemoteSwiftPackageReference" in (ctx.text(p) or "")]
    if spm and "Package.resolved" not in bases:
        yield Hit(spm[0], 0, "", "No `Package.resolved` was found, so Swift packages can resolve "
                                 "different versions over time.")
