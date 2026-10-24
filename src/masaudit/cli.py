# SPDX-License-Identifier: Apache-2.0
"""masaudit command line.

Exit codes: 0 ok, 1 open findings at or above --fail-on, 2 tool error.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from masaudit import __version__, config, detect, engine, fix, importers, lexer, safety, suppress
from masaudit import profile as profile_mod
from masaudit.model import SEVERITY_RANK, Finding, Profile, Project, Rule

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
DEFAULT_REPORT = "SECURITY-AUDIT.md"
DEFAULT_PATCH = "masaudit-fixes.patch"
DEFAULT_BASELINE = ".masaudit-baseline.json"
SPONSOR_LINE = "masaudit is free. If it helped, you can sponsor it: https://github.com/sponsors/hossam9k"
ASSUMED_LINE = "Assumed a general app (MAS-L1+P). Set --app-type for accurate results."

CLUE_SUFFIXES = (".gradle", ".kts", ".kt", ".java", ".swift", ".m", ".mm", ".dart", ".js", ".ts",
                 ".tsx", ".toml", ".plist", ".entitlements")
CLUE_NAMES = {"Podfile", "Package.swift", "pubspec.yaml", "package.json", "Cartfile"}
MAX_CLUE_FILES = 3000


class ToolError(Exception):
    pass


@dataclass
class ScanResult:
    root: str
    project: Project
    profile: Profile
    findings: List[Finding]
    rules: List[Rule]
    rules_version: str
    notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------- arguments


EPILOG = f"""\
examples:
  masaudit                          scan the current directory, write SECURITY-AUDIT.md
  masaudit app --app-type banking   scan ./app as a banking app
  masaudit --format sarif --output masaudit.sarif --fail-on high
  masaudit --fix-safe               preview safe fixes as a diff (changes nothing)
  masaudit --explain AND-001        read about one rule (offline)

app types: {", ".join(profile_mod.APP_TYPES)}

{SPONSOR_LINE}"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="masaudit",
        description="Mobile security scanner that scales its advice to your app's risk profile.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", default=".", metavar="PATH", help="project to scan (default: .)")
    p.add_argument("--app-type", metavar="TYPE", help="what kind of app this is (see 'app types' below)")
    p.add_argument("--format", choices=["md", "json", "sarif", "text"],
                   help="output format (default: summary on screen + SECURITY-AUDIT.md)")
    p.add_argument("--output", metavar="FILE", help="write the report here instead of the default")
    p.add_argument("--fail-on", choices=list(config.FAIL_ON),
                   help="exit 1 if an open finding to fix is at or above this severity")
    p.add_argument("--baseline", metavar="FILE", help="ignore findings listed in this baseline file")
    p.add_argument("--update-baseline", action="store_true",
                   help=f"write current findings to the baseline (default file: {DEFAULT_BASELINE})")
    p.add_argument("--fix-safe", action="store_true",
                   help="print a diff of vetted safe fixes (changes nothing)")
    p.add_argument("--write-patch", nargs="?", const=DEFAULT_PATCH, metavar="FILE",
                   help=f"with --fix-safe: also save the diff (default: {DEFAULT_PATCH})")
    p.add_argument("--yes", action="store_true",
                   help="with --fix-safe: apply the fixes in place (needs a clean git tree)")
    p.add_argument("--import-sarif", nargs="+", metavar="FILE", default=[],
                   help="add results from Android Lint, mobsfscan, Semgrep, or zizmor SARIF files")
    p.add_argument("--sarif-include-not-needed", action="store_true",
                   help="include 'not needed for your app' findings in SARIF as notes")
    p.add_argument("--explain", metavar="RULE-ID", help="print what a rule checks and how to fix it")
    p.add_argument("--list-rules", action="store_true", help="list every rule")
    p.add_argument("--no-color", action="store_true", help="no colors in terminal output")
    p.add_argument("--version", action="version",
                   version=f"masaudit {__version__} (rules {_safe_rules_version()})")
    return p


def _safe_rules_version() -> str:
    try:
        return engine.rules_version()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------- profile


def _is_interactive() -> bool:
    if os.environ.get("CI"):
        return False
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(prompt: str) -> Optional[str]:
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        return input()
    except EOFError:
        return None


def prompt_app_type(root: str, suggestions: List[str]) -> Optional[str]:
    """Ask the one question. Returns an app type, or None if the user gave no usable answer."""
    types = list(profile_mod.APP_TYPES)
    lines = ["", "What kind of app is this?"]
    for i, key in enumerate(types, 1):
        lines.append(f"  {i:>2}. {key:<16} {profile_mod.APP_TYPES[key][1]}")
    if suggestions:
        lines.append("")
        lines.append("Code clues (suggestions only):")
        lines += [f"  - {s}" for s in suggestions]
    sys.stderr.write(asciify("\n".join(lines)) + "\n")
    default_num = types.index("general") + 1
    for _ in range(3):
        answer = _ask(f"Enter a number or name [{default_num} = general]: ")
        if answer is None:
            return None
        answer = answer.strip()
        if not answer:
            return "general"
        if answer.isdigit() and 1 <= int(answer) <= len(types):
            return types[int(answer) - 1]
        try:
            return profile_mod.normalize(answer)
        except ValueError:
            sys.stderr.write("Not one of the listed types. Try again.\n")
    return None


def _confirm_against_clues(chosen: str, clues: Sequence[profile_mod.Clue], rules: Sequence[Rule]) -> str:
    """If the code suggests a riskier type than the answer, say so once and offer to switch."""
    warnings = profile_mod.check(profile_mod.make(chosen, "prompt"), list(clues), list(rules))
    if not warnings:
        return chosen
    suggested = re.search(r"--app-type ([\w-]+)", warnings[0]).group(1)  # type: ignore[union-attr]
    sys.stderr.write(asciify("\n" + warnings[0]) + "\n")
    answer = _ask(f"Use '{suggested}' instead? [y/N]: ")
    return suggested if answer is not None and answer.strip().lower() in ("y", "yes") else chosen


def _annotate_github(warnings: Sequence[str]) -> None:
    """On GitHub Actions, show app-type warnings as annotations on the run and the pull request."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for w in warnings:
        # Workflow-command escaping: % first, then line breaks.
        msg = w.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        sys.stdout.write(f"::warning title=masaudit: check your app type::{msg}\n")


def _offer_save(root: str, app_type: str) -> None:
    answer = _ask(f"Save '{app_type}' to {config.FILE_NAME} so you aren't asked again? [Y/n]: ")
    if answer is None or answer.strip().lower() not in ("", "y", "yes"):
        return
    try:
        path = config.save_app_type(root, app_type)
        sys.stderr.write(f"Saved {path}\n")
    except OSError as exc:
        sys.stderr.write(f"Couldn't save {config.FILE_NAME}: {exc}\n")


def resolve_profile(cli_type: Optional[str], cfg: Dict[str, object], root: str,
                    suggestions: List[str], allow_prompt: bool = True,
                    clues: Sequence[profile_mod.Clue] = (), rules: Sequence[Rule] = ()) -> Profile:
    if cli_type:
        try:
            prof = profile_mod.make(cli_type, "flag")
        except ValueError as exc:
            raise ToolError(str(exc)) from exc
    elif cfg.get("app_type"):
        prof = profile_mod.make(str(cfg["app_type"]), "config")
    else:
        chosen = prompt_app_type(root, suggestions) if allow_prompt and _is_interactive() else None
        if chosen:
            chosen = _confirm_against_clues(chosen, clues, rules)
            prof = profile_mod.make(chosen, "prompt")
            _offer_save(root, chosen)
        else:
            prof = profile_mod.make("general", "default")
    prof.suggestions = list(suggestions)
    return prof


# ---------------------------------------------------------------------------- scanning


def collect_clues(root: str, files: List[str]) -> List[profile_mod.Clue]:
    """Evidence about the app's type from code that ships: tests, demos, and comments don't count."""
    texts: Dict[str, str] = {}
    for rel in files:
        base = rel.rsplit("/", 1)[-1]
        if not (rel.endswith(CLUE_SUFFIXES) or base in CLUE_NAMES):
            continue
        if detect.scope_of(rel) in ("test", "debug"):
            continue
        text = safety.read_text(root, rel)
        if text is None:
            continue
        texts[rel] = text
        if len(texts) >= MAX_CLUE_FILES:
            break
    return profile_mod.find_clues(texts, strip=_without_comments)


def _without_comments(rel: str, text: str) -> str:
    """Comments out, strings (dependency names) kept."""
    lang = lexer.LANG_BY_SUFFIX.get(os.path.splitext(rel)[1])
    if lang:
        return lexer.strip(text, lang)
    if rel.rsplit("/", 1)[-1] in ("Podfile", "Cartfile") or rel.endswith((".yaml", ".yml", ".toml")):
        return re.sub(r"(?m)^\s*#.*$", "", text)
    return text


def scan(root: str, cli_type: Optional[str] = None, cfg: Optional[Dict[str, object]] = None,
         rules: Optional[List[Rule]] = None, import_sarif: Sequence[str] = (),
         baseline: Optional[str] = None, update_baseline: bool = False,
         allow_prompt: bool = True) -> ScanResult:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ToolError(f"not a directory: {root}")
    cfg = cfg if cfg is not None else config.load(root)
    files = safety.walk(root)
    excludes = list(cfg.get("exclude") or [])  # type: ignore[arg-type]
    if excludes:
        files = [f for f in files if not config.is_excluded(f, excludes)]
    platforms = detect.platforms(files)
    clues = collect_clues(root, files)
    all_rules = rules if rules is not None else engine.load_rules()
    prof = resolve_profile(cli_type, cfg, root, [c.describe() for c in clues], allow_prompt, clues, all_rules)

    project = Project(root=root, platforms=platforms, files=files)
    findings = engine.run(project, all_rules, prof)
    notes: List[str] = []
    for sarif_path in import_sarif:
        try:
            extra, extra_notes = importers.import_sarif(sarif_path, root, all_rules)
        except importers.SarifImportError as exc:
            raise ToolError(str(exc)) from exc
        findings += extra
        notes += extra_notes
    findings = _dedupe(findings)
    engine.calibrate(findings, prof)
    prof.warnings = profile_mod.check(prof, clues, all_rules, findings)
    notes += suppress.apply_inline(findings, root)
    if baseline or update_baseline:
        path = baseline or os.path.join(root, DEFAULT_BASELINE)
        if update_baseline:
            n = suppress.write_baseline(path, findings)
            notes.append(f"Wrote {n} finding(s) to the baseline {os.path.basename(path)}.")
        try:
            fps = suppress.load_baseline(path)
        except suppress.BaselineError as exc:
            raise ToolError(str(exc)) from exc
        suppress.apply_baseline(findings, fps)
    return ScanResult(root=root, project=project, profile=prof, findings=findings, rules=all_rules,
                      rules_version=engine.rules_version(), notes=notes)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule.id, f.location.path, f.location.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def fails(findings: List[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    limit = SEVERITY_RANK[fail_on]
    return any(f.status == "open" and f.bucket in ("fix-before-release", "fix-soon")
               and SEVERITY_RANK.get(f.effective_severity, 9) <= limit for f in findings)


# ---------------------------------------------------------------------------- output helpers


def asciify(s: str) -> str:
    from masaudit.report.terminal import asciify as _a

    return _a(s)


def _write_stdout(text: str) -> None:
    data = text.encode("utf-8")
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        sys.stdout.flush()
        buf.write(data)
        buf.flush()
    else:
        sys.stdout.write(text)


def _write_file(path: str, text: str) -> None:
    try:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    except OSError as exc:
        raise ToolError(f"can't write {path}: {exc}") from exc


def _find_rule(rules: List[Rule], rule_id: str) -> Optional[Rule]:
    want = rule_id.strip().upper()
    return next((r for r in rules if r.id.upper() == want), None)


# ---------------------------------------------------------------------------- fix-safe


def _git_clean(root: str) -> Optional[str]:
    """None if the git tree at root is clean; otherwise the reason it isn't usable."""
    git = shutil.which("git")
    if not git:
        return "git is not installed, so masaudit can't confirm your changes are safe to overwrite."
    try:
        # A hostile repo config must not run a command on `git status`: no fsmonitor, no hooks
        # (post-index-change), and no optional index writes that would trigger them.
        env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
        proc = subprocess.run([git, "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
                               "status", "--porcelain", "--untracked-files=normal"],
                              cwd=root, capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"couldn't run git status: {exc}"
    if proc.returncode != 0:
        return "this folder isn't a git repository, so there is no way to undo the change."
    if proc.stdout.strip():
        return "the git working tree has uncommitted changes. Commit or stash them first."
    return None


def run_fix_safe(result: ScanResult, args) -> int:
    plan = fix.plan(result.root, result.findings)
    diff = fix.unified_diff(plan.fixes)
    if diff:
        _write_stdout(diff)
    else:
        sys.stderr.write("No safe fixes to apply.\n")
    for s in plan.suggestions:
        sys.stderr.write(asciify(f"Suggestion (not changed): {s}") + "\n")
    for s in plan.skipped:
        sys.stderr.write(asciify(f"Skipped: {s}") + "\n")
    if args.write_patch and diff:
        _write_file(args.write_patch, diff)
        sys.stderr.write(f"Wrote {args.write_patch}. Apply it with: git apply {args.write_patch}\n")
    if args.yes and plan.fixes:
        reason = _git_clean(result.root)
        if reason:
            sys.stderr.write(f"masaudit: not applying fixes: {reason}\n")
            return EXIT_ERROR
        written = fix.apply(result.root, plan.fixes)
        sys.stderr.write(f"Applied {len(written)} fix(es): {', '.join(written)}\n")
    return EXIT_OK


# ---------------------------------------------------------------------------- main


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # `--import-sarif a.sarif PATH` puts PATH into the list; take a trailing directory back as PATH.
    if args.path == "." and len(args.import_sarif) > 1 and os.path.isdir(args.import_sarif[-1]):
        args.path = args.import_sarif.pop()
    try:
        return _main(args)
    except (ToolError, config.ConfigError) as exc:
        sys.stderr.write(asciify(f"masaudit: error: {exc}") + "\n")
        return EXIT_ERROR
    except KeyboardInterrupt:
        sys.stderr.write("masaudit: interrupted\n")
        return EXIT_ERROR
    except Exception as exc:  # a bug or a broken rule: never a silent pass
        sys.stderr.write(asciify(f"masaudit: internal error: {exc.__class__.__name__}: {exc}") + "\n")
        return EXIT_ERROR


def _main(args) -> int:
    from masaudit.report import jsonout, markdown, sarif, terminal

    if args.explain or args.list_rules:
        rules = engine.load_rules()
        if args.list_rules:
            sys.stdout.write(terminal.list_rules(rules))
        if args.explain:
            rule = _find_rule(rules, args.explain)
            if rule is None:
                raise ToolError(f"no rule with id {args.explain} (try --list-rules)")
            sys.stdout.write(terminal.explain(rule))
        return EXIT_OK
    if (args.yes or args.write_patch) and not args.fix_safe:
        raise ToolError("--yes and --write-patch only work together with --fix-safe")

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        raise ToolError(f"not a directory: {args.path}")
    cfg = config.load(root)
    fail_on = config.resolve_fail_on(args.fail_on, cfg)
    result = scan(root, cli_type=args.app_type, cfg=cfg, import_sarif=args.import_sarif,
                  baseline=args.baseline, update_baseline=args.update_baseline)

    if args.fix_safe:
        return run_fix_safe(result, args)

    color = terminal.use_color(args.no_color)
    if args.format is None:
        out_path = os.path.abspath(args.output) if args.output else os.path.join(root, DEFAULT_REPORT)
        _write_file(out_path, markdown.render(result))
        sys.stdout.write(terminal.render(result, report_path=out_path, color=color))
    else:
        if args.format == "md":
            text = markdown.render(result)
        elif args.format == "json":
            text = jsonout.render(result)
        elif args.format == "sarif":
            text = sarif.render(result, include_not_needed=args.sarif_include_not_needed)
        else:
            text = terminal.render(result, report_path=None, color=color and not args.output)
        if args.output:
            _write_file(args.output, text)
            sys.stderr.write(f"Wrote {args.output}\n")
        else:
            _write_stdout(text)
        if result.profile.source == "default" and args.format != "text":
            sys.stderr.write(ASSUMED_LINE + "\n")
        if args.format != "text":
            for w in result.profile.warnings:
                sys.stderr.write(asciify(f"WARNING: {w}") + "\n")
    _annotate_github(result.profile.warnings)
    if fails(result.findings, fail_on):
        n = sum(1 for f in result.findings if f.status == "open" and f.bucket in ("fix-before-release", "fix-soon")
                and SEVERITY_RANK.get(f.effective_severity, 9) <= SEVERITY_RANK[fail_on])
        sys.stderr.write(f"Exit 1: {n} open finding(s) at {fail_on} severity or above (--fail-on {fail_on}).\n")
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
