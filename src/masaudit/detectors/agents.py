# SPDX-License-Identifier: Apache-2.0
"""AI coding-agent configuration committed to a mobile repository (CI-009 to CI-014). Book: §15.2-§15.4, §20.1.

A team that commits agent settings shares them with everyone who opens the repository in Claude Code, Cursor,
VS Code, Gemini CLI, or Codex. A pull request can change what those agents run, read, and are allowed to do on
a developer's machine, which holds signing keys and cloud credentials. These rules read the committed files:

  MCP servers           .mcp.json, .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json
  Instructions          AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, .windsurfrules, .clinerules,
                        .github/copilot-instructions.md, and rule, prompt, command, agent, and skill folders
  Permissions, hooks    .claude/settings.json, .claude/settings.local.json, .codex/config.toml

Every file is parsed as data; nothing is run. JSON with comments (VS Code's format) is accepted.
"""

from __future__ import annotations

import json
import re
from typing import Iterable, Iterator, List, Optional, Tuple

from masaudit import safety
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule

SCOPE = "ci"            # developer tooling: not app code, never lowered as debug or test code

# ---------------------------------------------------------------------------- which files

MCP_FILES = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".roo/mcp.json",
             ".kiro/settings/mcp.json")
CLAUDE_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
CODEX_CONFIG = ".codex/config.toml"


def _is_at(path: str, names: Iterable[str]) -> bool:
    return any(path == n or path.endswith("/" + n) for n in names)


def mcp_files(ctx: Context) -> List[str]:
    return [p for p in ctx.files(".json") if _is_at(p, MCP_FILES)]


def instruction_files(ctx: Context) -> List[str]:
    """Markdown an agent loads as instructions (safety.is_agent_instructions: the walk reads only these)."""
    return [p for p in ctx.files() if safety.is_agent_instructions(p)]


def settings_files(ctx: Context) -> List[str]:
    return [p for p in ctx.files(".json") if _is_at(p, CLAUDE_SETTINGS)]


# ---------------------------------------------------------------------------- reading

_JSONC_TOKEN = re.compile(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/|,(?=\s*[}\]])', re.DOTALL)


def load_jsonc(text: Optional[str]) -> object:
    """JSON, or JSON with comments and trailing commas (VS Code's mcp.json); None when it isn't either."""
    if not text or len(text) > safety.MAX_FILE_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    # Comments and trailing commas outside strings become spaces of the same length, then parse again.
    stripped = _JSONC_TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"')
                                else re.sub(r"[^\n]", " ", m.group(0)), text)
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def _parsed(ctx: Context, path: str) -> Optional[dict]:
    """The file as a JSON object, or None. A file that should be JSON and isn't is noted, not passed as clean."""
    data = load_jsonc(ctx.text(path))
    if data is None and ctx.text(path) is not None:
        ctx.note_unknown(f"{path} isn't valid JSON, so its agent settings weren't checked.")
        return None
    return data if isinstance(data, dict) else None


def _line_after(text: str, anchor: str, *needles: str) -> int:
    """The line of the first of `needles` found after `anchor` in `text` (1-based); else the anchor's line, or 1."""
    start = text.find(anchor)
    start = 0 if start < 0 else start
    for needle in needles:
        at = text.find(needle, start) if needle else -1
        if at >= 0:
            return text.count("\n", 0, at) + 1
    return text.count("\n", 0, start) + 1


def _json_str(value: str) -> str:
    return json.dumps(value)[1:-1]          # how the value appears between quotes in the file


def _servers(data: dict) -> Iterator[Tuple[str, dict]]:
    """(name, config) of each MCP server: `mcpServers` (Claude, Cursor, Gemini) or `servers` (VS Code)."""
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, server in list(block.items())[:500]:
                if isinstance(server, dict):
                    yield str(name), server


def _strings(value: object) -> List[str]:
    return [v for v in value if isinstance(v, str)][:200] if isinstance(value, list) else []


# ---------------------------------------------------------------------------- CI-009 unpinned MCP server

_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_GIT_SHA = re.compile(r"#[0-9a-f]{40}$")
_LOCAL = re.compile(r"^(?:\.{0,2}/|~|[A-Za-z]:[\\/]|file:)")
_NPX = {"npx", "npx.cmd", "bunx", "bunx.cmd"}
_DLX = {"pnpm", "pnpm.cmd", "yarn", "yarn.cmd"}                  # `pnpm dlx pkg`, `yarn dlx pkg`
_PY_RUNNERS = {"uvx", "uvx.exe", "pipx"}                         # `uvx pkg`, `pipx run pkg`
_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "--network",
                       "--entrypoint", "--env-file", "-u", "--user", "--mount", "--platform", "-l", "--label",
                       "--add-host", "--cpus", "-m", "--memory", "--pull"}
_NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig"}


def _npm_spec_pinned(spec: str) -> bool:
    """`name@1.2.3` or `@scope/name@1.2.3`; a git URL pinned to a commit. Ranges and dist-tags (`@latest`) move."""
    if _GIT_SHA.search(spec):
        return True
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return False
    return bool(_EXACT_SEMVER.match(body.rsplit("@", 1)[1]))


def _py_spec_pinned(spec: str) -> bool:
    """`pkg==1.2.3` or uvx's `pkg@1.2.3`; a git URL pinned to a commit."""
    if re.search(r"@[0-9a-f]{40}$", spec):
        return True
    m = re.search(r"(?:==|@)(v?[0-9][^\s,;]*)$", spec)
    return bool(m and _EXACT_SEMVER.match(m.group(1)) and "*" not in m.group(1))


def _first_operand(args: List[str], value_flags: set) -> Tuple[Optional[str], List[str]]:
    """The first argument that isn't an option (skipping option values), and what follows it."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if a in value_flags and "=" not in a:
                i += 1
            i += 1
            continue
        return a, args[i + 1:]
    return None, []


def unpinned_package(command: str, args: List[str]) -> Optional[Tuple[str, str]]:
    """(package, how to pin it) when a launcher would fetch a package or image that isn't pinned; else None."""
    base = re.split(r"[\\/]", command.strip())[-1].lower() if command else ""
    if base in _DLX and args[:1] == ["dlx"]:
        base, args = "npx", args[1:]
    if base in _NPX:
        # `npx -p pkg@1.0.0 cmd` names the package with -p; otherwise it's the first operand.
        for i, a in enumerate(args):
            if a in ("-p", "--package") and i + 1 < len(args):
                spec = args[i + 1]
                break
            if a.startswith("--package="):
                spec = a.split("=", 1)[1]
                break
        else:
            spec, _rest = _first_operand(args, _NPX_VALUE_FLAGS)
        if not spec or _LOCAL.match(spec) or _npm_spec_pinned(spec):
            return None
        return spec, "an exact version such as `name@1.2.3`"
    if base in _PY_RUNNERS:
        rest = args[1:] if base == "pipx" and args[:1] == ["run"] else args
        if base == "pipx" and args[:1] != ["run"]:
            return None
        for i, a in enumerate(rest):
            if a == "--from" and i + 1 < len(rest):
                spec = rest[i + 1]
                break
            if a.startswith("--from=") or a.startswith("--spec="):
                spec = a.split("=", 1)[1]
                break
            if a == "--spec" and i + 1 < len(rest):
                spec = rest[i + 1]
                break
        else:
            spec, _rest = _first_operand(rest, {"--python", "--with", "--index", "--index-url", "-p"})
        if not spec or _LOCAL.match(spec) or _py_spec_pinned(spec):
            return None
        return spec, "an exact version such as `name==1.2.3`"
    if base in ("docker", "podman", "docker.exe", "podman.exe") and args[:1] == ["run"]:
        image, _rest = _first_operand(args[1:], _DOCKER_VALUE_FLAGS)
        if not image or "@sha256:" in image:
            return None
        return image, "an image digest such as `image@sha256:...`"
    return None


@detector("ci_mcp_unpinned")
def mcp_unpinned(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in mcp_files(ctx):
        data = _parsed(ctx, path)
        if data is None:
            continue
        text = ctx.text(path) or ""
        for name, server in _servers(data):
            command = server.get("command") if isinstance(server.get("command"), str) else ""
            args = _strings(server.get("args"))
            if command and not args and " " in command.strip():
                parts = command.split()                     # "npx -y some-server" written as one string
                command, args = parts[0], parts[1:]
            found = unpinned_package(command, args)
            if found is None:
                continue
            spec, how = found
            line = _line_after(text, f'"{_json_str(name)}"', f'"{_json_str(spec)}"', _json_str(spec))
            yield Hit(path, line, ctx.snippet(path, line),
                      f"MCP server `{name}` runs `{spec}`, which isn't pinned: each start can fetch different "
                      f"code. Pin it to {how}.", scope=SCOPE)


# ---------------------------------------------------------------------------- CI-010 secret in MCP config

_REFERENCE = re.compile(r"^\s*(?:\$\{[^}]{1,100}\}|\$[A-Za-z_][A-Za-z0-9_]{0,100}|%[A-Za-z_][A-Za-z0-9_]*%)\s*$")
_HAS_REFERENCE = re.compile(r"\$\{[^}]{1,100}\}|\$[A-Z_][A-Z0-9_]{2,}")
_SECRET_NAME = re.compile(r"(?i)(?:token|secret|passw|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
                          r"credential|auth|pat\b|_pat$|bearer|session|cookie|license[_-]?key)")
_PLACEHOLDER = re.compile(r"(?i)^(?:<[^>]*>|\[[^\]]*\]|\{[^}]*\}|x{3,}|\*{3,}|\.{3,}|your[-_ ].*|.*[-_ ]here|"
                          r"changeme|change[-_]me|replace[-_ ]?me.*|todo|tbd|none|null|test|example|dummy|redacted|"
                          r"secret|token|password|api[-_]?key|sk-\.\.\.|true|false)$")
_KNOWN_SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|"
    r"sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|"
    r"lin_api_[A-Za-z0-9]{30,}|figd_[A-Za-z0-9_-]{30,}|ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{40,})")
_BEARER = re.compile(r"(?i)^(?:bearer|basic|token)\s+(\S{8,})$")
_SECRET_ARG = re.compile(r"(?i)^--?(?:[\w-]*(?:token|secret|api[-_]?key|password|access[-_]?key))=(.+)$")


def _looks_real(value: str) -> bool:
    """A value that can be a live credential: long enough, mixed characters, not a placeholder or reference."""
    v = value.strip().strip("'\"")
    m = _BEARER.match(v)
    if m:
        v = m.group(1)
    if len(v) < 12 or _REFERENCE.match(v) or _HAS_REFERENCE.search(v) or _PLACEHOLDER.match(v):
        return False
    if " " in v or v.startswith(("http://", "https://")):
        return False
    return bool(re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def _secret_values(server: dict) -> Iterator[Tuple[str, str]]:
    """(where, value) of each literal that holds a secret: env and header values, arguments, the URL's query."""
    for block in ("env", "headers"):
        entries = server.get(block)
        if isinstance(entries, dict):
            for key, value in list(entries.items())[:200]:
                if not isinstance(value, str):
                    continue
                if _KNOWN_SECRET.search(value) or (_SECRET_NAME.search(str(key)) and _looks_real(value)):
                    yield f"{block} `{key}`", value
    args = _strings(server.get("args"))
    for i, a in enumerate(args):
        m = _SECRET_ARG.match(a)
        if m and _looks_real(m.group(1)):
            yield "an argument", m.group(1)
        elif _KNOWN_SECRET.search(a):
            yield "an argument", a
        elif a.startswith("-") and _SECRET_NAME.search(a) and i + 1 < len(args) and _looks_real(args[i + 1]):
            yield f"the value of `{a}`", args[i + 1]
    url = server.get("url") or server.get("serverUrl") or server.get("httpUrl")
    if isinstance(url, str):
        for m in re.finditer(r"[?&]([\w.-]{1,60})=([^&#\s]{8,})", url):
            if _KNOWN_SECRET.search(m.group(2)) or (_SECRET_NAME.search(m.group(1)) and _looks_real(m.group(2))):
                yield f"the URL's `{m.group(1)}` parameter", m.group(2)


@detector("ci_mcp_secret")
def mcp_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in mcp_files(ctx):
        data = _parsed(ctx, path)
        if data is None:
            continue
        text = ctx.text(path) or ""
        for name, server in _servers(data):
            seen = set()
            for where, value in _secret_values(server):
                line = _line_after(text, f'"{_json_str(name)}"', _json_str(value))
                if line in seen:
                    continue
                seen.add(line)
                snippet = ctx.snippet(path, line)
                if len(value) >= 4:     # the generic masker may not know this format: hide the value itself
                    snippet = snippet.replace(value, value[:4] + "…[masked]")
                yield Hit(path, line, snippet,
                          f"MCP server `{name}` has a secret written into {where}. Everyone who can read the "
                          "repository has it.", scope=SCOPE)


# ---------------------------------------------------------------------------- CI-011 hidden text in instructions

_TAGS = re.compile(r"[\U000e0000-\U000e007f]+")
_VARIATION_SUPPLEMENT = re.compile(r"[\U000e0100-\U000e01ef]{2,}")
_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_ZERO_WIDTH_RUN = re.compile(r"[\u200b\u200c\u200d\u2060-\u2064\ufeff\u180e]{3,}")


def _decode_tags(run: str) -> str:
    """What a run of Unicode tag characters spells: each one is an ASCII character moved to U+E00xx."""
    return "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007E else "" for c in run)


def hidden_text(line: str) -> Optional[str]:
    """Why a line of an agent instruction file holds text a person reading it can't see, or None."""
    m = _TAGS.search(line)
    if m:
        decoded = re.sub(r"\s+", " ", _decode_tags(m.group(0))).strip()
        shown = safety.mask(decoded)[:80] + ("..." if len(decoded) > 80 else "")
        return (f"{len(m.group(0))} invisible Unicode tag characters. AI models read them as text; here they "
                f"spell: \"{shown}\"." if decoded else
                f"{len(m.group(0))} invisible Unicode tag characters, which AI models can read as text.")
    m = _VARIATION_SUPPLEMENT.search(line)
    if m:
        return (f"{len(m.group(0))} invisible variation selectors in a row, a known way to hide a message "
                "that an AI model can decode.")
    m = _BIDI.search(line)
    if m:
        return (f"U+{ord(m.group(0)):04X}, a bidirectional control character, changes the order in which this "
                "line is displayed, so a reviewer may read different instructions from the ones the agent gets.")
    m = _ZERO_WIDTH_RUN.search(line)
    if m:
        return (f"{len(m.group(0))} zero-width characters in a row: invisible to a reviewer, and a known way to "
                "encode a hidden message.")
    return None


@detector("ci_agent_hidden_text")
def agent_hidden_text(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in instruction_files(ctx):
        text = ctx.text(path)
        if not text or text.isascii():
            continue
        for n, line in safety.iter_lines(text):
            if line.isascii():
                continue
            why = hidden_text(line)
            if why:
                yield Hit(path, n, ctx.snippet(path, n), why, scope=SCOPE)


# ---------------------------------------------------------------------------- CI-012 hidden instructions

# Markdown that doesn't render: HTML comments and link-reference "comments" (`[//]: # (text)`).
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_REF_COMMENT = re.compile(r"(?m)^\[(?://|comment|_)\]:\s*#\s*(?:\((.{0,2000}?)\)|\"(.{0,2000}?)\")\s*$")
_DIRECTIVE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|"
    r"other|user'?s?)\s+(?:instructions|rules|prompts?|messages?)"
    r"|\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|show|reveal|report|alert|ask)\b[^.\n]{0,40}\b(?:user|"
    r"human|developer|reviewer|anyone)"
    r"|\bwithout\s+(?:telling|asking|informing|notifying)\b"
    r"|\b(?:silently|secretly|quietly)\s+(?:run|execute|add|insert|send|upload|post|install|download|modify|change)"
    r"|\b(?:curl|wget|Invoke-WebRequest|iwr|irm)\b[^\n]{0,200}(?:\|\s*(?:ba|z)?sh\b|\|\s*python|\|\s*node|\|\s*iex)"
    r"|\b(?:base64\s+(?:-d|--decode)|eval\s*\(|exec\s*\(|nc\s+-e\b|/dev/tcp/)"
    r"|\b(?:exfiltrat\w*|upload|send|post)\b[^.\n]{0,60}\b(?:secrets?|tokens?|credentials?|keys?|\.env|keystore|"
    r"ssh)\b[^.\n]{0,60}\b(?:to|at)\s+https?://"
    r"|\b(?:you\s+are\s+now|new\s+instructions?:|system\s+prompt|</?system>|\[/?INST\])"
    r"|\b(?:add|insert)\b[^.\n]{0,60}\b(?:backdoor|hidden\s+(?:account|user|endpoint)|test\s+account\s+with)")


def hidden_directive(comment: str) -> Optional["re.Match[str]"]:
    """Where an unrendered comment gives the agent a suspicious order, or None."""
    return _DIRECTIVE.search(comment)


@detector("ci_agent_hidden_instructions")
def agent_hidden_instructions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in instruction_files(ctx):
        text = ctx.text(path)
        if not text or ("<!--" not in text and "]:" not in text):
            continue
        for regex in (_HTML_COMMENT, _REF_COMMENT):
            for m in regex.finditer(text):
                group = next((i for i in range(1, (m.lastindex or 0) + 1) if m.group(i)), 0)
                if not group:
                    continue
                d = hidden_directive(m.group(group))
                if d is None:
                    continue
                at = m.start(group) + d.start()             # the line of the order, inside a long comment
                line = text.count("\n", 0, at) + 1
                said = re.sub(r"\s+", " ", m.group(group)[d.start():d.start() + 120].split("\n")[0]).strip()
                yield Hit(path, line, ctx.snippet(path, line),
                          f"A comment that GitHub and Markdown viewers don't show, but the agent reads, says "
                          f"\"{safety.mask(said)}\". Check who added it and why.", scope=SCOPE)


# ---------------------------------------------------------------------------- CI-013 agent runs unchecked

_ANY_BASH = re.compile(r"^\s*(?:Bash|Shell|run_shell_command)\s*(?:\(\s*(?:\*|:\*|\*:\*)?\s*\))?\s*$")


@detector("ci_agent_permissions")
def agent_permissions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in settings_files(ctx):
        data = _parsed(ctx, path)
        if data is None:
            continue
        text = ctx.text(path) or ""
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            line = _line_after(text, '"permissions"', '"bypassPermissions"')
            yield Hit(path, line, ctx.snippet(path, line),
                      "Claude Code runs every tool without asking (bypassPermissions) for everyone who opens "
                      "the repository.", scope=SCOPE, severity="high")
        for entry in _strings(perms.get("allow")):
            if _ANY_BASH.match(entry):
                line = _line_after(text, '"allow"', f'"{_json_str(entry)}"')
                yield Hit(path, line, ctx.snippet(path, line),
                          f"`{entry}` lets the agent run any shell command without asking.", scope=SCOPE,
                          severity="high")
        if data.get("enableAllProjectMcpServers") is True:
            line = _line_after(text, '"enableAllProjectMcpServers"', "true")
            yield Hit(path, line, ctx.snippet(path, line),
                      "Every MCP server in .mcp.json starts without asking, including one a pull request adds.",
                      scope=SCOPE, severity="medium")
    for path in ctx.files(".toml"):
        if not _is_at(path, (CODEX_CONFIG,)):
            continue
        text = ctx.text(path) or ""
        for n, line in safety.iter_lines(text):
            m = re.match(r"""^\s*(sandbox_mode|approval_policy)\s*=\s*["']([\w-]+)["']""", line)
            if m and (m.group(1), m.group(2)) in (("sandbox_mode", "danger-full-access"),
                                                  ("approval_policy", "never")):
                what = ("runs commands with no sandbox" if m.group(1) == "sandbox_mode"
                        else "never asks before running a command")
                yield Hit(path, n, ctx.snippet(path, n), f"Codex {what} for everyone who opens the repository.",
                          scope=SCOPE, severity="high")


# ---------------------------------------------------------------------------- CI-014 hook runs downloaded code

_DOWNLOAD_RUN = re.compile(
    r"(?i)\b(?:curl|wget|fetch|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b[^\n]{0,300}?\|\s*(?:sudo\s+)?"
    r"(?:ba|z|da)?sh\b|\b(?:curl|wget|fetch|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b[^\n]{0,300}?\|\s*"
    r"(?:python3?|node|ruby|perl|iex|Invoke-Expression)\b"
    r"|(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)"
    r"|\b(?:iex|Invoke-Expression)\b[^\n]{0,40}\((?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object)"
    r"|\bpython3?\s+-c\s+[\"'][^\n]{0,200}\burl(?:lib|open)")


def _hook_commands(hooks: object) -> Iterator[str]:
    """Every `command` string in Claude Code's hooks block, whatever the event."""
    if isinstance(hooks, dict):
        for value in list(hooks.values())[:100]:
            yield from _hook_commands(value)
    elif isinstance(hooks, list):
        for item in hooks[:200]:
            yield from _hook_commands(item)
    elif isinstance(hooks, str):
        return
    if isinstance(hooks, dict) and isinstance(hooks.get("command"), str):
        yield hooks["command"]


@detector("ci_agent_hook_download")
def agent_hook_download(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in settings_files(ctx):
        data = _parsed(ctx, path)
        if data is None or not isinstance(data.get("hooks"), (dict, list)):
            continue
        text = ctx.text(path) or ""
        for command in _hook_commands(data["hooks"]):
            line = _line_after(text, '"hooks"', _json_str(command)[:60])
            if _DOWNLOAD_RUN.search(command):
                yield Hit(path, line, ctx.snippet(path, line),
                          "A hook downloads code and runs it each time the agent starts or uses a tool, on every "
                          "developer's machine that opens the repository.", scope=SCOPE)
                continue
            parts = command.split()
            found = unpinned_package(parts[0], parts[1:]) if parts else None
            if found is not None:
                yield Hit(path, line, ctx.snippet(path, line),
                          f"A hook runs `{found[0]}`, which isn't pinned, so each run can fetch different code. "
                          f"Pin it to {found[1]}.", scope=SCOPE, severity="medium")
