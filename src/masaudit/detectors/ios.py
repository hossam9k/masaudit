# SPDX-License-Identifier: Apache-2.0
"""iOS detectors: Info.plist / ATS, entitlements, privacy manifests, project.pbxproj, shared
schemes and .xcconfig build settings, and Swift or Objective-C code that needs more than a
single regex (function bodies, #if blocks evaluated against the real compilation conditions).
"""

from __future__ import annotations

import itertools
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.detect import scope_of as _scope_of
from masaudit.detectors import flutter
from masaudit.textscan import bracket_match, holds_any
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.parsers import pbxproj, plist, xcconfig, xcscheme


_SCOPES: Dict[str, str] = {}


def scope_of(path: str) -> str:
    """detect.scope_of, memoised: detectors ask it about the same paths many times per scan."""
    s = _SCOPES.get(path)
    if s is None:
        if len(_SCOPES) >= 200_000:
            _SCOPES.clear()
        s = _SCOPES[path] = _scope_of(path)
    return s


CODE_SUFFIXES = (".swift", ".m", ".mm", ".h")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")

# ============================================================================ shared helpers


def _cache(ctx: Context) -> Dict[str, Any]:
    c = getattr(ctx, "_ios_cache", None)
    if c is None:
        c = {}
        ctx._ios_cache = c  # type: ignore[attr-defined]
    return c


def _listdir(ctx: Context, rel: str) -> List[str]:
    full = os.path.join(ctx.root, rel)
    if not safety.is_within(ctx.root, full) or os.path.islink(full) or not os.path.isdir(full):
        return []
    try:
        return sorted(os.listdir(full))
    except OSError:
        return []


_TEST_DIR = re.compile(r"(?:^|/)(?:[^/]*Tests?|Tests?[^/]*|[^/]*TestHelpers?|Mocks?|[^/]*Mocks|Fixtures|Previews?"
                       r"|PreviewContent|Preview Content)/", re.IGNORECASE)


def _is_test_path(path: str) -> bool:
    """Test, mock and preview code (wider than detect.scope_of: `WikipediaUnitTests/`, `Mocks/`)."""
    return scope_of(path) in ("test", "debug") or bool(_TEST_DIR.search(path)) \
        or posixpath.basename(path).startswith(("Mock", "Fake", "Stub"))


# ---------------------------------------------------------------------------- plists


@dataclass
class PlistDoc:
    path: str
    data: Any
    lines: Dict[tuple, int]

    def line(self, *path: Any) -> int:
        return plist.line_of(self.lines, *path)


def _load_plists(ctx: Context, suffix: str, key: str) -> List[PlistDoc]:
    cache = _cache(ctx)
    if key not in cache:
        docs: List[PlistDoc] = []
        for path in ctx.files(suffix):
            raw = safety.read_bytes(ctx.root, path)
            if not raw:
                continue
            data = plist.loads(raw)
            if data is None:
                ctx.note_unknown(f"Couldn't parse {path} (invalid plist, or it declares entities).")
                continue
            lines = {} if plist.is_binary(raw) else plist.key_lines(ctx.text(path) or "")
            docs.append(PlistDoc(path, data, lines))
        cache[key] = docs
    return cache[key]


def _plists(ctx: Context) -> List[PlistDoc]:
    return _load_plists(ctx, ".plist", "plists")


def _shipping_plists(ctx: Context) -> List[PlistDoc]:
    """Plists that can end up in a release build (not referenced only by Debug configurations)."""
    debug_only = _debug_only_plists(ctx)
    return [d for d in _plists(ctx) if d.path not in debug_only]


def _ats_docs(ctx: Context) -> Iterator[Tuple[PlistDoc, Dict[str, Any]]]:
    for doc in _shipping_plists(ctx):
        ats = plist.get(doc.data, "NSAppTransportSecurity")
        if isinstance(ats, dict):
            yield doc, ats


def _plist_hit(ctx: Context, doc: PlistDoc, path: tuple, message: str) -> Hit:
    line = doc.line(*path)
    return Hit(doc.path, line, ctx.snippet(doc.path, line) if line else "", message)


_UI_APP_KEYS = ("UILaunchScreen", "UILaunchStoryboardName", "UIApplicationSceneManifest", "UIMainStoryboardFile",
                "UISupportedInterfaceOrientations", "LSRequiresIPhoneOS")
_NOT_APP_DIR = re.compile(r"(?:^|/)[^/]*(?:test|mock|harness|sample|example|demo|preview)[^/]*/", re.IGNORECASE)


def _app_plists(ctx: Context) -> List[PlistDoc]:
    """Info.plists of iOS apps (not extensions, frameworks, watch apps, tests or demos)."""
    out = []
    for doc in _shipping_plists(ctx):
        d = doc.data
        if not isinstance(d, dict) or "CFBundleIdentifier" not in d or "NSExtension" in d:
            continue
        if any(k in d for k in ("WKApplication", "WKWatchKitApp", "WKCompanionAppBundleIdentifier")):
            continue
        pkg = d.get("CFBundlePackageType")
        if isinstance(pkg, str) and pkg not in ("APPL", "$(PRODUCT_BUNDLE_PACKAGE_TYPE)"):
            continue
        if not any(k in d for k in _UI_APP_KEYS) or _NOT_APP_DIR.search(doc.path) or scope_of(doc.path) != "main":
            continue
        out.append(doc)
    return out


# ---------------------------------------------------------------------------- Xcode projects


def _projects(ctx: Context) -> List[pbxproj.Project]:
    cache = _cache(ctx)
    if "projects" not in cache:
        out = []
        for path in ctx.files(name="project.pbxproj"):
            data = pbxproj.parse(ctx.text(path))
            if data is None:
                ctx.note_unknown(f"Couldn't parse {path} (not a valid project file).")
                continue
            out.append(pbxproj.Project(data, path))
        cache["projects"] = out
    return cache["projects"]


def _schemes(ctx: Context, proj: pbxproj.Project) -> List[xcscheme.Scheme]:
    """Shared schemes (of the project, or of a workspace next to it) that archive this project's targets."""
    cache = _cache(ctx).setdefault("schemes", {})
    if proj.path not in cache:
        xcodeproj = posixpath.dirname(proj.path)
        parent = posixpath.dirname(xcodeproj)
        containers = [(xcodeproj, True)]
        containers += [(posixpath.join(parent, n) if parent else n, False)
                       for n in _listdir(ctx, parent) if n.endswith(".xcworkspace")]
        out: List[xcscheme.Scheme] = []
        for container, own in containers:
            for scheme in xcscheme.shared_schemes(ctx.root, container):
                if not scheme.archive_config:
                    continue
                ours = any(t in proj.objects for t in scheme.archive_targets)
                if ours or (own and not scheme.archive_targets):
                    out.append(scheme)
        cache[proj.path] = out
    return cache[proj.path]


def _archive_configs(ctx: Context, proj: pbxproj.Project) -> Set[str]:
    """Configurations that the project's shared schemes archive (empty: no shared schemes)."""
    return {s.archive_config for s in _schemes(ctx, proj) if s.archive_config}


def _primary_configs(ctx: Context, proj: pbxproj.Project, primary: Optional[pbxproj.Target]) -> Set[str]:
    """Shipping configurations of the main product: those archived by a scheme that builds the primary
    app target (an Alpha scheme archiving an Alpha configuration builds a different product)."""
    names = set(proj.project_configs())
    for t in proj.targets():
        names |= set(t.configs)
    shipping = {n for n in names if _is_shipping(ctx, proj, n)}
    if primary is None:
        return shipping
    own = {s.archive_config for s in _schemes(ctx, proj) if primary.id in s.archive_targets and s.archive_config}
    return (own & shipping) or shipping


def _is_shipping(ctx: Context, proj: pbxproj.Project, cfg_name: str) -> bool:
    """A configuration ships when a shared scheme archives it (or, with no shared schemes, when its
    name isn't Debug-like). Test- and Debug-named configurations never count."""
    if pbxproj.is_debug_config(cfg_name):
        return False
    archived = _archive_configs(ctx, proj)
    return not archived or cfg_name in archived


Value = Tuple[Optional[str], str, int]       # (value or None if not a string, file, line)


def _xc_layer(ctx: Context, rel: str) -> Dict[str, Value]:
    cache = _cache(ctx).setdefault("xc", {})
    if rel not in cache:
        unknowns: List[str] = []
        settings = xcconfig.resolve(ctx.root, rel, read=lambda r, p: ctx.text(p), unknowns=unknowns)
        for u in unknowns:
            ctx.note_unknown(u)
        cache[rel] = {k: (s.value, s.path, s.line) for k, s in settings.items()}
    return cache[rel]


def _pbx_layer(proj: pbxproj.Project, cfg: pbxproj.BuildConfig) -> Dict[str, Value]:
    out: Dict[str, Value] = {}
    for k, v in cfg.settings.items():
        if isinstance(v, list):
            v = " ".join(x for x in v if isinstance(x, str))
        out[k] = (v if isinstance(v, str) else None, proj.path, cfg.lines.get(k, cfg.line))
    return out


def _layers(ctx: Context, proj: pbxproj.Project, target: pbxproj.Target, cfg_name: str) -> List[Dict[str, Value]]:
    layers: List[Dict[str, Value]] = []
    for cfg in (proj.project_configs().get(cfg_name), target.configs.get(cfg_name)):
        if cfg is None:
            continue
        if cfg.base_xcconfig:
            layers.append(_xc_layer(ctx, cfg.base_xcconfig))
        layers.append(_pbx_layer(proj, cfg))
    return layers


def _effective(ctx: Context, proj: pbxproj.Project, target: pbxproj.Target,
               cfg_name: str) -> Dict[str, Value]:
    """Build settings of one target in one configuration, lowest precedence first."""
    merged: Dict[str, Value] = {}
    for layer in _layers(ctx, proj, target, cfg_name):
        for k, v in layer.items():
            if v[0] is not None and v[0].strip() == "$(inherited)" and k in merged:
                continue
            merged[k] = v
    return merged


@dataclass
class Origin:
    proj: pbxproj.Project
    target: pbxproj.Target
    cfg: str


def _release_setting_sets(ctx: Context) -> Iterator[Tuple[str, Dict[str, Value], Optional[Origin]]]:
    """(label, settings, origin) for every shipping configuration we can see.

    From each project: every non-test target in every shipping configuration (see _is_shipping).
    Plus root .xcconfig files no project references (XcodeGen/Tuist repos), unless their name
    says Debug.
    """
    referenced: Set[str] = set()
    for proj in _projects(ctx):
        configs = proj.project_configs()
        for cfg in configs.values():
            if cfg.base_xcconfig:
                referenced.add(cfg.base_xcconfig)
        demo = _demo_project(ctx, proj)
        for target in proj.targets():
            for cfg in target.configs.values():
                if cfg.base_xcconfig:
                    referenced.add(cfg.base_xcconfig)
            if target.is_test or demo:
                continue
            for name in sorted(set(target.configs) | set(configs)):
                if not _is_shipping(ctx, proj, name):
                    continue
                yield f"{target.name} ({name})", _effective(ctx, proj, target, name), Origin(proj, target, name)
    included: Set[str] = set()
    all_xc = ctx.files(".xcconfig")
    for path in all_xc:
        for inc, _opt, _line in xcconfig.parse(ctx.text(path) or "").includes:
            target_path = xcconfig.include_path(path, inc)
            if target_path:
                included.add(target_path)
    for path in all_xc:
        if path in referenced or path in included:
            continue
        stem = posixpath.splitext(posixpath.basename(path))[0]
        if pbxproj.is_debug_config(stem) or scope_of(path) in ("test", "debug"):
            continue
        yield path, _xc_layer(ctx, path), None


Check = Callable[[str, str, Dict[str, Value], Optional[Origin]], Optional[str]]


def _setting_hits(ctx: Context, check: Check, keys: Callable[[str], bool]) -> Iterator[Hit]:
    found: Dict[Tuple[str, int], List[Any]] = {}       # (path, line) -> [message, key, [labels], [origins]]
    order: List[Tuple[str, int]] = []
    for label, settings, origin in _release_setting_sets(ctx):
        for key, (value, path, line) in settings.items():
            if value is None or not keys(key):
                continue
            plain = value.replace("$(inherited)", "").replace("${inherited}", "")
            if xcconfig.is_unresolved(plain):
                ctx.note_unknown(f"{key} in {label} is set from a variable ({value}); couldn't decide.")
                continue
            message = check(key, plain, settings, origin)
            if not message:
                continue
            rec = found.get((path, line))
            if rec is None:
                rec = found[(path, line)] = [message, key, [], []]
                order.append((path, line))
            rec[2].append(label)
            rec[3].append(origin)
    for path, line in order:
        message, key, labels, origins = found[(path, line)]
        origin = origins[0]
        label = labels[0]
        if origin is not None:
            pcfg = origin.proj.project_configs().get(origin.cfg)
            if path == origin.proj.path and pcfg is not None and pcfg.lines.get(key) == line:
                n = len({o.target.name for o in origins if o is not None})
                label = f"project-level {origin.cfg}, inherited by {n} target{'s' if n != 1 else ''}"
            elif len(labels) > 1:
                label = f"{labels[0]} and {len(labels) - 1} more"
        yield Hit(path, line, ctx.snippet(path, line), f"{message} [{label}]")


def _debug_only_plists(ctx: Context) -> Set[str]:
    cache = _cache(ctx)
    if "debug_plists" not in cache:
        kinds: Dict[str, Set[bool]] = {}
        for proj in _projects(ctx):
            configs = proj.project_configs()
            for target in proj.targets():
                for name in set(target.configs) | set(configs):
                    value = _effective(ctx, proj, target, name).get("INFOPLIST_FILE", (None, "", 0))[0]
                    if not value:
                        continue
                    path = proj.settings_path(value)
                    if path is not None:
                        kinds.setdefault(path, set()).add(not _is_shipping(ctx, proj, name))
        cache["debug_plists"] = {p for p, k in kinds.items() if k == {True}}
    return cache["debug_plists"]


def _infoplist_keys(ctx: Context) -> Set[str]:
    """Info.plist keys added through INFOPLIST_KEY_<Key> build settings (generated Info.plist)."""
    cache = _cache(ctx)
    if "infoplist_keys" not in cache:
        keys: Set[str] = set()
        for _label, settings, _origin in _release_setting_sets(ctx):
            for k, (v, _p, _l) in settings.items():
                if k.startswith("INFOPLIST_KEY_") and v and v.strip():
                    keys.add(k[len("INFOPLIST_KEY_"):].split("[", 1)[0])
        cache["infoplist_keys"] = keys
    return cache["infoplist_keys"]


# ---------------------------------------------------------------------------- targets that don't ship


def _kmp_scaffold(ctx: Context, proj: pbxproj.Project) -> bool:
    """The Kotlin Multiplatform wizard's iosApp shell: two Swift files and an empty TEAM_ID."""
    src = proj.source_root
    prefix = src + "/" if src else ""
    team_unset = False
    for path in ctx.files(".xcconfig"):
        if not path.startswith(prefix):
            continue
        text = ctx.text(path) or ""
        if re.search(r"^\s*TEAM_ID\s*=\s*$", text, re.MULTILINE) and "$(TEAM_ID)" in text:
            team_unset = True
    if not team_unset:
        return False
    swift = [p for p in ctx.files(".swift") if p.startswith(prefix)]
    names = {posixpath.basename(p) for p in swift}
    return 0 < len(swift) <= 3 and names <= {"iOSApp.swift", "ContentView.swift", "App.swift"}


def _demo_project(ctx: Context, proj: pbxproj.Project) -> bool:
    """Projects that don't ship: a demo or showcase app inside a Swift package (when another
    project in the repo holds the real app), or the KMP wizard's unconfigured iosApp shell."""
    cache = _cache(ctx).setdefault("demo", {})
    if proj.path in cache:
        return cache[proj.path]
    cache[proj.path] = False            # recursion guard
    result = _kmp_scaffold(ctx, proj)
    if not result:
        files = set(ctx.project.files)
        parts = proj.source_root.split("/") if proj.source_root else []
        for i in range(len(parts), 0, -1):
            folder = "/".join(parts[:i])
            if folder + "/Package.swift" not in files:
                continue
            others = [p for p in _projects(ctx) if p is not proj
                      and not (p.source_root + "/").startswith(folder + "/")
                      and any(t.is_app for t in p.targets())]
            if others:
                result = True
                break
    cache[proj.path] = result
    return result


def _primary_app(proj: pbxproj.Project) -> Optional[pbxproj.Target]:
    apps = [t for t in proj.targets() if t.is_app]
    if not apps:
        return None
    stem = posixpath.basename(posixpath.dirname(proj.path))
    stem = stem[: -len(".xcodeproj")] if stem.endswith(".xcodeproj") else stem
    for t in apps:
        if t.name == stem:
            return t
    return max(apps, key=lambda t: len(proj.phase_files(t, "PBXSourcesBuildPhase")) + 1000 * len(t.synchronized_groups))


def _anchors(ctx: Context) -> List[Tuple[str, int, str]]:
    """Where an absence finding points: the primary app target of each shipping project, or, with no
    Xcode project (XcodeGen, Tuist), each app Info.plist. (path, line, app name)."""
    out: List[Tuple[str, int, str]] = []
    projects = [p for p in _projects(ctx) if not _demo_project(ctx, p)]
    for proj in sorted(projects, key=lambda p: (p.path.count("/"), p.path)):
        app = _primary_app(proj)
        if app is not None:
            out.append((proj.path, app.line, app.name))
            break
    if out or _projects(ctx):
        return out
    docs = _app_plists(ctx) or [d for d in _shipping_plists(ctx)
                                 if plist.get(d.data, "CFBundleIdentifier") is not None][:1]
    for doc in docs:
        name = plist.get(doc.data, "CFBundleName")
        if not isinstance(name, str) or xcconfig.is_unresolved(name):
            name = doc.path.split("/", 1)[0] if "/" in doc.path else doc.path
        out.append((doc.path, 0, name))
    return out


def _anchor_hits(ctx: Context, message: Callable[[str], str]) -> Iterator[Hit]:
    for path, line, name in _anchors(ctx):
        yield Hit(path, line, ctx.snippet(path, line) if line else "", message(name))


# ---------------------------------------------------------------------------- compilation conditions

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_COND_KEYS = ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "OTHER_SWIFT_FLAGS", "GCC_PREPROCESSOR_DEFINITIONS")


def _cond_tokens(base: str, value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    toks = value.replace('"', " ").replace("'", " ").replace("\\", " ").split()
    if base == "SWIFT_ACTIVE_COMPILATION_CONDITIONS":
        for t in toks:
            if _IDENT.fullmatch(t):
                out[t] = "1"
        return out
    if base == "OTHER_SWIFT_FLAGS":
        names = [toks[i + 1] for i, t in enumerate(toks[:-1]) if t == "-D"]
        names += [t[2:] for t in toks if t.startswith("-D") and len(t) > 2]
    else:
        names = toks
    for n in names:
        sym, _, val = n.partition("=")
        if _IDENT.fullmatch(sym):
            out[sym] = val or "1"
    return out


def _config_symbols(ctx: Context, proj: pbxproj.Project, target: pbxproj.Target, cfg_name: str) -> Dict[str, str]:
    """Compilation conditions of a target in one configuration; `$(inherited)` merges lower layers."""
    per_key: Dict[str, Dict[str, str]] = {}
    for layer in _layers(ctx, proj, target, cfg_name):
        for key, (value, _p, _l) in layer.items():
            base = key.split("[", 1)[0]
            if base not in _COND_KEYS or value is None or "sdk=iphonesimulator" in key:
                continue
            toks = _cond_tokens(base, value)
            if "$(inherited)" in value or "${inherited}" in value:
                merged = dict(per_key.get(key, {}))
                if "[" in key:
                    merged.update(per_key.get(base, {}))
                merged.update(toks)
                per_key[key] = merged
            else:
                per_key[key] = toks
    out: Dict[str, str] = {}
    for toks in per_key.values():
        out.update(toks)
    return out


@dataclass
class CondEnv:
    defined: Dict[str, str] = field(default_factory=dict)   # set by the primary app target: true
    partial: Set[str] = field(default_factory=set)          # set only by extensions or frameworks: unknown
    known: Set[str] = field(default_factory=set)            # set in some configuration of some target
    targets: Dict[str, List[str]] = field(default_factory=dict)   # symbol -> shipping targets setting it


def _cond_env(ctx: Context) -> CondEnv:
    """Which #if symbols the shipping product defines. Set by the primary app target in a configuration
    its scheme archives: true. Set only by an extension or framework that ships with it (EXTENSION):
    unknown, since both branches compile into some binary. Set only by another app target (an Alpha
    flavor) or a Debug configuration: false. Never seen in any configuration: unknown."""
    cache = _cache(ctx)
    if "cond_env" in cache:
        return cache["cond_env"]
    env = CondEnv()
    targets_of: Dict[str, Set[str]] = {}
    for proj in _projects(ctx):
        if _demo_project(ctx, proj):
            continue
        primary = _primary_app(proj)
        main_configs = _primary_configs(ctx, proj, primary)
        configs = set(proj.project_configs())
        for target in proj.targets():
            if target.is_test:
                continue
            for name in sorted(set(target.configs) | configs):
                syms = _config_symbols(ctx, proj, target, name)
                env.known.update(syms)
                if name not in main_configs:
                    continue
                for s in syms:
                    targets_of.setdefault(s, set()).add(target.name)
                if target.is_app and primary is not None and target.id != primary.id:
                    continue
                if primary is not None and target.id == primary.id:
                    env.defined.update(syms)
                else:
                    env.partial.update(syms)
    env.partial -= set(env.defined)
    env.targets = {s: sorted(t) for s, t in targets_of.items()}
    cache["cond_env"] = env
    return env


Truth = Optional[bool]


def _lookup(env: CondEnv, sym: str) -> Tuple[Truth, Optional[str]]:
    if sym in env.defined:
        return True, env.defined[sym]
    if sym in env.partial:
        return None, None
    if sym in env.known or sym == "DEBUG":
        return False, "0"
    return None, None


_COND_TOKEN = re.compile(r"\s*(\|\||&&|==|!=|>=|<=|[!()<>,]|[A-Za-z_][A-Za-z0-9_.]*|\d+(?:\.\d+)*)")


def _eval_cond(expr: str, env: CondEnv) -> Truth:
    """Three-valued evaluation of a #if condition: True, False, or None (can't tell)."""
    toks: List[str] = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = _COND_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            return None
        toks.append(m.group(1))
        pos = m.end()
        if len(toks) > 200:
            return None
    state = {"i": 0}

    def peek() -> str:
        return toks[state["i"]] if state["i"] < len(toks) else ""

    def take() -> str:
        t = peek()
        state["i"] += 1
        return t

    def ternary_and(a: Truth, b: Truth) -> Truth:
        if a is False or b is False:
            return False
        return True if a is True and b is True else None

    def ternary_or(a: Truth, b: Truth) -> Truth:
        if a is True or b is True:
            return True
        return False if a is False and b is False else None

    def p_or(depth: int) -> Truth:
        v = p_and(depth)
        while peek() == "||":
            take()
            v = ternary_or(v, p_and(depth))
        return v

    def p_and(depth: int) -> Truth:
        v = p_unary(depth)
        while peek() == "&&":
            take()
            v = ternary_and(v, p_unary(depth))
        return v

    def p_unary(depth: int) -> Truth:
        if depth > 40:
            raise ValueError("too deep")
        if peek() == "!":
            take()
            v = p_unary(depth + 1)
            return None if v is None else not v
        return p_primary(depth + 1)

    def p_primary(depth: int) -> Truth:
        t = take()
        if t == "(":
            v = p_or(depth)
            if take() != ")":
                raise ValueError("unbalanced")
            return v
        if t in ("true", "false"):
            return t == "true"
        if t and t[0].isdigit():
            return t.strip("0.") != ""
        if not t or not _IDENT.match(t):
            raise ValueError("unexpected token")
        if t == "defined":
            paren = peek() == "("
            if paren:
                take()
            name = take()
            if paren and take() != ")":
                raise ValueError("unbalanced")
            return _lookup(env, name)[0]
        if peek() == "(":                      # os(iOS), canImport(X), swift(>=5.9), targetEnvironment(...)
            take()
            args: List[str] = []
            level = 1
            while level:
                a = take()
                if not a:
                    raise ValueError("unbalanced")
                level += (a == "(") - (a == ")")
                if level:
                    args.append(a)
            if t == "targetEnvironment" and args == ["simulator"]:
                return False
            return None
        truth, value = _lookup(env, t)
        if peek() in ("==", "!=", ">=", "<=", ">", "<"):
            op = take()
            num = take()
            if not num or not num[0].isdigit():
                return None
            if truth is None:
                return None
            try:
                left = float(value) if value and value.replace(".", "", 1).isdigit() else (1.0 if truth else 0.0)
                right = float(num)
            except ValueError:
                return None
            return {"==": left == right, "!=": left != right, ">=": left >= right, "<=": left <= right,
                    ">": left > right, "<": left < right}[op]
        return truth

    try:
        v = p_or(0)
    except (ValueError, IndexError, RecursionError):
        return None
    return v if state["i"] == len(toks) else None


_PP = re.compile(r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elseif|elif|else|endif)\b([^\n]*)", re.MULTILINE)


def _directive_cond(directive: str, rest: str) -> str:
    c = rest.split("//", 1)[0].split("/*", 1)[0].strip()
    if directive == "ifdef":
        return f"defined({c})"
    if directive == "ifndef":
        return f"!defined({c})"
    return c


def _blank_inactive(code: str, env: CondEnv) -> str:
    """Blank every line of an #if branch that can't be compiled into the shipping product."""
    if "#" not in code:
        return code
    lines = code.split("\n")
    stack: List[List[bool]] = []          # [parent_dead, any_branch_true, this_dead]
    out = []
    for line in lines:
        m = _PP.match(line) if "#" in line else None
        if m:
            d = m.group(1)
            if d in ("if", "ifdef", "ifndef"):
                parent_dead = bool(stack) and stack[-1][2]
                v = _eval_cond(_directive_cond(d, m.group(2)), env)
                stack.append([parent_dead, v is True, parent_dead or v is False])
            elif d in ("elseif", "elif") and stack:
                top = stack[-1]
                v = _eval_cond(_directive_cond("if", m.group(2)), env)
                top[2] = top[0] or top[1] or v is False
                top[1] = top[1] or v is True
            elif d == "else" and stack:
                top = stack[-1]
                top[2] = top[0] or top[1]
            elif d == "endif" and stack:
                stack.pop()
            out.append(line)
            continue
        out.append(" " * len(line) if stack and stack[-1][2] else line)
    return "\n".join(out)


def _blank_debug(code: str) -> str:
    """Blank DEBUG-only code with no project information (DEBUG is assumed off in release)."""
    return _blank_inactive(code, CondEnv())


def _release_code(ctx: Context, path: str, keep_strings: bool = True) -> Optional[str]:
    """Code with comments blanked and inactive #if branches blanked. Offsets match the raw file."""
    cache = _cache(ctx).setdefault("release_code", {})
    key = (path, keep_strings)
    if key not in cache:
        code = ctx.code(path, keep_strings=keep_strings)
        cache[key] = _blank_inactive(code, _cond_env(ctx)) if code is not None else None
    return cache[key]


def _branch_variants(body: str, env: CondEnv, limit: int = 16) -> List[Tuple[str, List[str]]]:
    """The body once per combination of its top-level #if branches (other branches blanked), so a
    check can tell an #if EXTENSION trust-all branch from the #else that validates. Branches the
    shipping product can't compile are left out. Returns [(text, conditions of the chosen branches)]."""
    if "#" not in body:
        return [(body, [])]
    lines = body.split("\n")
    chains: List[List[List[Any]]] = []         # chain -> [cond, line indices, truth]
    directive_lines: Set[int] = set()
    depth = 0
    cur: Optional[List[List[Any]]] = None
    for i, line in enumerate(lines):
        m = _PP.match(line) if "#" in line else None
        if m:
            d = m.group(1)
            if d in ("if", "ifdef", "ifndef"):
                depth += 1
                if depth == 1:
                    cond = _directive_cond(d, m.group(2))
                    cur = [[cond, [], _eval_cond(cond, env)]]
                    chains.append(cur)
                    directive_lines.add(i)
                    continue
            elif d in ("elseif", "elif", "else") and depth == 1 and cur is not None:
                if d == "else":
                    cur.append(["else", [], None])
                else:
                    cond = _directive_cond("if", m.group(2))
                    cur.append([cond, [], _eval_cond(cond, env)])
                directive_lines.add(i)
                continue
            elif d == "endif":
                if depth == 1 and cur is not None:
                    directive_lines.add(i)
                    if all(b[0] != "else" for b in cur):
                        cur.append(["else", [], None])
                    cur = None
                    depth = 0
                    continue
                depth = max(0, depth - 1)
        if depth >= 1 and cur is not None:
            cur[-1][1].append(i)
    if cur is not None or not chains:
        return [(body, [])]
    options: List[List[int]] = []
    for chain in chains:
        live: List[int] = []
        earlier_true = False
        for bi, (_cond, _idx, truth) in enumerate(chain):
            if not earlier_true and truth is not False:
                live.append(bi)
            earlier_true = earlier_true or truth is True
        options.append(live or [len(chain) - 1])
    total = 1
    for o in options:
        total *= len(o)
    if total > limit:
        return [(body, [])]
    variants = []
    for choice in itertools.product(*options):
        blank = set(directive_lines)
        conds: List[str] = []
        for chain, k in zip(chains, choice):
            for bi, branch in enumerate(chain):
                if bi != k:
                    blank.update(branch[1])
            if chain[k][0] != "else":
                conds.append(chain[k][0])
        text = "\n".join(" " * len(ln) if i in blank else ln for i, ln in enumerate(lines))
        variants.append((text, conds))
    return variants


def _variant_note(env: CondEnv, conds: List[str]) -> str:
    """' (compiled when EXTENSION is set: Share, Widget)' for branches only some targets compile."""
    notes = []
    for cond in conds:
        for sym in _IDENT.findall(cond):
            if sym in env.partial and env.targets.get(sym):
                names = env.targets[sym]
                shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
                notes.append(f"the #if {sym} branch, compiled into {shown}")
    return f" (In {'; '.join(dict.fromkeys(notes))}.)" if notes else ""


def _body(code: str, start: int, max_gap: int = 800) -> Optional[Tuple[int, int]]:
    """Span of the brace-balanced block that starts after `start` (code must have strings blanked)."""
    i = code.find("{", start)
    if i == -1 or i - start > max_gap:
        return None
    j = bracket_match(code, i, "{", "}")        # the same depth count, answered from a cached pairing
    return (i, j + 1) if j < len(code) else None


def _paren_end(code: str, open_idx: int, limit: int = 2000) -> int:
    """Index just past the parenthesis or bracket that closes the one at open_idx (or -1)."""
    pairs = {"(": ")", "[": "]"}
    opener = code[open_idx]
    closer = pairs.get(opener)
    if closer is None:
        return -1
    depth = 0
    for j in range(open_idx, min(len(code), open_idx + limit)):
        ch = code[j]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return j + 1
    return -1


_FUNC_START = re.compile(r"\bfunc\s+\w+|^\s*[-+]\s*\(", re.MULTILINE)


def _enclosing_function(code: str, index: int) -> Tuple[int, int]:
    """Best-effort span of the function around `index` (from the last `func` before it)."""
    start = 0
    for m in _FUNC_START.finditer(code, 0, index):
        start = m.start()
    span = _body(code, start, max_gap=4000)
    if span and span[0] <= index <= span[1]:
        return start, span[1]
    return max(0, index - 1500), min(len(code), index + 1500)


def _functions(ctx: Context, signature: "re.Pattern[str]", files: Optional[List[str]] = None,
               literals: Tuple[str, ...] = ()) -> Iterator[Tuple[str, int, str, str, "re.Match[str]", int]]:
    """(path, line, body, whole_file, match, body_start) for each function whose signature matches,
    in shipping code (strings blanked). `literals`: cheap substrings a matching file must contain."""
    for path in files if files is not None else ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or (literals and not any(lit in raw for lit in literals)) or not signature.search(raw):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if code is None:
            continue
        for m in signature.finditer(code):
            span = _body(code, m.end())
            if span is None:
                continue
            yield path, ctx.line_of(code, m.start()), code[span[0]:span[1]], code, m, span[0]


def _code_hits(ctx: Context, regex: "re.Pattern[str]", prefilter: str, message: str,
               keep_strings: bool = False) -> Iterator[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or prefilter not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=keep_strings)
        if code is None:
            continue
        for m in regex.finditer(code):
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line), message)


def _search_code(ctx: Context, regex: "re.Pattern[str]", suffixes: Tuple[str, ...] = CODE_SUFFIXES,
                 keep_strings: bool = False, include_tests: bool = True,
                 literals: Tuple[str, ...] = ()) -> bool:
    """True if any code file matches. `literals`: cheap substrings, one of which a match must contain."""
    for path in ctx.files(*suffixes):
        if not include_tests and _is_test_path(path):
            continue
        if literals and not holds_any(ctx, path, literals):
            continue
        code = ctx.code(path, keep_strings=keep_strings)
        if code and regex.search(code):
            return True
    return False


def _deps_text(ctx: Context) -> str:
    """Podfile, Cartfile, Package.swift and pubspec.yaml contents, comments removed."""
    cache = _cache(ctx)
    if "deps" not in cache:
        parts = []
        for name in ("Podfile", "Cartfile", "Package.swift", "pubspec.yaml"):
            for path in ctx.files(name=name):
                text = ctx.code(path) or ""
                if name != "Package.swift":
                    text = re.sub(r"#[^\n]*", "", text)
                parts.append(text)
        cache["deps"] = "\n".join(parts)
    return cache["deps"]


# ============================================================================ network


def _is_local(domain: str) -> bool:
    d = domain.strip().lower()
    return d in LOCAL_HOSTS or d.endswith((".local", ".localhost", ".test"))


def _is_onion(domain: str) -> bool:
    d = domain.strip().lower().lstrip("*.")
    return d == "onion" or d.endswith(".onion")


_ATS_KEY = re.compile(
    r"^INFOPLIST_KEY_(?:NSAppTransportSecurity_)?(NSAllowsArbitraryLoads|NSAllowsArbitraryLoadsInWebContent)$"
)


@detector("ios_ats_arbitrary_loads")
def ats_arbitrary_loads(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        web = plist.truthy(ats.get("NSAllowsArbitraryLoadsInWebContent"))
        # On iOS 10+, NSAllowsArbitraryLoads is ignored when any of the narrower keys is present.
        overridden = any(k in ats for k in ("NSAllowsArbitraryLoadsInWebContent",
                                            "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"))
        if plist.truthy(ats.get("NSAllowsArbitraryLoads")) and not overridden:
            yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSAllowsArbitraryLoads"),
                             "NSAllowsArbitraryLoads turns off App Transport Security for every host.")
        if web:
            yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSAllowsArbitraryLoadsInWebContent"),
                             "NSAllowsArbitraryLoadsInWebContent lets every web view load plain HTTP.")

    def check(key: str, value: str, settings: Dict[str, Value], _o: Optional[Origin]) -> Optional[str]:
        generated = settings.get("GENERATE_INFOPLIST_FILE", (None, "", 0))[0]
        if not xcconfig.is_yes(value) or not xcconfig.is_yes(generated):
            return None
        return f"Build setting {key} = YES adds an ATS exception to the generated Info.plist."

    yield from _setting_hits(ctx, check, lambda k: bool(_ATS_KEY.match(k)))


def _anchor_pinned_code(ctx: Context) -> bool:
    """Code installs its own trust anchors (custom CA pinned in code)."""
    cache = _cache(ctx)
    if "anchor_pinned" not in cache:
        cache["anchor_pinned"] = _search_code(ctx, re.compile(r"SecTrustSetAnchorCertificates(?:Only)?\b"),
                                              literals=("SecTrustSetAnchorCertificates",))
    return cache["anchor_pinned"]


@detector("ios_ats_exception_http")
def ats_exception_http(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        domains = ats.get("NSExceptionDomains")
        if not isinstance(domains, dict):
            continue
        for domain, conf in domains.items():
            # Onion services are encrypted and authenticated end to end by the onion address itself.
            if not isinstance(conf, dict) or _is_local(domain) or _is_onion(domain):
                continue
            for key in ("NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads"):
                if plist.truthy(conf.get(key)):
                    sub = " and its subdomains" if plist.truthy(conf.get("NSIncludesSubdomains")) else ""
                    note = ""
                    if _anchor_pinned_code(ctx):
                        note = (" The app sets its own trust anchors in code (SecTrustSetAnchorCertificates); if "
                                "that is why this exception exists, confirm every request to this host is HTTPS.")
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSExceptionDomains", domain, key),
                                     f"Plain HTTP is allowed for {domain}{sub}.{note}")


_WEAK_TLS = {"TLSV1.0", "TLSV1.1"}
_WEAK_TLS_CODE = re.compile(
    r"\b(?:tlsMinimumSupportedProtocolVersion|TLSMinimumSupportedProtocol)\s*=\s*[\w.]*?"
    r"(?:TLSv10|TLSv11|tlsProtocol1|tlsProtocol11|kTLSProtocol1|kTLSProtocol11)\b"
)


@detector("ios_weak_tls")
def weak_tls(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        domains = ats.get("NSExceptionDomains")
        if not isinstance(domains, dict):
            continue
        for domain, conf in domains.items():
            if not isinstance(conf, dict):
                continue
            for key in ("NSExceptionMinimumTLSVersion", "NSTemporaryExceptionMinimumTLSVersion"):
                value = conf.get(key)
                if isinstance(value, str) and value.strip().upper() in _WEAK_TLS:
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSExceptionDomains", domain, key),
                                     f"{domain} accepts {value.strip()}, below the TLS 1.2 floor ATS enforces.")
    yield from _code_hits(ctx, _WEAK_TLS_CODE, "TLS",
                          "The session accepts TLS 1.0 or 1.1, below the TLS 1.2 floor ATS enforces.")


_NW_WEAK_TLS = re.compile(
    r"\bsec_protocol_options_set_(?:min|max)_tls_protocol_version\s*\([^;\n]{0,200}?"
    r"(?:\.TLSv1[01]\b|tls_protocol_version_TLSv1[01]\b|\.DTLSv10\b|tls_protocol_version_DTLSv10\b)"
    r"|\bSSLSetProtocolVersion(?:Min|Max)\s*\([^;\n]{0,160}?\b(?:kTLSProtocol1|kTLSProtocol11|kSSLProtocol3|kSSLProtocol2|kDTLSProtocol1)\b"
)


@detector("ios_network_framework_tls")
def network_framework_tls(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _code_hits(ctx, _NW_WEAK_TLS, "Protocol",
                          "This connection accepts TLS 1.0 or 1.1. Network.framework and Secure Transport "
                          "connections are outside ATS, so nothing else raises the floor.")


# ---------------------------------------------------------------------------- trust and pinning

_CHALLENGE = re.compile(
    r"didReceive\s+challenge\s*:\s*URLAuthenticationChallenge"
    r"|didReceive(?:Authentication)?Challenge\s*:\s*\(\s*NSURLAuthenticationChallenge"
)
_TRUST_CREDENTIAL = re.compile(r"URLCredential\s*(?:\.init)?\s*\(\s*trust\s*:|credentialForTrust\s*:|initWithTrust\s*:")
_USE_CREDENTIAL = re.compile(r"\.useCredential\b|NSURLSessionAuthChallengeUseCredential")
_EVALUATES = re.compile(r"SecTrustEvaluate\w*|TSKPinningValidator|\bevaluate\s*\(")
_REJECTS = re.compile(r"[cC]ancelAuthenticationChallenge|[rR]ejectProtectionSpace")
# Words that only pinning code uses. Chain-access APIs alone (SecTrustCopyCertificateChain,
# SecCertificateCopyData) also serve trust-on-first-use dialogs, so they need a constant to compare with.
_STRONG_PIN = re.compile(r"(?i:\bpin(?:s|ned\w*|set|ning\w*)?\b)|\bspki\w*|SPKI\w*|\bpublicKeyHash\w*")
_CHAIN_API = re.compile(r"SecTrustCopyCertificateChain|SecTrustGetCertificateAtIndex|SecCertificateCopyKey"
                        r"|SecTrustCopyPublicKey|SecTrustCopyKey")
_PIN_CONST = re.compile(r"\bforResource\s*:|\bSHA256\b|\bsha256\b|CC_SHA256|\bSHA256Digest\b")
_DEFAULT_HANDLING = re.compile(r"\.performDefaultHandling\b|NSURLSessionAuthChallengePerformDefaultHandling")


def _pin_markers(body: str) -> bool:
    return bool(_STRONG_PIN.search(body) or (_CHAIN_API.search(body) and _PIN_CONST.search(body)))


@detector("ios_trust_all")
def trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    env = _cond_env(ctx)
    for path, line, body, _code, _m, _s in _functions(ctx, _CHALLENGE):
        for text, conds in _branch_variants(body, env):
            if not (_TRUST_CREDENTIAL.search(text) and _USE_CREDENTIAL.search(text)):
                continue
            if _EVALUATES.search(text) or _REJECTS.search(text):
                continue
            if _pin_markers(text):
                msg = ("This handler compares pins but never validates the chain (no SecTrustEvaluateWithError), "
                       "so an expired or self-signed certificate carrying a pinned key is accepted.")
            else:
                msg = "This handler returns .useCredential for any server trust without evaluating it."
            yield Hit(path, line, ctx.snippet(path, line), msg + _variant_note(env, conds))
            break


@detector("ios_pin_fallback")
def pin_fallback(ctx: Context, rule: Rule) -> Iterable[Hit]:
    env = _cond_env(ctx)
    for path, line, body, _code, _m, _s in _functions(ctx, _CHALLENGE):
        for text, conds in _branch_variants(body, env):
            if not (_pin_markers(text) and _DEFAULT_HANDLING.search(text)) or _REJECTS.search(text):
                continue
            yield Hit(path, line, ctx.snippet(path, line),
                      "This pinning handler never cancels the challenge: when no pin matches it falls back to "
                      ".performDefaultHandling, which accepts any publicly trusted certificate."
                      + _variant_note(env, conds))
            break


@detector("ios_pins_no_backup")
def pins_no_backup(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, ats in _ats_docs(ctx):
        pinned = ats.get("NSPinnedDomains")
        if not isinstance(pinned, dict):
            continue
        for domain, conf in pinned.items():
            if not isinstance(conf, dict):
                continue
            for key in ("NSPinnedCAIdentities", "NSPinnedLeafIdentities"):
                ids = conf.get(key)
                if isinstance(ids, list) and len(ids) < 2:
                    yield _plist_hit(ctx, doc, ("NSAppTransportSecurity", "NSPinnedDomains", domain, key),
                                     f"{domain} has {len(ids)} pin under {key}: no backup pin.")


_PIN_EVIDENCE_CODE = re.compile(
    r"\bTrustKit\b|TSKPinningValidator|kTSKPinnedDomains|PinnedCertificatesTrustEvaluator"
    r"|PublicKeysTrustEvaluator|\bCertificatePinner\b|WultraSSLPinning|SecTrustSetAnchorCertificates(?:Only)?\b"
    r"|\bpinnedCertificates\b|\bpinnedPublicKeys\b|\bspkiHashes\b"
)
# A literal from each _PIN_EVIDENCE_CODE alternative ("TSKPinn" for both TSK names, "TrustEvaluator" for both
# evaluators).
_PIN_EVIDENCE_NEEDLES = ("TrustKit", "TSKPinn", "TrustEvaluator", "CertificatePinner", "WultraSSLPinning",
                         "SecTrustSetAnchorCertificates", "pinnedCertificates", "pinnedPublicKeys", "spkiHashes")
_PIN_EVIDENCE_DEPS = re.compile(r"TrustKit|ssl-pinning-ios|WultraSSLPinning", re.IGNORECASE)


def _native_pinning_evidence(ctx: Context, code_files: List[str]) -> bool:
    for _doc, ats in _ats_docs(ctx):
        if isinstance(ats.get("NSPinnedDomains"), dict) and ats["NSPinnedDomains"]:
            return True
    for path in code_files + [p for p in ctx.files(".kt") if re.search(r"/(ios|apple|darwin)Main/", "/" + p)]:
        if not holds_any(ctx, path, _PIN_EVIDENCE_NEEDLES):
            continue
        code = ctx.code(path, keep_strings=False)
        if code and _PIN_EVIDENCE_CODE.search(code):
            return True
    for _path, _line, body, _code, _m, _s in _functions(ctx, _CHALLENGE, code_files):
        if _pin_markers(body) and not _is_test_path(_path):
            return True
    for name in ("Podfile", "Package.swift", "Cartfile"):
        for path in ctx.files(name=name):
            text = ctx.code(path) or ""
            if name != "Package.swift":        # Ruby-style comments in Podfile and Cartfile
                text = re.sub(r"#[^\n]*", "", text)
            if _PIN_EVIDENCE_DEPS.search(text):
                return True
    return False


@detector("ios_pinning_missing")
def pinning_missing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    is_flutter = flutter.is_flutter(ctx)
    if not is_flutter and ctx.files(name="package.json"):
        ctx.note_unknown("React Native project: iOS pinning may live in JavaScript; IOS pinning check skipped.")
        return
    code_files = ctx.files(*CODE_SUFFIXES)
    if not code_files:
        return
    if is_flutter and flutter.dart_pinning_evidence(ctx):
        return
    if _native_pinning_evidence(ctx, code_files):
        if is_flutter and not flutter.uses_native_http(ctx):
            ctx.note_unknown("iOS pinning is configured natively, but Flutter's Dart HttpClient has its own "
                             "TLS stack and ignores it; confirm the Dart side pins too.")
        return
    missing = "no NSPinnedDomains, TrustKit, or pin-checking URLSession delegate"
    if is_flutter:
        missing = "no NSPinnedDomains, TrustKit, pin-checking URLSession delegate, or Dart-side pinning"
    yield from _anchor_hits(ctx, lambda name: f"No certificate pinning found for app {name}: {missing}.")


# ============================================================================ WebViews


_INSPECTABLE = re.compile(r"\bisInspectable\s*=\s*true\b|\binspectable\s*=\s*YES\b|\bsetInspectable\s*:\s*YES\b")


@detector("ios_webview_inspectable")
def webview_inspectable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _code_hits(ctx, _INSPECTABLE, "nspectable",
                          "Web inspection is switched on in code that also compiles into release builds.")


_MESSAGE_HANDLER = re.compile(
    r"didReceive\s+(\w+)\s*:\s*WKScriptMessage\b|didReceiveScriptMessage\s*:\s*\(\s*WKScriptMessage\s*\*\s*\)\s*(\w+)"
)
_FRAMEINFO_ANY = re.compile(r"\.\s*frameInfo\b|\bframeInfo\s*\]|\[\s*\w+\s+frameInfo\s*\]")


# A handler that only maps the message to a typed action for its delegate, and touches nothing sensitive.
_DELEGATE_ACTION = re.compile(r"\bdelegate\s*[?!]?\s*\.\s*\w+\s*\(\s*action\s*:")
_HANDLER_SINK = re.compile(r"(?i)URLSession|NextcloudKit|download|upload|keychain|token|password|credential|cookie|"
                           r"FileManager|\.write\s*\(|evaluateJavaScript|callAsyncJavaScript|\.open\s*\(|openURL|"
                           r"\bsend\s*\(|\bpost\w*\s*\(|request|account|session")


@detector("ios_message_handler_origin")
def message_handler_origin(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, line, body, code, m, start in _functions(ctx, _MESSAGE_HANDLER):
        param = m.group(1) or m.group(2)
        if not param or param == "_":
            continue
        p = re.escape(param)
        direct = re.compile(rf"\b{p}\s*\.\s*frameInfo\b|\[\s*{p}\s+frameInfo\s*\]"
                            r"|\.\s*frameInfo\s*\.\s*(?:isMainFrame|securityOrigin|request)\b")
        if direct.search(body):
            continue
        inner = body[1:-1].strip()
        # A trampoline that only forwards the message: the real handler is reported on its own.
        if re.fullmatch(rf"(?:return\s+)?(?:(?:self|[\w]+)[?!]?\s*\.\s*)*userContentController\s*\("
                        rf"[^()]{{0,200}}didReceive\s*:\s*{p}\s*(?:,[^()]{{0,200}})?\)\s*;?", inner):
            continue
        # Passed to a helper in this file that reads frameInfo.
        passes = re.search(rf"[(,]\s*(?:\w+\s*:\s*)?{p}\s*[,)]", body)
        rest = code[:start] + code[start + len(body):]
        if passes and _FRAMEINFO_ANY.search(rest):
            continue
        msg = (f"This script message handler never checks {param}.frameInfo (main frame and securityOrigin), "
               "so any page or iframe in the web view can call it.")
        severity = ""
        if _DELEGATE_ACTION.search(body) and not _HANDLER_SINK.search(body):
            severity = "medium"
            msg += (" It only turns the message into a typed action for its delegate (navigation and UI), "
                    "with no network, file, or credential access here.")
        yield Hit(path, line, ctx.snippet(path, line), msg, severity=severity)


_KVC_FILE_ACCESS = re.compile(
    r"\bsetValue\s*\(\s*(?:true|1|NSNumber\s*\(\s*value\s*:\s*(?:true|1)\s*\)|kCFBooleanTrue)\s*,\s*forKey\s*:\s*"
    r"\"(allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)\""
    r"|\bsetValue\s*:\s*(?:@YES|@\(\s*YES\s*\)|@1|@true|\[\s*NSNumber\s+numberWithBool\s*:\s*YES\s*\])\s+forKey\s*:\s*"
    r"@\"(allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)\""
)


@detector("ios_webview_file_access_kvc")
def webview_file_access_kvc(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "FromFileURLs" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=True)
        for m in _KVC_FILE_ACCESS.finditer(code or ""):
            key = m.group(1) or m.group(2)
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      f"The private WebKit preference {key} is switched on through key-value coding, so a "
                      "file:// page can read other local files" + (" and any web origin." if "Universal" in key
                                                                  else "."))


_LOAD_FILE_URL = re.compile(
    r"\bloadFileURL\s*\(\s*[^,;\n]{1,200}?,\s*allowingReadAccessTo\s*:\s*([^\n;]{1,200})"
    r"|\bloadFileURL\s*:\s*[^\]\n]{1,200}?\ballowingReadAccessToURL\s*:\s*([^\]\n]{1,200})\]"
)
_BROAD_DIR = re.compile(
    r"\b(?:documentDirectory|documentsDirectory|libraryDirectory|applicationSupportDirectory|cachesDirectory"
    r"|NSDocumentDirectory|NSLibraryDirectory|NSApplicationSupportDirectory|NSCachesDirectory|homeDirectory"
    r"|temporaryDirectory)\b|\bNSHomeDirectory\s*\(|\bNSTemporaryDirectory\s*\(|fileURLWithPath\s*:\s*@?\"/\""
)
_NARROWED = re.compile(r"appending(?:PathComponent)?\s*\(|URLByAppendingPathComponent|appendingPathComponent")


def _broad_expr(expr: str) -> bool:
    return bool(_BROAD_DIR.search(expr)) and not _NARROWED.search(expr)


@detector("ios_webview_broad_file_access")
def webview_broad_file_access(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "allowingReadAccessTo" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        for m in _LOAD_FILE_URL.finditer(code):
            arg = (m.group(1) or m.group(2) or "").strip()
            close = _paren_balance_cut(arg)
            broad = _broad_expr(close)
            if not broad:
                ident = re.match(r"(?:self\s*\.\s*)?([A-Za-z_]\w*)\s*$", close)
                if ident:
                    fstart, _fend = _enclosing_function(code, m.start())
                    before = code[fstart:m.start()]
                    for a in re.finditer(rf"\b{re.escape(ident.group(1))}\s*(?::\s*[\w.?!]+\s*)?=\s*([^\n;]+)", before):
                        broad = _broad_expr(a.group(1))
            if broad:
                line = ctx.line_of(code, m.start())
                yield Hit(path, line, ctx.snippet(path, line),
                          "The web view may read every file in an app container folder, not only the folder "
                          "that holds the page.")


def _paren_balance_cut(arg: str) -> str:
    """Cut an argument at the parenthesis that closes the call it belongs to."""
    depth = 0
    for i, ch in enumerate(arg):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            if depth == 0:
                return arg[:i].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return arg[:i].strip()
    return arg.strip()


_DEEPLINK_HANDLER = re.compile(
    r"\bfunc\s+application\s*\([^)]{0,200}?\bopen\s+(\w+)\s*:\s*URL\b"
    r"|\bfunc\s+scene\s*\([^)]{0,200}?\bopenURLContexts\s+(\w+)\s*:"
    r"|\bfunc\s+application\s*\([^)]{0,200}?\bcontinue\s+(\w+)\s*:\s*NSUserActivity"
    r"|\bfunc\s+scene\s*\([^)]{0,200}?\bcontinue\s+(\w+)\s*:\s*NSUserActivity"
    r"|\.onOpenURL\s*(?:\(\s*perform\s*:\s*)?(?=\{\s*(\w+)\s+in)"
)
_WEB_LOAD = re.compile(r"\.load\s*\(\s*(?:URLRequest\s*\(\s*url\s*:|request\s*\()|\bloadFileURL\s*\(|\bloadHTMLString\s*\(")
_HOST_ALLOWLIST = re.compile(r"\.host\s*(?:==|!=)\s*\"|\"\s*(?:==|!=)\s*\w+\s*\.host\b|allowed\w*\s*\.contains\s*\("
                             r"|\.contains\s*\(\s*\w+\s*\.host\b|switch\s+[\w.?]+\.host\b|trusted\w*Host")
_CALL_WITH = r"\b(\w+)\s*\(\s*(?:\w+\s*:\s*)?{v}\b"


def _taint(body: str, seeds: Set[str]) -> Set[str]:
    """The seed names plus local constants derived from them (three rounds of `let x = f(seed)`)."""
    names = set(seeds)
    for _ in range(3):
        for a in re.finditer(r"\b(?:let|var)\s+(\w+)\s*(?::\s*[\w.?!<>\[\]]+\s*)?=\s*([^\n{;]+)", body):
            if a.group(1) not in names and any(re.search(rf"\b{re.escape(n)}\b", a.group(2)) for n in names):
                names.add(a.group(1))
    return names


def _tainted_load(body: str, seeds: Set[str]) -> Optional[int]:
    """Offset of a web view load whose arguments derive from the seed names, if any."""
    names = _taint(body, seeds)
    for m in _WEB_LOAD.finditer(body):
        end = _paren_end(body, body.find("(", m.start()))
        args = body[m.start():end if end != -1 else m.end() + 200]
        if any(re.search(rf"\b{re.escape(n)}\b", args) for n in names):
            return m.start()
    return None


@detector("ios_deeplink_webview")
def deeplink_webview(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, line, body, code, m, start in _functions(ctx, _DEEPLINK_HANDLER,
                                                       literals=("UIApplication", "UIScene", "onOpenURL")):
        param = next((g for g in m.groups() if g), None)
        if not param or param == "_":
            continue
        if _HOST_ALLOWLIST.search(body):
            continue
        seeds = {param}
        offset = _tainted_load(body, seeds)
        where = (start, body)
        if offset is None:
            # One level into helpers defined in this file that receive the URL.
            names = "|".join(re.escape(n) for n in sorted(_taint(body, seeds)))
            for call in re.finditer(_CALL_WITH.format(v=f"(?:{names})"), body):
                fn = call.group(1)
                for f in re.finditer(rf"\bfunc\s+{re.escape(fn)}\s*\(\s*(?:\w+\s+)?(\w+)\s*:", code):
                    span = _body(code, f.end())
                    if span is None:
                        continue
                    hbody = code[span[0]:span[1]]
                    if _HOST_ALLOWLIST.search(hbody):
                        continue
                    off = _tainted_load(hbody, {f.group(1)})
                    if off is not None:
                        offset, where = off, (span[0], hbody)
                        break
                if offset is not None:
                    break
        if offset is None:
            continue
        hit_line = ctx.line_of(code, where[0] + offset)
        yield Hit(path, hit_line, ctx.snippet(path, hit_line),
                  f"A URL that arrives through a deep link or universal link (handler at line {line}) is loaded "
                  "into a web view with no exact host allowlist.")


# ============================================================================ deep links


_SDK_SCHEMES = re.compile(r"^(?:com\.googleusercontent\.apps\.|fb\d|msauth\.)", re.IGNORECASE)
_AUTH_WORDS = re.compile(
    r"(?:^|[/._?&=#-])(?:oauth2?|callback|redirect|auth|authori[sz]e|login|signin|sign-in|sso)(?=$|[/._?&=#-])",
    re.IGNORECASE)
_NON_AUTH_CTX = re.compile(r"checkout|billing|payment|3ds|threeDS|paypal|stripe|donat", re.IGNORECASE)
_AUTH_CTX = re.compile(r"oauth|authorize|\bsso\b|login|signIn|sign_in", re.IGNORECASE)
_SCHEME_LITERAL = re.compile(r'"([A-Za-z][A-Za-z0-9+.\-]*)://([^"\s]*)"')
_ASWEB = re.compile(r"ASWebAuthenticationSession\s*\(")
_CALLBACK_SCHEME = re.compile(r"callbackURLScheme\s*:\s*(?!nil\b)([^\s,)][^,)\n]*)"
                              r"|callback\s*:\s*\.customScheme\s*\(\s*([^)\n]*)\)")
_HTTPS_CALLBACK = re.compile(r"callback\s*:\s*\.https\s*\(")
_COOKIE_SYNC_CTX = re.compile(r"(?i)cookie|sync\w*with\w*browser|browser\w*sync")
_CODE_FLOW_CTX = re.compile(r"(?i)oauth|authorize|code_challenge|codeVerifier|\bsso\b|login|signIn|sign_in|token")
# flutter_web_auth / flutter_web_auth_2: ASWebAuthenticationSession on iOS.
_FLUTTER_WEB_AUTH = re.compile(r"\bFlutterWebAuth2?\s*\.\s*authenticate\s*\(")


def _flutter_web_auth_files(ctx: Context) -> Iterator[Tuple[str, str]]:
    for path in ctx.files(".dart"):
        raw = ctx.text(path)
        if raw is None or "FlutterWebAuth" not in raw or _is_test_path(path) or path.endswith("_test.dart"):
            continue
        code = ctx.code(path, keep_strings=True)
        if code:
            yield path, code
_AVAILABLE_174 = re.compile(r"#available\s*\(\s*iOS\s+17\.4\b")


def _url_schemes(ctx: Context) -> Set[str]:
    schemes: Set[str] = set()
    for doc in _shipping_plists(ctx):
        types = plist.get(doc.data, "CFBundleURLTypes")
        if not isinstance(types, list):
            continue
        for t in types:
            for s in (plist.get(t, "CFBundleURLSchemes") or []):
                if not isinstance(s, str):
                    continue
                if xcconfig.is_unresolved(s):
                    ctx.note_unknown(f"URL scheme {s} in {doc.path} comes from a build variable.")
                    continue
                schemes.add(s.lower())
    return schemes


def _unreachable_else_spans(code: str) -> List[Tuple[int, int]]:
    """`else` blocks of `if #available(iOS 17.4, *)`: the custom-scheme fallback there never runs on
    an OS that has the https callback, and is reported once through the main branch instead."""
    spans = []
    for m in _AVAILABLE_174.finditer(code):
        body = _body(code, m.end(), max_gap=200)
        if body is None:
            continue
        rest = re.match(r"\s*else\s*\{", code[body[1]:body[1] + 200])
        if rest:
            span = _body(code, body[1])
            if span:
                spans.append(span)
    return spans


def _resolve_scheme(expr: str, code_by_path: Dict[str, str], schemes: Set[str]) -> Optional[str]:
    """The registered scheme an ASWebAuthenticationSession callback expression names, if we can tell."""
    expr = expr.strip()
    lit = re.fullmatch(r'"([A-Za-z][A-Za-z0-9+.\-]*)"', expr)
    if lit:
        return lit.group(1).lower()
    name = re.search(r"(\w+)\s*$", expr)
    if not name:
        return None
    rx = re.compile(rf"\b{re.escape(name.group(1))}\s*(?::\s*String\s*)?=\s*\"([A-Za-z][A-Za-z0-9+.\-]*)\"")
    for code in code_by_path.values():
        for d in rx.finditer(code):
            if d.group(1).lower() in schemes:
                return d.group(1).lower()
    return None


@detector("ios_custom_scheme_auth")
def custom_scheme_auth(ctx: Context, rule: Rule) -> Iterable[Hit]:
    schemes = {s for s in _url_schemes(ctx) if not _SDK_SCHEMES.match(s)}
    files: Dict[str, str] = {}
    for path in ctx.files(*CODE_SUFFIXES):
        if _is_test_path(path):
            continue
        raw = ctx.text(path)
        if raw is None or ("://" not in raw and "ASWebAuthenticationSession" not in raw
                           and "callbackURLScheme" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is not None:
            files[path] = code
    groups: Dict[Any, List[Tuple[int, str, int, str]]] = {}     # key -> [(rank, path, line, message)]
    order: List[Any] = []
    low: Set[Tuple[str, int]] = set()

    def add(key: Any, rank: int, path: str, line: int, message: str) -> None:
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((rank, path, line, message))

    for path, code in files.items():
        seen_lines: Set[int] = set()
        dead = _unreachable_else_spans(code)
        https_here = bool(_HTTPS_CALLBACK.search(code))
        for m in _ASWEB.finditer(code):
            close = _paren_end(code, m.end() - 1, limit=1200)
            window = code[m.end():close if close != -1 else m.end() + 600]
            c = _CALLBACK_SCHEME.search(window)
            if not c:
                continue
            at = m.end() + c.start()
            if any(s <= at < e for s, e in dead):
                continue
            fstart, _fend = _enclosing_function(code, m.start())
            fhead = code[fstart:min(len(code), fstart + 200)].split("{", 1)[0]
            _fend = max(_fend, close if close != -1 else m.end())
            url_arg = re.search(r"url\s*:\s*([^,)\n]+)", window)
            context = " ".join([fhead, url_arg.group(1) if url_arg else "", c.group(0), path])
            if _NON_AUTH_CTX.search(context) and not _AUTH_CTX.search(context):
                continue
            line = ctx.line_of(code, at)
            seen_lines.add(line)
            scheme = _resolve_scheme(c.group(1) or c.group(2) or "", files, schemes)
            if https_here:
                msg = ("The web sign-in session still returns through a custom URL scheme as the fallback for "
                       "iOS before 17.4; any app can register that scheme.")
            else:
                msg = "The sign-in session returns through a custom URL scheme, which isn't tied to your app."
            # A session that only shares Safari cookies (a browser sync) returns no authorization code.
            surround = code[max(0, fstart - 600):_fend]
            if _COOKIE_SYNC_CTX.search(surround) and not _CODE_FLOW_CTX.search(surround):
                msg += (" This session looks like a browser cookie sync rather than an OAuth code callback, so "
                        "less rides on the redirect.")
                low.add((path, line))
            add(scheme or ("asweb", path, line), 0, path, line, msg)
        for m in _SCHEME_LITERAL.finditer(code):
            scheme, rest = m.group(1).lower(), m.group(2)
            if scheme not in schemes or not _AUTH_WORDS.search(rest) or _NON_AUTH_CTX.search(rest):
                continue
            line = ctx.line_of(code, m.start())
            if line in seen_lines or any(s <= m.start() < e for s, e in dead):
                continue
            seen_lines.add(line)
            add(scheme, 1, path, line,
                f"Auth redirect {scheme}://{rest} uses a custom URL scheme registered in CFBundleURLTypes.")
    for path, code in _flutter_web_auth_files(ctx):
        for m in _FLUTTER_WEB_AUTH.finditer(code):
            close = _paren_end(code, m.end() - 1, limit=1200)
            args = code[m.end():close if close != -1 else m.end() + 600]
            c = re.search(r"\bcallbackUrlScheme\s*:\s*([^,)\n]+)", args)
            if not c or re.search(r"\bhttpsHost\s*:", args):
                continue
            expr = c.group(1).strip()
            lit = re.fullmatch(r"['\"]([^'\"]*)['\"]", expr)
            if not lit:
                name = re.search(r"(\w+)\s*$", expr)
                d = name and re.search(r"\b" + re.escape(name.group(1)) + r"\s*=\s*['\"]([^'\"]*)['\"]", code)
                lit = d or None
            scheme = lit.group(1).lower() if lit else None
            if scheme == "https":
                continue
            line = ctx.line_of(code, m.start())
            add(scheme or ("flutter", path, line), 0, path, line,
                "FlutterWebAuth2 opens ASWebAuthenticationSession on iOS and returns through the custom URL scheme "
                f"`{scheme or expr}`, which isn't tied to your app.")
    for key in order:
        items = sorted(groups[key], key=lambda x: x[0])
        _rank, path, line, message = items[0]
        others = [f"{p}:{ln}" for _r, p, ln, _msg in items[1:]]
        if others:
            shown = ", ".join(others[:4]) + (f" and {len(others) - 4} more" if len(others) > 4 else "")
            message += f" Same scheme also at {shown}."
        yield Hit(path, line, ctx.snippet(path, line), message, severity="low" if (path, line) in low else "")


# ============================================================================ storage


_KC_MIGRATABLE = re.compile(
    r"\bkSecAttrAccessible(?:WhenUnlocked|AfterFirstUnlock)\b|\.accessibility\(\s*\.(?:whenUnlocked|afterFirstUnlock)\s*[,)]"
)
_KC_SYNC = re.compile(r"kSecAttrSynchronizable\b[^\n]{0,40}\b(?:true|kCFBooleanTrue|YES)\b|\.synchronizable\(\s*true\s*\)")
_KA_INIT = re.compile(r"\bKeychain\s*\(\s*(?:service|server|accessGroup)\s*:")
# A KeychainAccess write: `keychain["k"] = v`, `keychain[data: "k"] = v` or `try keychain.set(v, key:)`.
_KA_WRITE = re.compile(r"\b\w*[kK]eychain\w*\s*\[[^\]\n]{1,120}\]\s*=(?!=)|\b\w*[kK]eychain\w*\s*\.\s*set\s*\(")


@detector("ios_keychain_migratable")
def keychain_migratable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        # A file reports only through a _KC_MIGRATABLE match (it holds "kSecAttrAccessible" or
        # "accessibility(") or an `import KeychainAccess`.
        if not holds_any(ctx, path, ("kSecAttrAccessible", "accessibility(", "KeychainAccess")):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if code is None or _KC_SYNC.search(code):
            continue
        for m in _KC_MIGRATABLE.finditer(code):
            before = code[max(0, code.rfind("\n", 0, m.start()) + 1):m.start()]
            after = code[m.end():m.end() + 40]
            # A comparison or a switch case reads the class; it doesn't store an item.
            if re.search(r"(?:==|!=|===|!==)\s*\(?\s*$", before) or re.search(r"\bcase\s+$", before) \
                    or re.match(r"\s*(?:as\s+String\s*)?\)?\s*(?:==|!=)", after):
                continue
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      "This Keychain accessibility class has no ThisDeviceOnly suffix.")
        if re.search(r"^\s*(?:@\w+\s+)*import\s+KeychainAccess\b", code, re.MULTILINE) \
                and not re.search(r"\.accessibility\s*\(", code) and _KA_WRITE.search(code):
            m = _KA_INIT.search(code)
            if m:
                line = ctx.line_of(code, m.start())
                yield Hit(path, line, ctx.snippet(path, line),
                          "This KeychainAccess keychain never sets .accessibility(...), so its items use the "
                          "library default .afterFirstUnlock, which isn't ThisDeviceOnly.")


_UD_KEY = r"(?![^\"]*(?:fcm|apns|push|device))[^\"]*(?:token|password|passwd|secret|jwt|credential|api_?key|session_?key)[^\"]*"
_UD_WRITE = re.compile(
    r"(?:UserDefaults|NSUserDefaults)\b[^\n;]{0,120}?\b(?:set|setValue|setObject)\s*[(:][^\n]{0,160}?forKey\s*:\s*@?\"("
    + _UD_KEY + r")\"|@AppStorage\(\s*\"(" + _UD_KEY + r")\"", re.IGNORECASE)
_UD_READ = re.compile(
    r"(?:UserDefaults|defaults)\b[^\n;]{0,80}?\.(?:string|data|object|value|array|dictionary)\s*\(\s*forKey\s*:\s*\"("
    + _UD_KEY + r")\"|NSUserDefaults\b[^\n;]{0,120}?\b(?:string|object|data)ForKey\s*:\s*@\"(" + _UD_KEY + r")\"",
    re.IGNORECASE)


@detector("ios_userdefaults_secret")
def userdefaults_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    writes: List[Hit] = []
    reads: List[Tuple[str, Hit]] = []
    written: Set[str] = set()
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or ("efaults" not in raw and "AppStorage" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        for m in _UD_WRITE.finditer(code):
            written.add((m.group(1) or m.group(2) or "").lower())
            line = ctx.line_of(code, m.start())
            writes.append(Hit(path, line, ctx.snippet(path, line),
                              "A value whose key names a token or secret is written to UserDefaults."))
        for m in _UD_READ.finditer(code):
            key = m.group(1) or m.group(2) or ""
            line = ctx.line_of(code, m.start())
            reads.append((key.lower(), Hit(path, line, ctx.snippet(path, line),
                                           f"UserDefaults key \"{key}\" names a token or secret and is read here, so "
                                           "it is stored there in plain text (it may be written from Dart, "
                                           "JavaScript or another target).")))
    yield from writes
    seen: Set[str] = set()
    for key, hit in reads:
        if key in written or key in seen:
            continue
        seen.add(key)
        yield hit


_PB_WRITE = re.compile(
    r"(?:UIPasteboard\s*\.\s*general|\[\s*UIPasteboard\s+generalPasteboard\s*\])\s*"
    r"(?:\.\s*(?:string|strings|url|urls|items)\s*=|\.?\s*(?:setValue|setData|setItems|addItems|setString|setObjects)\s*[(:])"
)
_PB_SECRET = re.compile(
    r"password|passcode|passphrase|token|secret|otp|\bpin\b|iban|card|cvv|cvc|seed|mnemonic|recovery|backup_?key"
    r"|private_?key|api_?key|e2e", re.IGNORECASE)
_PB_LOCAL_ONLY = re.compile(r"\.localOnly\s*:\s*(?!false\b)|UIPasteboardOptionLocalOnly\s*:\s*(?!@NO\b|@\(NO\))")
_PB_EXPIRY = re.compile(r"\.expirationDate\b|UIPasteboardOptionExpirationDate")
_INTERNAL_GUARD = re.compile(r"guard\s+(?:DebugFlags\.\w*[iI]nternal|isInternal\w*|FeatureFlags\.\w*[iI]nternal)"
                             r"|\bdebugOnly_\w+")


@detector("ios_pasteboard_secret")
def pasteboard_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "asteboard" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        for m in _PB_WRITE.finditer(code):
            tail = code[m.end() - 1:]
            if m.group(0).rstrip().endswith("("):
                end = _paren_end(code, m.end() - 1, limit=800)
                span = code[m.end():end] if end != -1 else code[m.end():m.end() + 300]
            else:
                stop = re.search(r"[;\n]", tail[1:])
                span = tail[1:1 + stop.start()] if stop else tail[1:200]
            if not _PB_SECRET.search(span):
                continue
            line = ctx.line_of(code, m.start())
            fstart, fend = _enclosing_function(code, m.start())
            note = (" This path looks internal-only (guarded by an internal or debug flag)."
                    if _INTERNAL_GUARD.search(code[fstart:fend]) else "")
            # An internal-only path is dead code in App Store builds: report it as debug scope (lowered).
            scope = "debug" if note else ""
            if _PB_LOCAL_ONLY.search(span):
                if _PB_EXPIRY.search(span):
                    continue
                yield Hit(path, line, ctx.snippet(path, line),
                          "A value that looks secret goes to the general pasteboard with .localOnly but no "
                          ".expirationDate, so it stays there until something else is copied." + note, scope=scope)
                continue
            yield Hit(path, line, ctx.snippet(path, line),
                      "A value that looks secret goes to the general pasteboard without .localOnly, so Universal "
                      "Clipboard can send it to the user's other devices." + note, scope=scope)


_DOCS_WRITE_NAME = re.compile(
    r"(?:appendingPathComponent|appending\s*\(\s*(?:path|component)\s*:|URLByAppendingPathComponent\s*:|"
    r"stringByAppendingPathComponent\s*:|fileURLWithPath\s*:)\s*\(?\s*@?\"([^\"\n]{1,80})\"")
_SENSITIVE_FILE = re.compile(
    r"token|session|secret|credential|password|\.db$|\.sqlite\w*$|\.realm$|keystore|keychain|\bkeys?\b|backup|export",
    re.IGNORECASE)
_DOCS_DIR = re.compile(r"\bdocumentDirectory\b|\bdocumentsDirectory\b|\bNSDocumentDirectory\b")


@detector("ios_documents_exposed")
def documents_exposed(ctx: Context, rule: Rule) -> Iterable[Hit]:
    exposed: Optional[Tuple[str, int]] = None
    for doc in _app_plists(ctx) or _shipping_plists(ctx):
        if plist.truthy(plist.get(doc.data, "UIFileSharingEnabled")):
            exposed = (doc.path, doc.line("UIFileSharingEnabled"))
            break
    if exposed is None and "UIFileSharingEnabled" in _infoplist_keys(ctx):
        exposed = ("build setting INFOPLIST_KEY_UIFileSharingEnabled", 0)
    if exposed is None:
        return
    where = f"{exposed[0]}:{exposed[1]}" if exposed[1] else exposed[0]
    for path in ctx.files(*CODE_SUFFIXES):
        if _is_test_path(path):
            continue
        raw = ctx.text(path)
        if raw is None or "ocument" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        reported: Set[int] = set()
        for d in _DOCS_DIR.finditer(code):
            fstart, fend = _enclosing_function(code, d.start())
            for n in _DOCS_WRITE_NAME.finditer(code, fstart, fend):
                name = n.group(1)
                if not _SENSITIVE_FILE.search(name) or n.start() in reported:
                    continue
                reported.add(n.start())
                line = ctx.line_of(code, n.start())
                yield Hit(path, line, ctx.snippet(path, line),
                          f"\"{name}\" is stored in Documents, which UIFileSharingEnabled ({where}) shows in the Files "
                          "app and Finder, and which ends up in unencrypted computer backups.")


_GROUP_CONTAINER = re.compile(r"containerURL\s*\(\s*forSecurityApplicationGroupIdentifier\s*:"
                              r"|containerURLForSecurityApplicationGroupIdentifier\s*:")
_FILE_WRITE = re.compile(r"\.write\s*\(\s*to\s*:|\bcreateFile\s*\(\s*atPath|\bcreateFileAtPath\s*:|writeToURL\s*:"
                         r"|writeToFile\s*:|\bNSPersistentStoreDescription\s*\(|addPersistentStore")
_SECRET_NAME = re.compile(r"token|password|passwd|secret|credential|session(?!Configuration)|jwt|api_?key", re.IGNORECASE)


@detector("ios_app_group_secret_file")
def app_group_secret_file(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "ApplicationGroupIdentifier" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=True)
        if code is None:
            continue
        for g in _GROUP_CONTAINER.finditer(code):
            fstart, fend = _enclosing_function(code, g.start())
            fn = code[fstart:fend]
            if not _FILE_WRITE.search(fn):
                continue
            names = [n.group(1) for n in _DOCS_WRITE_NAME.finditer(fn)]
            receivers = [w.group(1) for w in re.finditer(r"\b(\w+)\s*\.\s*write\s*\(\s*to\s*:", fn)]
            hit = next((x for x in names + receivers if _SECRET_NAME.search(x) and "URLSession" not in x), None)
            if hit is None:
                continue
            line = ctx.line_of(code, g.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      f"\"{hit}\" is written to a file in the shared App Group container, which every app and "
                      "extension in the group can read, without Keychain protection.")
            break


_UNARCHIVE = re.compile(
    r"\bNSKeyedUnarchiver\s*\.\s*unarchiveObject\s*\(\s*(?:with|withFile)\s*:|\bunarchiveTopLevelObjectWithData\b"
    r"|\[\s*NSKeyedUnarchiver\s+unarchiveObjectWith(?:Data|File)\s*:|\brequiresSecureCoding\s*=\s*(?:false|NO)\b")
_TYPE_DECL = re.compile(r"\b(?:class|struct|actor|enum)\s+([A-Z]\w*)|@interface\s+([A-Z]\w*)")


def _group_container_types(ctx: Context) -> Tuple[Set[str], Dict[str, str]]:
    """Files that open an App Group container, and their code (strings blanked); cached."""
    cache = _cache(ctx)
    if "group_container_files" not in cache:
        files: Dict[str, str] = {}
        for path in ctx.files(*CODE_SUFFIXES):
            raw = ctx.text(path) or ""
            if "ApplicationGroupIdentifier" not in raw or _is_test_path(path):
                continue
            code = ctx.code(path, keep_strings=False) or ""
            if _GROUP_CONTAINER.search(code):
                files[path] = code
        cache["group_container_files"] = files
    files = cache["group_container_files"]
    return set(files), files


def _trusted_archive(ctx: Context, path: str, code: str, idx: int) -> bool:
    """Does the archive come from the app's own App Group container, or is it decrypted first? Then only
    apps signed by the same team can have written it."""
    fstart, _fend = _enclosing_function(code, idx)
    if re.search(r"\bdecrypt\w*\s*\(", code[fstart:idx], re.IGNORECASE):
        return True
    paths, files = _group_container_types(ctx)
    if path in paths:
        return True
    names = {a or b for a, b in _TYPE_DECL.findall(code)}
    for other_code in files.values():
        if any(re.search(r"\b" + re.escape(n) + r"\s*\(", other_code) for n in names):
            return True
    return False


@detector("ios_insecure_unarchiver")
def insecure_unarchiver(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "Unarchiver" not in raw:
            continue
        code = ctx.code(path, keep_strings=False)
        if code is None:
            continue
        for m in _UNARCHIVE.finditer(code):
            line = ctx.line_of(code, m.start())
            msg = "This NSKeyedUnarchiver call doesn't restrict which classes it builds."
            severity = ""
            if _trusted_archive(ctx, path, code, m.start()):
                severity = "medium"
                msg += (" The archive comes from the app's own App Group container or is decrypted first, so only "
                        "apps signed by the same team can write it; still move to secure coding.")
            yield Hit(path, line, ctx.snippet(path, line), msg, severity=severity)


# ============================================================================ authentication


_EVAL_POLICY = re.compile(
    r"\.evaluatePolicy\s*\(\s*[^()]{0,300}?(?:\([^()]{0,300}\)[^()]{0,300}?){0,6},\s*localizedReason\s*:"
    r"|\bevaluatePolicy\s*:\s*[^\]]{0,300}?\blocalizedReason\s*:"
)
_KEY_BOUND = re.compile(r"kSecAttrAccessControl|SecAccessControlCreateWithFlags|kSecUseAuthenticationContext"
                        r"|SecKeyCreateSignature")
_BIO_BINDING = re.compile(r"\.biometry(?:CurrentSet|Any)\b|\.userPresence\b"
                          r"|kSecAccessControl(?:BiometryCurrentSet|BiometryAny|UserPresence|TouchIDCurrentSet|TouchIDAny)\b")


@detector("ios_biometric_boolean")
def biometric_boolean(ctx: Context, rule: Rule) -> Iterable[Hit]:
    binds_elsewhere = None
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "evaluatePolicy" not in raw:
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if code is None or _KEY_BOUND.search(code):
            continue
        for m in _EVAL_POLICY.finditer(code):
            if binds_elsewhere is None:
                binds_elsewhere = _search_code(ctx, _BIO_BINDING, include_tests=False,
                                               literals=("biometry", "userPresence", "kSecAccessControl"))
            line = ctx.line_of(code, m.start())
            msg = "evaluatePolicy is used, and this file never touches a key protected by SecAccessControl."
            if binds_elsewhere:
                # The real unlock most likely reads the biometry-bound item; this call is a confirmation
                # or user-verification gate, which is weaker but not the whole vault.
                msg += (" This repo binds a key to biometrics elsewhere (SecAccessControl), so this is likely a "
                        "confirmation gate; confirm it isn't the unlock path.")
            yield Hit(path, line, ctx.snippet(path, line), msg, severity="medium" if binds_elsewhere else "")


_REUSE_DURATION = re.compile(
    r"\btouchIDAuthenticationAllowableReuseDuration\s*=\s*(?:LATouchIDAuthenticationMaximumAllowableReuseDuration\b"
    r"|TimeInterval\s*\(\s*0*[1-9]|0*[1-9]\d*(?:\.\d+)?\b|0*\.\d*[1-9])"
    r"|\bsetTouchIDAuthenticationAllowableReuseDuration\s*:\s*(?:LATouchIDAuthenticationMaximumAllowableReuseDuration\b"
    r"|0*[1-9]|0*\.\d*[1-9])"
)


@detector("ios_biometric_reuse")
def biometric_reuse(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _code_hits(ctx, _REUSE_DURATION, "AllowableReuseDuration",
                          "A recent device unlock satisfies this LocalAuthentication check without a new prompt, "
                          "so whoever picks up an unlocked phone passes it.")


# ============================================================================ platform


_KEYBOARD_METHOD = re.compile(
    r"shouldAllowExtensionPointIdentifier\s+\w+\s*:\s*UIApplication\s*\.\s*ExtensionPointIdentifier"
    r"|shouldAllowExtensionPointIdentifier\s*:\s*\(\s*(?:UIApplicationExtensionPointIdentifier|NSString)"
)
_REFUSES_KEYBOARD = re.compile(
    r"(?:!=|==)\s*(?:UIApplication\s*\.\s*ExtensionPointIdentifier)?\s*\.keyboard\b|\.keyboard\s*(?:!=|==)"
    r"|UIApplicationKeyboardExtensionPointIdentifier|case\s+\.keyboard\b")


@detector("ios_third_party_keyboard")
def third_party_keyboard(ctx: Context, rule: Rule) -> Iterable[Hit]:
    code_files = ctx.files(*CODE_SUFFIXES)
    if not code_files:
        return
    found = False
    for path, line, body, _code, _m, _s in _functions(ctx, _KEYBOARD_METHOD):
        found = True
        refuses = _REFUSES_KEYBOARD.search(body) and (re.search(r"\breturn\s+(?:false|NO)\b", body)
                                                       or re.search(r"!=\s*(?:UIApplication\s*\.\s*"
                                                                    r"ExtensionPointIdentifier)?\s*\.keyboard\b|"
                                                                    r"\.keyboard\s*!=", body))
        if not refuses:
            yield Hit(path, line, ctx.snippet(path, line),
                      "shouldAllowExtensionPointIdentifier exists but doesn't return false for keyboards, so "
                      "third-party keyboards still see what users type.")
    if found:
        return
    yield from _anchor_hits(ctx, lambda name: (
        f"App {name} never refuses third-party keyboards (no shouldAllowExtensionPointIdentifier returning false "
        "for .keyboard), so a keyboard with Full Access can log what users type."))


@detector("ios_keyboard_full_access")
def keyboard_full_access(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc in _shipping_plists(ctx):
        ext = plist.get(doc.data, "NSExtension")
        if not isinstance(ext, dict) or ext.get("NSExtensionPointIdentifier") != "com.apple.keyboard-service":
            continue
        if plist.truthy(plist.get(ext, "NSExtensionAttributes", "RequestsOpenAccess")):
            yield _plist_hit(ctx, doc, ("NSExtension", "NSExtensionAttributes", "RequestsOpenAccess"),
                             "This keyboard extension requests Full Access (network and shared storage).")


_SWITCHER_EVIDENCE = re.compile(
    r"\bsceneCaptureState\b|\bisCaptured\b|capturedDidChangeNotification|userDidTakeScreenshotNotification"
    r"|privacySensitive\s*\(|\.redacted\s*\(\s*reason\s*:\s*\.privacy|\bsecure_application\b|\bscreen_protector\b"
    r"|\bprivacy_screen\b|\bno_screenshot\b|\bflutter_privacy_screen\b|isSecureTextEntry\s*=\s*true[^\n]{0,80}layer"
    r"|screenBlocking|ScreenShield|ScreenProtectorKit|SecureView\b|privacyScreen|PrivacyScreen|BlurWindow"
    r"|appSwitcher|AppSwitcher|snapshotProtect\w*|hideContentsInAppSwitcher|screenSecurity|ScreenSecurity")
_RESIGN_HANDLER = re.compile(
    r"\b(?:func\s+(?:sceneWillResignActive|applicationWillResignActive|sceneDidEnterBackground"
    r"|applicationDidEnterBackground)|-\s*\(\s*void\s*\)\s*(?:applicationWillResignActive|applicationDidEnterBackground"
    r"|sceneWillResignActive|sceneDidEnterBackground))\b")
_COVERS_VIEW = re.compile(r"addSubview|insertSubview|UIVisualEffectView|UIBlurEffect|\bisHidden\s*=|\.alpha\s*=|"
                          r"makeKeyAndVisible|setHidden\s*:|blur|cover|privacy|overlay|obscure|snapshot|lock",
                          re.IGNORECASE)
_COVERS_VIEW_STRICT = re.compile(r"addSubview|insertSubview|UIVisualEffectView|UIBlurEffect|\bisHidden\s*=|"
                                 r"makeKeyAndVisible|setHidden\s*:|privacy|[bB]lur|[cC]over(?:View|Window)\b|"
                                 r"[oO]bscure|[sS]napshot[A-Z]\w*")
_RESIGN_SELECTOR = re.compile(
    r"#selector\s*\(\s*(?:[\w.]+\.)?(\w+)[^)]*\)[^\n]{0,120}?(?:willResignActive|didEnterBackground)Notification"
    r"|(?:willResignActive|didEnterBackground)Notification[^\n]{0,160}?#selector\s*\(\s*(?:[\w.]+\.)?(\w+)")
# A literal from each _SWITCHER_EVIDENCE alternative ("privacy_screen" also in flutter_privacy_screen,
# "AppSwitcher" in hideContentsInAppSwitcher).
_SWITCHER_LITERALS = ("sceneCaptureState", "isCaptured", "capturedDidChangeNotification",
                      "userDidTakeScreenshotNotification", "privacySensitive", "redacted", "secure_application",
                      "screen_protector", "privacy_screen", "no_screenshot", "isSecureTextEntry", "screenBlocking",
                      "ScreenShield", "ScreenProtectorKit", "SecureView", "privacyScreen", "PrivacyScreen", "BlurWindow",
                      "appSwitcher", "AppSwitcher", "snapshotProtect", "screenSecurity", "ScreenSecurity")
_DART_LIFECYCLE_COVER = re.compile(
    r"AppLifecycleState\s*\.\s*(?:inactive|paused|hidden)[\s\S]{0,400}?(?:[oO]verlay|[bB]lur|[oO]bscur|[pP]rivacy|[sS]ecureScreen)"
    r"|(?:[oO]verlay|[bB]lur|[oO]bscur|[pP]rivacy|[sS]ecureScreen)\w*\s*=[^;\n]{0,200}AppLifecycleState\s*\.")
_SCENE_PHASE_COVER = re.compile(r"scenePhase[\s\S]{0,400}?(?:\.blur\s*\(|\.overlay\s*\(|redacted|PrivacyView|"
                                r"LockScreen|Placeholder)")


@detector("ios_app_switcher_snapshot")
def app_switcher_snapshot(ctx: Context, rule: Rule) -> Iterable[Hit]:
    code_files = ctx.files(*CODE_SUFFIXES)
    if not code_files:
        return
    if _search_code(ctx, _SWITCHER_EVIDENCE, CODE_SUFFIXES + (".dart",), literals=_SWITCHER_LITERALS) or re.search(
            r"\b(?:secure_application|screen_protector|privacy_screen|no_screenshot|flutter_privacy_screen)\s*:",
            _deps_text(ctx)):
        return
    for _p, _l, body, _c, _m, _s in _functions(ctx, _RESIGN_HANDLER):
        if _COVERS_VIEW.search(body):
            return
    # Every _SCENE_PHASE_COVER match holds "scenePhase"; each _DART_LIFECYCLE_COVER alternative "AppLifecycleState".
    if _search_code(ctx, _SCENE_PHASE_COVER, (".swift",), literals=("scenePhase",)) or _search_code(
            ctx, _DART_LIFECYCLE_COVER, (".dart",), include_tests=False, literals=("AppLifecycleState",)):
        return
    # Observers of willResignActive / didEnterBackground: look at the selector they call.
    for path in ctx.files(".swift", ".m"):
        raw = ctx.text(path)
        if raw is None or ("ResignActive" not in raw and "EnterBackground" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=False) or ""
        for sel in _RESIGN_SELECTOR.finditer(code):
            name = sel.group(1) or sel.group(2)
            for f in re.finditer(rf"\bfunc\s+{re.escape(name)}\s*\(|^\s*-\s*\(\s*void\s*\)\s*{re.escape(name)}\b", code,
                                 re.MULTILINE):
                span = _body(code, f.end())
                if span and _COVERS_VIEW_STRICT.search(code[span[0]:span[1]]):
                    return
    yield from _anchor_hits(ctx, lambda name: (
        f"App {name} never covers its screen when it goes to the background or is recorded (no "
        "sceneWillResignActive overlay, sceneCaptureState check or privacySensitive()), so the app switcher "
        "snapshot and screen recordings show whatever was on screen."))


# ============================================================================ build and resilience


_DEBUG_PODS = re.compile(r"^(?:FLEX|FLEXing|Reveal-SDK|netfox|Wormholy|CocoaDebug|DBDebugToolkit|FlipperKit|Flipper"
                         r"|Flipper-[\w-]+|LookinServer|Atlantis|DoraemonKit(?:/[\w]+)?|Bagel|GDPerformanceView-Swift)$")
_POD_LINE = re.compile(r"^\s*pod\s+['\"]([^'\"]+)['\"]([^\n]*)$", re.MULTILINE)
_POD_CONFIGS = re.compile(r"(?::configurations?\s*=>|configurations?\s*:)\s*(\[[^\]]*\]|['\"][^'\"]+['\"])")
_DEBUG_IMPORT = re.compile(
    r"^\s*(?:@?import)\s+(FLEX|netfox|Wormholy|CocoaDebug|DBDebugToolkit|LookinServer|Atlantis|DoraemonKit|FlipperKit)\b"
    r"|^\s*#import\s*<(FLEX|FlipperKit|CocoaDebug|DoraemonKit|LookinServer)/|\b(FLEXManager)\s*\.\s*shared\b",
    re.MULTILINE)


_DEBUG_TOOL_LITERALS = ("FLEX", "netfox", "Wormholy", "CocoaDebug", "DBDebugToolkit", "LookinServer", "Atlantis",
                        "DoraemonKit", "FlipperKit")


def _podfile_debug_pods(text: str) -> Iterator[Tuple[int, str]]:
    """(offset, pod) for debug-tool pods that are linked into a non-test target in every configuration."""
    stack: List[str] = []
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.split("#", 1)[0]
        t = re.match(r"\s*(?:abstract_)?target\s+['\"]([^'\"]+)['\"]", line)
        if t:
            stack.append(t.group(1))
        elif re.search(r"\bdo\b\s*(?:\|[^|]*\|)?\s*$", line):
            stack.append("")
        m = _POD_LINE.match(line.rstrip("\n"))
        if m:
            name, rest = m.group(1), m.group(2)
            in_test = any("test" in s.lower() for s in stack if s)
            if _DEBUG_PODS.match(name) and not in_test:
                cfg = _POD_CONFIGS.search(rest)
                cfgs = re.findall(r"['\"]([^'\"]+)['\"]", cfg.group(1)) if cfg else []
                if not cfgs or not all(pbxproj.is_debug_config(c) for c in cfgs):
                    yield offset + m.start(1), name
        if re.match(r"\s*end\b", line) and stack:
            stack.pop()
        offset += len(raw_line)


@detector("ios_debug_tool_release")
def debug_tool_release(ctx: Context, rule: Rule) -> Iterable[Hit]:
    reported: Set[str] = set()
    for path in ctx.files(name="Podfile"):
        text = ctx.text(path) or ""
        for off, name in _podfile_debug_pods(text):
            reported.add(name.split("/")[0].split("-")[0].lower())
            line = ctx.line_of(text, off)
            yield Hit(path, line, ctx.snippet(path, line),
                      f"Debug tool pod {name} is linked in every configuration, including Release.")
    for path in ctx.files(*CODE_SUFFIXES):
        if _is_test_path(path):
            continue
        raw = ctx.text(path)
        if raw is None or not any(t in raw for t in _DEBUG_TOOL_LITERALS) or not _DEBUG_IMPORT.search(raw):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if code is None:
            continue
        for m in _DEBUG_IMPORT.finditer(code):
            name = next(g for g in m.groups() if g)
            key = "flex" if name == "FLEXManager" else name.lower()
            if key in reported or re.search(rf"canImport\s*\(\s*{re.escape(name)}\s*\)", code):
                continue
            reported.add(key)
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      f"Debug tool {name} is used in code that also compiles into release builds.")


def _entitlements(ctx: Context) -> List[Tuple[PlistDoc, bool]]:
    """(entitlements file, ships in a release build)."""
    cache = _cache(ctx)
    if "entitlements" in cache:
        return cache["entitlements"]
    kinds: Dict[str, Set[bool]] = {}
    projects = _projects(ctx)
    for proj in projects:
        configs = set(proj.project_configs())
        demo = _demo_project(ctx, proj)
        for target in proj.targets():
            for name in set(target.configs) | configs:
                value = _effective(ctx, proj, target, name).get("CODE_SIGN_ENTITLEMENTS", (None, "", 0))[0]
                if not value or xcconfig.is_unresolved(value):
                    continue
                path = proj.settings_path(value)
                if path is not None:
                    shipping = not target.is_test and not demo and _is_shipping(ctx, proj, name)
                    kinds.setdefault(path, set()).add(shipping)
    out = []
    for doc in _load_plists(ctx, ".entitlements", "entitlement_docs"):
        if doc.path in kinds:
            shipping = True in kinds[doc.path]
        else:
            stem = posixpath.splitext(posixpath.basename(doc.path))[0]
            shipping = not pbxproj.is_debug_config(stem) and scope_of(doc.path) == "main"
        out.append((doc, shipping))
    cache["entitlements"] = out
    return out


@detector("ios_get_task_allow")
def get_task_allow(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for doc, shipping in _entitlements(ctx):
        if shipping and plist.truthy(plist.get(doc.data, "get-task-allow")):
            yield _plist_hit(ctx, doc, ("get-task-allow",),
                             "get-task-allow is true in entitlements a release build signs with, so any debugger "
                             "can attach to the app.")


@detector("ios_appattest_development")
def appattest_development(ctx: Context, rule: Rule) -> Iterable[Hit]:
    key = "com.apple.developer.devicecheck.appattest-environment"
    for doc, shipping in _entitlements(ctx):
        value = plist.get(doc.data, key)
        if shipping and isinstance(value, str) and value.strip().lower() == "development":
            yield _plist_hit(ctx, doc, (key,),
                             "App Attest uses the development environment in entitlements a release build signs "
                             "with; Apple's production attestation is never requested.")


@detector("ios_release_debug_flag")
def release_debug_flag(ctx: Context, rule: Rule) -> Iterable[Hit]:
    def check(key: str, value: str, _settings: Dict[str, Value], _o: Optional[Origin]) -> Optional[str]:
        if "sdk=iphonesimulator" in key:
            return None
        base = key.split("[", 1)[0]
        syms = _cond_tokens(base, value)
        if base == "GCC_PREPROCESSOR_DEFINITIONS":
            if "DEBUG" in syms and syms["DEBUG"].strip() not in ("0",):
                return f"{base} defines DEBUG={syms['DEBUG']}, so #if DEBUG code compiles into the release build."
            return None
        if "DEBUG" in syms:
            return f"{base} contains DEBUG, so #if DEBUG code compiles into the release build."
        return None

    yield from _setting_hits(ctx, check, lambda k: k.split("[", 1)[0] in _COND_KEYS)


@detector("ios_release_testability")
def release_testability(ctx: Context, rule: Rule) -> Iterable[Hit]:
    def check(key: str, value: str, _settings: Dict[str, Value], origin: Optional[Origin]) -> Optional[str]:
        if key == "ENABLE_TESTABILITY" and xcconfig.is_yes(value):
            return "ENABLE_TESTABILITY = YES exports internal symbols and skips stripping."
        if key == "STRIP_INSTALLED_PRODUCT" and xcconfig.is_no(value):
            return "STRIP_INSTALLED_PRODUCT = NO ships the binary with its symbols."
        if key == "STRIP_SWIFT_SYMBOLS" and xcconfig.is_no(value):
            return "STRIP_SWIFT_SYMBOLS = NO keeps Swift symbols in the shipped binary."
        if key == "STRIP_STYLE" and origin is not None and origin.target.is_app \
                and value.strip().strip('"').lower() in ("debugging", "non-global"):
            return f"STRIP_STYLE = {value.strip()} leaves symbols in the app binary (use all for an app)."
        return None

    yield from _setting_hits(ctx, check, lambda k: k in ("ENABLE_TESTABILITY", "STRIP_INSTALLED_PRODUCT",
                                                         "STRIP_SWIFT_SYMBOLS", "STRIP_STYLE"))


_ATTEST_EVIDENCE = re.compile(
    r"\bDCAppAttestService\b|\bAppAttestProvider\w*|AppleProvider\s*\.\s*appAttest|\bappAttest(?:WithDeviceCheckFallback)?\b"
    r"|\bfreerasp\b|\bTalsec\b|com\.aheaditec|\bApproov\w*|\bapproov\b|\bPromon\b|\biXGuard\b|\bAppdome\b"
    r"|\bZimperium\b|\bzDefend\b|\bVerimatrix\b|\bOneSpan\b|\bBuild38\b")
_ATTEST_LITERALS = ("AppAttest", "appAttest", "freerasp", "Talsec", "aheaditec", "pproov", "Promon", "iXGuard",
                    "Appdome", "Zimperium", "zDefend", "Verimatrix", "OneSpan", "Build38")
_DEVICECHECK = re.compile(r"\bDCDevice\b|\bDeviceCheckProvider\w*|AppleProvider\s*\.\s*deviceCheck")


@detector("ios_app_attest_missing")
def app_attest_missing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    suffixes = CODE_SUFFIXES + (".kt", ".dart")
    if not ctx.files(*CODE_SUFFIXES):
        return
    if _search_code(ctx, _ATTEST_EVIDENCE, suffixes, literals=_ATTEST_LITERALS) \
            or _ATTEST_EVIDENCE.search(_deps_text(ctx)):
        return
    if _search_code(ctx, _DEVICECHECK, suffixes, literals=("DCDevice", "DeviceCheck", "deviceCheck")):
        yield from _anchor_hits(ctx, lambda name: (
            f"App {name} uses DeviceCheck only (a device-level signal, not app integrity); App Attest isn't "
            "integrated, so the server can't tell your app from a modified copy or a script."))
        return
    yield from _anchor_hits(ctx, lambda name: (
        f"App Attest isn't integrated in app {name} (no DCAppAttestService, Firebase App Attest provider or "
        "attestation SDK), so the server can't tell your app from a modified copy or a script."))


# ============================================================================ privacy


_IDFA = re.compile(r"\bASIdentifierManager\b|\badvertisingIdentifier\b")


@detector("ios_idfa_without_att")
def idfa_without_att(ctx: Context, rule: Rule) -> Iterable[Hit]:
    uses = []
    for path in ctx.files(*CODE_SUFFIXES):
        if _is_test_path(path):
            continue
        raw = ctx.text(path)
        if raw is None or ("dvertisingIdentifier" not in raw and "ASIdentifierManager" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        m = _IDFA.search(code or "")
        if m:
            uses.append((path, ctx.line_of(code, m.start())))
    if not uses:
        return
    asks = _search_code(ctx, re.compile(r"\brequestTrackingAuthorization\b"), CODE_SUFFIXES + (".dart", ".kt"),
                        literals=("requestTrackingAuthorization",))
    purpose = any("NSUserTrackingUsageDescription" in d.data for d in _shipping_plists(ctx) if isinstance(d.data, dict)) \
        or "NSUserTrackingUsageDescription" in _infoplist_keys(ctx)
    if asks and purpose:
        return
    missing = "the App Tracking Transparency prompt (requestTrackingAuthorization)" if not asks \
        else "an NSUserTrackingUsageDescription purpose string"
    for path, line in uses:
        yield Hit(path, line, ctx.snippet(path, line),
                  f"The advertising identifier is read, and the project has no {missing}.")


_RR_CATEGORIES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("UserDefaults", re.compile(r"\bUserDefaults\b|\bNSUserDefaults\b|@AppStorage\b")),
    ("FileTimestamp", re.compile(
        r"\bFileAttributeKey\s*\.\s*(?:creationDate|modificationDate)\b|\[\s*\.(?:creationDate|modificationDate)\s*\]"
        r"|\b(?:contentModificationDate|creationDate|contentAccessDate|attributeModificationDate)Key\b"
        r"|\bNSFile(?:CreationDate|ModificationDate)\b|\bNSURL(?:Creation|ContentModification|ContentAccess)DateKey\b"
        r"|\bfileModificationDate\s*\(|(?<![\w.])(?:getattrlist|getattrlistbulk|fgetattrlist|getattrlistat|fstatat"
        r"|lstat|fstat|stat)\s*\(")),
    ("SystemBootTime", re.compile(r"\bsystemUptime\b|\bmach_absolute_time\s*\(")),
    ("DiskSpace", re.compile(
        r"\bvolume(?:Available|Total)Capacity(?:ForImportantUsage|ForOpportunisticUsage)?Key\b"
        r"|\bNSURLVolume(?:Available|Total)Capacity\w*Key\b|\bsystemFreeSize\b|\bNSFileSystem(?:Free)?Size\b"
        r"|(?<![\w.])(?:statfs|statvfs|fstatfs|fstatvfs)\s*\(")),
    ("ActiveKeyboards", re.compile(r"\bactiveInputModes\b")),
]
# Per category, literals at least one of which every match of its regex contains (alternative by alternative).
_RR_NEEDLES: Dict[str, Tuple[str, ...]] = {
    "UserDefaults": ("UserDefaults", "@AppStorage"),
    "FileTimestamp": ("FileAttributeKey", "creationDate", "modificationDate", "DateKey", "NSFile",
                      "fileModificationDate", "getattrlist", "stat"),
    "SystemBootTime": ("systemUptime", "mach_absolute_time"),
    "DiskSpace": ("Capacity", "systemFreeSize", "NSFileSystem", "statfs", "statvfs"),
    "ActiveKeyboards": ("activeInputModes",),
}


def _manifests(ctx: Context) -> List[PlistDoc]:
    return [d for d in _load_plists(ctx, ".xcprivacy", "manifests") if isinstance(d.data, dict)]


@detector("ios_required_reason_api")
def required_reason_api(ctx: Context, rule: Rule) -> Iterable[Hit]:
    manifests = _manifests(ctx)
    if not manifests:
        return            # IOS-019 reports the missing manifest
    declared: Set[str] = set()
    for doc in manifests:
        for entry in plist.get(doc.data, "NSPrivacyAccessedAPITypes") or []:
            if not isinstance(entry, dict):
                continue
            cat = entry.get("NSPrivacyAccessedAPIType")
            reasons = entry.get("NSPrivacyAccessedAPITypeReasons")
            if isinstance(cat, str) and isinstance(reasons, list) and reasons:
                declared.add(cat.replace("NSPrivacyAccessedAPICategory", ""))
    todo = [(c, rx) for c, rx in _RR_CATEGORIES if c not in declared]
    for path in ctx.files(*CODE_SUFFIXES):
        if not todo:
            break
        if scope_of(path) != "main" or _is_test_path(path):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if not code:
            continue
        for cat, rx in list(todo):
            if not holds_any(ctx, path, _RR_NEEDLES[cat]):
                continue
            m = rx.search(code)
            if m:
                todo.remove((cat, rx))
                line = ctx.line_of(code, m.start())
                yield Hit(path, line, ctx.snippet(path, line),
                          f"{m.group(0).strip('(').strip()} is a required-reason API (category {cat}), and no "
                          f"PrivacyInfo.xcprivacy in the repo declares NSPrivacyAccessedAPICategory{cat} with a reason.")


# (regex of API use, required keys: any one of these satisfies it)
_PURPOSE_APIS: List[Tuple["re.Pattern[str]", Tuple[str, ...], str]] = [
    (re.compile(r"\brequestWhenInUseAuthorization\b|\bstartUpdatingLocation\b|\brequestLocation\s*\("),
     ("NSLocationWhenInUseUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription"), "location"),
    (re.compile(r"\brequestAlwaysAuthorization\b"), ("NSLocationAlwaysAndWhenInUseUsageDescription",), "background location"),
    (re.compile(r"\brequestAccess\s*\(\s*for\s*:\s*(?:AVMediaType\s*)?\.video\b|requestAccessForMediaType\s*:\s*AVMediaTypeVideo"
                r"|\bAVCaptureDeviceInput\s*\(|\bsourceType\s*=\s*\.camera\b|UIImagePickerControllerSourceTypeCamera"),
     ("NSCameraUsageDescription",), "the camera"),
    (re.compile(r"\brequestAccess\s*\(\s*for\s*:\s*(?:AVMediaType\s*)?\.audio\b|requestAccessForMediaType\s*:\s*AVMediaTypeAudio"
                r"|\brequestRecordPermission\b|\bAVAudioRecorder\s*\("),
     ("NSMicrophoneUsageDescription",), "the microphone"),
    (re.compile(r"\brequestAccess\s*\(\s*for\s*:\s*(?:CNEntityType\s*)?\.contacts\b|requestAccessForEntityType\s*:\s*CNEntityTypeContacts"
                r"|\benumerateContacts\s*\(|\bunifiedContacts\s*\("),
     ("NSContactsUsageDescription",), "contacts"),
    (re.compile(r"\bPHPhotoLibrary\s*\.\s*requestAuthorization\s*\((?!\s*for\s*:\s*\.addOnly)|\bPHAsset\s*\.\s*fetchAssets\s*\("),
     ("NSPhotoLibraryUsageDescription",), "the photo library"),
    (re.compile(r"\brequestAuthorization\s*\(\s*for\s*:\s*\.addOnly|\bUIImageWriteToSavedPhotosAlbum\s*\("),
     ("NSPhotoLibraryAddUsageDescription", "NSPhotoLibraryUsageDescription"), "saving to the photo library"),
    (re.compile(r"\bHKHealthStore\b[\s\S]{0,400}?\brequestAuthorization\s*\(\s*toShare"),
     ("NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription"), "HealthKit data"),
    (re.compile(r"\bCBCentralManager\s*\(|\bCBPeripheralManager\s*\(|initWithDelegate\s*:[^\]]{0,80}\]\s*;?[^\n]*CBCentralManager"),
     ("NSBluetoothAlwaysUsageDescription",), "Bluetooth"),
    (re.compile(r"\bCMMotionActivityManager\s*\(|\bCMPedometer\s*\("), ("NSMotionUsageDescription",), "motion activity"),
    (re.compile(r"\bSFSpeechRecognizer\s*\.\s*requestAuthorization\b"), ("NSSpeechRecognitionUsageDescription",),
     "speech recognition"),
    (re.compile(r"\brequestAccess\s*\(\s*to\s*:\s*\.event\b|\brequestFullAccessToEvents\b|\brequestWriteOnlyAccessToEvents\b"),
     ("NSCalendarsUsageDescription", "NSCalendarsFullAccessUsageDescription", "NSCalendarsWriteOnlyAccessUsageDescription"),
     "calendars"),
    (re.compile(r"\brequestAccess\s*\(\s*to\s*:\s*\.reminder\b|\brequestFullAccessToReminders\b"),
     ("NSRemindersUsageDescription", "NSRemindersFullAccessUsageDescription"), "reminders"),
    (re.compile(r"\bATTrackingManager\s*\.\s*requestTrackingAuthorization\b"), ("NSUserTrackingUsageDescription",),
     "tracking"),
    (re.compile(r"\bNFC(?:NDEF|Tag|VAS)ReaderSession\s*\("), ("NFCReaderUsageDescription",), "NFC"),
    (_EVAL_POLICY, ("NSFaceIDUsageDescription",), "Face ID"),
]
_PURPOSE_LITERALS = ("Authorization", "requestAccess", "AVCaptureDeviceInput", ".camera", "SourceTypeCamera",
                     "RecordPermission", "AVAudioRecorder", "enumerateContacts", "unifiedContacts", "PHAsset",
                     "SavedPhotosAlbum", "CBCentralManager", "CBPeripheralManager", "CMMotionActivityManager",
                     "CMPedometer", "AccessToEvents", "AccessToReminders", "ReaderSession", "evaluatePolicy",
                     "startUpdatingLocation", "requestLocation")
_PLACEHOLDER = re.compile(r"^\s*(?:todo|tbd|fixme|lorem|placeholder|description|usage description|xxx+)\b|lorem ipsum"
                          r"|^\s*we need (?:access|permission)\.?\s*$|^\s*\$\(PRODUCT_NAME\) (?:needs|requires) access\.?\s*$",
                          re.IGNORECASE)


@detector("ios_purpose_string")
def purpose_string(ctx: Context, rule: Rule) -> Iterable[Hit]:
    plists = _app_plists(ctx) or [d for d in _shipping_plists(ctx) if isinstance(d.data, dict)
                                   and "CFBundleIdentifier" in d.data and scope_of(d.path) == "main"]
    if not plists and not _projects(ctx):
        return
    keys: Dict[str, Tuple[PlistDoc, Any]] = {}
    for doc in _shipping_plists(ctx):
        if isinstance(doc.data, dict) and scope_of(doc.path) == "main":
            for k, v in doc.data.items():
                if isinstance(k, str) and (k.endswith("UsageDescription") or k == "NFCReaderUsageDescription"):
                    keys.setdefault(k, (doc, v))
    generated = _infoplist_keys(ctx)
    for k, (doc, v) in keys.items():
        if isinstance(v, str) and (not v.strip() or _PLACEHOLDER.search(v)):
            yield _plist_hit(ctx, doc, (k,), f"{k} is empty or a placeholder (\"{v.strip()[:40]}\"); people see this "
                             "text in the permission prompt and App Review rejects it.")
    have = set(keys) | generated
    # Localized InfoPlist.strings values count too (the bundle's info dictionary merges them).
    for path in ctx.files(".strings"):
        if posixpath.basename(path).lower() == "infoplist.strings" and not _is_test_path(path):
            have.update(re.findall(r"^\s*\"?(\w+UsageDescription)\"?\s*=", ctx.text(path) or "", re.MULTILINE))
    todo = list(_PURPOSE_APIS)
    for path in ctx.files(*CODE_SUFFIXES):
        if not todo:
            break
        if scope_of(path) != "main" or _is_test_path(path):
            continue
        if not holds_any(ctx, path, _PURPOSE_LITERALS):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        if not code:
            continue
        for item in list(todo):
            rx, needed, what = item
            if any(k in have for k in needed):
                todo.remove(item)
                continue
            m = rx.search(code)
            if m:
                todo.remove(item)
                line = ctx.line_of(code, m.start())
                yield Hit(path, line, ctx.snippet(path, line),
                          f"This code asks for {what}, and no shipping Info.plist or INFOPLIST_KEY_ setting has "
                          f"{' or '.join(needed)}; the request fails or the app is rejected.")


# entitlement -> (code evidence regex, feature description)
_ENTITLEMENT_FEATURES: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("com.apple.developer.healthkit", re.compile(r"\bHKHealthStore\b|\bHealthKit\b|\bhealth\s*:|\bhealthkit\b", re.I),
     "HealthKit"),
    ("com.apple.security.application-groups", re.compile(
        r"suiteName|ApplicationGroupIdentifier|app_?group|appGroup|group\.[\w.-]+\"|home_widget|AppGroup", re.I),
     "App Groups"),
    ("com.apple.developer.icloud-container-identifiers", re.compile(
        r"\bCKContainer\b|\bCloudKit\b|NSUbiquitous|forUbiquityContainerIdentifier|ubiquityIdentityToken|icloud",
        re.I), "iCloud"),
    ("com.apple.developer.homekit", re.compile(r"\bHMHomeManager\b|\bHomeKit\b"), "HomeKit"),
    ("com.apple.developer.nfc.readersession.formats", re.compile(r"\bNFC\w*ReaderSession\b|\bCoreNFC\b|nfc_manager|flutter_nfc",
                                                                 re.I), "NFC tag reading"),
    ("com.apple.developer.networking.vpn.api", re.compile(r"\bNEVPNManager\b|\bNETunnelProviderManager\b|NetworkExtension"),
     "Personal VPN"),
    ("com.apple.developer.contacts.notes", re.compile(r"\bCNContactNoteKey\b|\bnote\b"), "contact notes"),
    ("com.apple.developer.siri", re.compile(r"\bINPreferences\b|\bIntents\b|\bINInteraction\b|AppIntent|\bSiri", re.I),
     "SiriKit"),
]


@detector("ios_unused_entitlement")
def unused_entitlement(ctx: Context, rule: Rule) -> Iterable[Hit]:
    docs = [(d, s) for d, s in _entitlements(ctx) if s and isinstance(d.data, dict)]
    if not docs:
        return
    suffixes = CODE_SUFFIXES + (".kt", ".dart", ".js", ".ts", ".tsx")
    deps = _deps_text(ctx)
    for key, rx, feature in _ENTITLEMENT_FEATURES:
        holders = [d for d, _s in docs if key in d.data and d.data.get(key) not in (False, None, [], "")]
        if not holders:
            continue
        if rx.search(deps) or _search_code(ctx, rx, suffixes, keep_strings=True):
            continue
        for doc in holders:
            yield _plist_hit(ctx, doc, (key,), f"The {feature} entitlement is granted, and no code uses {feature}.")


_TRACKING_DOMAINS = (
    "app-measurement.com", "google-analytics.com", "googleadservices.com", "doubleclick.net", "googlesyndication.com",
    "graph.facebook.com", "connect.facebook.net", "appsflyer.com", "appsflyersdk.com", "adjust.com", "adjust.io",
    "branch.io", "kochava.com", "singular.net", "mixpanel.com", "amplitude.com", "onesignal.com", "braze.com",
    "appboy.com", "segment.io", "segment.com", "flurry.com", "applovin.com", "unityads.unity3d.com", "chartboost.com",
    "vungle.com", "inmobi.com", "ironsrc.com", "criteo.com", "taboola.com", "outbrain.com", "scorecardresearch.com",
    "heapanalytics.com", "clevertap-prod.com", "wzrkt.com", "moengage.com", "leanplum.com", "smartlook.com",
    "uxcam.com", "fullstory.com",
)
_HOST_LITERAL = re.compile(r"\"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(/[^\"\s]*)?\"", re.IGNORECASE)
_NON_TRACKING_PATH = re.compile(r"privacy|terms|legal|policy|help|support|docs|blog|about|opt-?out", re.IGNORECASE)


def _tracking_domain(host: str) -> Optional[str]:
    h = host.lower()
    for d in _TRACKING_DOMAINS:
        if h == d or h.endswith("." + d):
            return d
    return None


@detector("ios_tracking_domains")
def tracking_domains(ctx: Context, rule: Rule) -> Iterable[Hit]:
    manifests = _manifests(ctx)
    if not manifests:
        return
    tracking = any(plist.truthy(plist.get(d.data, "NSPrivacyTracking")) for d in manifests)
    declared: List[str] = []
    for d in manifests:
        for v in plist.get(d.data, "NSPrivacyTrackingDomains") or []:
            if isinstance(v, str):
                declared.append(v.strip().lower().lstrip("*."))
    seen: Set[str] = set()
    for path in ctx.files(*CODE_SUFFIXES):
        if scope_of(path) != "main" or _is_test_path(path):
            continue
        if not holds_any(ctx, path, _TRACKING_DOMAINS):
            continue
        code = _release_code(ctx, path, keep_strings=True)
        for m in _HOST_LITERAL.finditer(code or ""):
            host = m.group(1).lower()
            dom = _tracking_domain(host)
            if dom is None or (m.group(2) and _NON_TRACKING_PATH.search(m.group(2))):
                continue
            covered = tracking and any(host == x or host.endswith("." + x) or x.endswith(dom) for x in declared)
            if covered or host in seen:
                continue
            seen.add(host)
            line = ctx.line_of(code, m.start())
            why = "NSPrivacyTracking is not true" if not tracking else "it isn't in NSPrivacyTrackingDomains"
            yield Hit(path, line, ctx.snippet(path, line),
                      f"The app contacts {host}, a known tracking domain, and the privacy manifest doesn't declare "
                      f"it ({why}).")


# ============================================================================ code


_XXE = re.compile(
    r"\bshouldResolveExternalEntities\s*=\s*(?:true|YES)\b|\bsetShouldResolveExternalEntities\s*:\s*YES\b"
    r"|\bXML_PARSE_NOENT\b|\bXML_PARSE_DTDLOAD\b|\bxmlSubstituteEntitiesDefault\s*\(\s*1\s*\)")


@detector("ios_xml_external_entities")
def xml_external_entities(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES + (".c", ".cc", ".cpp")):
        raw = ctx.text(path)
        if raw is None or ("ExternalEntities" not in raw and "XML_PARSE_" not in raw and "SubstituteEntities" not in raw):
            continue
        code = _release_code(ctx, path, keep_strings=False)
        for m in _XXE.finditer(code or ""):
            line = ctx.line_of(code, m.start())
            yield Hit(path, line, ctx.snippet(path, line),
                      "This XML parser resolves external entities or loads DTDs, so a crafted document can read "
                      "local files or make network requests (XXE).")


# ============================================================================ privacy and build


PRIVACY_MANIFEST = "PrivacyInfo.xcprivacy"


def _exists_under(ctx: Context, folder: str, name: str) -> bool:
    prefix = folder.rstrip("/") + "/" if folder else ""
    if any(f.startswith(prefix) and f.rsplit("/", 1)[-1] == name for f in ctx.project.files):
        return True
    base = os.path.join(ctx.root, folder)
    if not safety.is_within(ctx.root, base) or not os.path.isdir(base):
        return False
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in safety.SKIP_DIRS
                       and not os.path.islink(os.path.join(dirpath, d))]
        if name in filenames:
            return True
    return False


@detector("ios_privacy_manifest")
def privacy_manifest(ctx: Context, rule: Rule) -> Iterable[Hit]:
    projects = list(_projects(ctx))
    if not projects:
        ctx.note_unknown(f"No Xcode project was found, so app targets couldn't be checked for {PRIVACY_MANIFEST}.")
        return
    for proj in projects:
        if _demo_project(ctx, proj):
            continue
        in_project = any(isinstance(o, dict) and o.get("isa") == "PBXFileReference"
                         and proj.file_name(oid) == PRIVACY_MANIFEST for oid, o in proj.objects.items())
        for target in proj.targets():
            if not target.is_app:
                continue
            refs = proj.phase_files(target, "PBXResourcesBuildPhase")
            if any(proj.file_name(r) == PRIVACY_MANIFEST for r in refs):
                continue
            if any(_exists_under(ctx, g, PRIVACY_MANIFEST) for g in target.synchronized_groups):
                continue
            if in_project:
                msg = (f"{PRIVACY_MANIFEST} is in the project but not in app target {target.name}'s "
                       "Copy Bundle Resources, so it doesn't ship.")
            else:
                msg = f"App target {target.name} has no {PRIVACY_MANIFEST}."
            yield Hit(proj.path, target.line, ctx.snippet(proj.path, target.line), msg)
