# SPDX-License-Identifier: Apache-2.0
"""Android detectors: manifest, network security config, Gradle, and Android-specific code."""

from __future__ import annotations

import bisect
import datetime
import fnmatch
import itertools
import posixpath
import re
import weakref
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit import guards
from masaudit.detect import scope_of as _scope_of
from masaudit.detectors import flutter, rn_expo
from masaudit.guards import guarded_by
from masaudit.textscan import bracket_match, finditer_lit, holds_all, holds_any, text_memo, xml_tags
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.parsers import gradle, manifest, proguard, xmlsafe
from masaudit.parsers.xmlsafe import Element
from masaudit.safety import small_int


_SCOPES: Dict[str, str] = {}


def scope_of(path: str) -> str:
    """detect.scope_of, memoised: detectors ask it about the same paths many times per scan."""
    s = _SCOPES.get(path)
    if s is None:
        if len(_SCOPES) >= 200_000:
            _SCOPES.clear()
        s = _SCOPES[path] = _scope_of(path)
    return s


CODE_SUFFIXES = (".kt", ".java")
BUILD_FILES = ("build.gradle", "build.gradle.kts")


# ---------------------------------------------------------------------------- per-scan cache

_CACHES: "weakref.WeakKeyDictionary[Context, Dict[str, object]]" = weakref.WeakKeyDictionary()


def _memo(ctx: Context, key: str, fn: Callable[[], object]):
    """Compute a project-wide fact once per scan (several rules share the project model)."""
    store = _CACHES.setdefault(ctx, {})
    if key not in store:
        store[key] = fn()
    return store[key]


# ---------------------------------------------------------------------------- helpers


def _xml(ctx: Context, path: str):
    def parse():
        text = ctx.text(path)
        return None if text is None else xmlsafe.parse(text)
    root = _memo(ctx, "xml:" + path, parse)
    if root is None and ctx.text(path) is not None:
        ctx.note_unknown(f"Couldn't parse {path} (invalid XML or it declares entities).")
    return root


def _hit(ctx: Context, path: str, line: int, message: str, ack: str = "", scope: str = "",
         severity: str = "") -> Hit:
    """A hit whose scope also knows Gradle variants: code in a debug or non-release flavor or build
    type (src/staging/, src/internal/, a debug-derived build type) is reported as debug code.
    `severity` overrides the rule's severity for this one hit ("" keeps the rule's)."""
    base = scope_of(path)
    if not scope:
        scope = _scope(ctx, path)
    return Hit(path, line, ctx.snippet(path, line), message,
               scope=scope if scope != base else "", acknowledged=ack, severity=severity)


# Per-file cap on call sites a detector examines: each site costs a scan of its function, and a generated or
# hostile file with thousands of them must not stall the scan.
_MAX_SITES = 400


def _sites(matches):
    return itertools.islice(matches, _MAX_SITES)


def _build_types_of(ctx: Context, path: str, code: str, blank: str) -> Dict[str, gradle.BuildType]:
    return _memo(ctx, "build_types:" + path, lambda: gradle.build_types(code, blank))


def _manifests(ctx: Context) -> Iterator[Tuple[str, Element]]:
    for path in ctx.files(name="AndroidManifest.xml"):
        root = _xml(ctx, path)
        if root is not None and root.tag == "manifest":
            yield path, root


def _res_xml(ctx: Context, root_tag: str) -> Iterator[Tuple[str, Element]]:
    for path in ctx.files(".xml"):
        if "/res/xml/" not in "/" + path:
            continue
        text = ctx.text(path) or ""
        if f"<{root_tag}" not in text:
            continue
        root = _xml(ctx, path)
        if root is not None and root.tag == root_tag:
            yield path, root


def _code_files(ctx: Context, *needles: str) -> Iterator[Tuple[str, str, str]]:
    """(path, code, blank) for Kotlin/Java files whose raw text contains every needle.

    `code` has comments blanked; `blank` also blanks string contents. Offsets are identical.
    """
    for path in ctx.files(*CODE_SUFFIXES):
        if not holds_all(ctx, path, needles):
            continue
        code = ctx.code(path, keep_strings=True)
        blank = ctx.code(path, keep_strings=False)
        if code is not None and blank is not None:
            yield path, code, blank


def _code_files_any(ctx: Context, needles: Tuple[str, ...]) -> Iterator[Tuple[str, str, str]]:
    """Like _code_files, for files whose raw text contains at least one needle. A needle without
    whitespace that occurs in `code` or `blank` occurs at the same offset in the raw text (the lexer only
    turns characters into spaces), so this is a sound prefilter for any search that needs a needle."""
    for path in ctx.files(*CODE_SUFFIXES):
        if not holds_any(ctx, path, needles):
            continue
        code = ctx.code(path, keep_strings=True)
        blank = ctx.code(path, keep_strings=False)
        if code is not None and blank is not None:
            yield path, code, blank


def _match(text: str, i: int, opener: str, closer: str) -> int:
    """Index of the bracket closing the one at `i` (text must have strings blanked)."""
    return bracket_match(text, i, opener, closer)


def _args(blank: str, open_paren: int) -> List[Tuple[int, int]]:
    """Top-level argument spans of the call whose "(" is at open_paren."""
    close = _match(blank, open_paren, "(", ")")
    spans, depth, start = [], 0, open_paren + 1
    for j in range(open_paren + 1, close):
        c = blank[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            spans.append((start, j))
            start = j + 1
    if blank[start:close].strip() or spans:
        spans.append((start, close))
    return spans


def _debug_guarded(blank: str, idx: int) -> bool:
    """True if idx sits under `if (BuildConfig.DEBUG)` or an `if (... FLAG_DEBUGGABLE ...)` check."""
    return guarded_by(blank, idx, guards._jvm_debug)       # guards.jvm_debug_guarded, linear per file


def _is_import(blank: str, idx: int) -> bool:
    line_start = blank.rfind("\n", 0, idx) + 1
    return blank[line_start:idx].lstrip().startswith(("import", "package"))


_FUN_HEAD = re.compile(r"\bfun\s+(?:<[^>{}]*>\s*)?(?:[\w.]+\.)?(?P<name>\w+)\s*\(")
_JAVA_HEAD = re.compile(r"(?P<name>\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?$")
_NOT_METHODS = {"if", "for", "while", "switch", "catch", "synchronized", "when", "return", "new", "else", "try",
                "super", "this"}


def _function_at(blank: str, idx: int) -> Tuple[int, int, str]:
    """(body start, body end, name) of the innermost function or method around idx.

    Falls back to the whole file when no function encloses it. `blank` must have strings blanked.
    """
    depth = 0
    j = idx - 1
    while j >= 0:
        c = blank[j]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                head = blank[max(0, j - 400):j].rstrip()
                head_line = head[head.rfind("\n", 0, max(0, len(head) - 1)) + 1:] if head else ""
                heads = list(_FUN_HEAD.finditer(head))
                fm = heads[-1] if heads else None
                if fm is not None:
                    close = _match(blank, max(0, j - 400) + fm.end() - 1, "(", ")")
                    tail = blank[close + 1:j]
                    if close < j and re.fullmatch(r"\s*(?::\s*[\w.<>?,\s*]+)?\s*", tail):
                        return j + 1, _match(blank, j, "{", "}"), fm.group("name")
                jm = _JAVA_HEAD.search(head_line)
                if jm and jm.group("name") not in _NOT_METHODS and not re.search(r"\b(?:new|class|interface)\s+\w*\s*$",
                                                                                 head_line[:jm.start()]):
                    return j + 1, _match(blank, j, "{", "}"), jm.group("name")
            else:
                depth -= 1
        j -= 1
    return 0, len(blank), ""


_CLASS_HEAD = re.compile(r"\b(?:class|object|interface)\s+(?P<name>[A-Z]\w*)")


def _class_at(blank: str, idx: int) -> str:
    """Name of the innermost class or object declared around idx (blank = strings blanked)."""
    best = ""
    for m in _CLASS_HEAD.finditer(blank, 0, idx):
        brace = blank.find("{", m.end())
        if brace == -1 or brace > idx:
            # a class header whose body starts after idx can't enclose it
            continue
        semi = blank.find(";", m.end(), brace)
        if semi != -1 and "(" not in blank[m.end():semi]:
            continue
        if _match(blank, brace, "{", "}") > idx:
            best = m.group("name")
    return best


def _module_of(path: str) -> str:
    p = "/" + path
    if "/src/" in p:
        return p[: p.index("/src/")].lstrip("/")
    return posixpath.dirname(path)


def _source_set(path: str) -> str:
    p = "/" + path
    if "/src/" not in p:
        return ""
    return p.split("/src/", 1)[1].split("/", 1)[0]


_APP_PLUGIN = re.compile(r"com\.android\.application|android[.-]application")
_LIB_PLUGIN = re.compile(r"com\.android\.library|android[.-]library|com\.android\.test\b|java-library"
                         r"|kotlin\(\s*\"jvm\"\s*\)|kotlin\(\s*\"multiplatform\"\s*\)")


def _module_kinds(ctx: Context) -> Dict[str, str]:
    """module dir -> "app" | "lib" | "unknown", from each build.gradle(.kts)."""
    def compute() -> Dict[str, str]:
        out: Dict[str, str] = {}
        for path in ctx.files(*BUILD_FILES):
            if path.rsplit("/", 1)[-1] not in BUILD_FILES:
                continue
            code = ctx.code(path) or ""
            if _APP_PLUGIN.search(code):
                kind = "app"
            elif _LIB_PLUGIN.search(code):
                kind = "lib"
            else:
                kind = "unknown"
            out[posixpath.dirname(path)] = kind
        return out
    return _memo(ctx, "module_kinds", compute)


def _build_files(ctx: Context, kinds: Tuple[str, ...] = ("app", "unknown")) -> Iterator[Tuple[str, str, str]]:
    modules = _module_kinds(ctx)
    for path in ctx.files(*BUILD_FILES):
        if path.rsplit("/", 1)[-1] not in BUILD_FILES:
            continue
        if modules.get(posixpath.dirname(path), "unknown") not in kinds:
            continue
        code = ctx.code(path, keep_strings=True)
        blank = ctx.code(path, keep_strings=False)
        if code is not None and blank is not None:
            yield path, code, blank


def _under(el: Element, tag: str) -> bool:
    p = el.parent
    while p is not None:
        if p.tag == tag:
            return True
        p = p.parent
    return False


# ---------------------------------------------------------------------------- project model: variants


@dataclass
class _Module:
    dir: str
    kind: str
    build_types: Dict[str, gradle.BuildType] = field(default_factory=dict)
    flavors: List[str] = field(default_factory=list)
    deps: List[gradle.Dependency] = field(default_factory=list)
    ids: List[str] = field(default_factory=list)      # applicationId and namespace literals


_ID_SETTING = re.compile(r"(?<![\w.])(?:applicationId|namespace)\s*(?:=\s*|\(\s*|[ \t]+)"
                         r"(?:[\"'](?P<lit>[\w.]+)[\"']|(?P<const>[A-Z][A-Z0-9_]*)\b)")


def _modules(ctx: Context) -> Dict[str, _Module]:
    def compute() -> Dict[str, _Module]:
        kinds = _module_kinds(ctx)
        out: Dict[str, _Module] = {}
        for path in ctx.files(*BUILD_FILES):
            if path.rsplit("/", 1)[-1] not in BUILD_FILES:
                continue
            code, blank = ctx.code(path, True), ctx.code(path, False)
            if code is None or blank is None:
                continue
            d = posixpath.dirname(path)
            ids = []
            for m in _ID_SETTING.finditer(code):
                if m.group("lit"):
                    ids.append(m.group("lit"))
                else:       # a constant from buildSrc or the build script itself
                    local = re.search(r"\b" + m.group("const") + r"\s*=\s*[\"']([\w.]+)[\"']", code)
                    value = local.group(1) if local else _string_constants(ctx).get(m.group("const"))
                    if value:
                        ids.append(value)
            out[d] = _Module(d, kinds.get(d, "unknown"), _build_types_of(ctx, path, code, blank),
                             gradle.product_flavors(code, blank), gradle.dependencies(code), ids)
        return out
    return _memo(ctx, "modules", compute)


_NONRELEASE_FLAVOR = re.compile(r"(?i)^(?:staging|stage|stg|internal|dev|devel|develop|development|qa|uat|mock|mocked"
                                r"|sandbox|test|testing|demo|local|preprod)$|(?:Staging|Dev|Develop|Internal|Qa|QA|Uat"
                                r"|UAT|Mock|Mocked|Sandbox|Local)$")


def _camel(name: str) -> List[str]:
    return [t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", name)]


def _build_type_kind(name: str, types: Dict[str, gradle.BuildType], depth: int = 0) -> str:
    """"debug" (debuggable), "nonrelease" (derived from debug but not debuggable), or "release"."""
    if name == "debug":
        return "debug"
    bt = types.get(name)
    if bt is None or depth > 5:
        return "release"
    if bt.debuggable is True:
        return "debug"
    if bt.init_from and bt.init_from != name:
        parent = _build_type_kind(bt.init_from, types, depth + 1)
        if parent == "debug":
            return "nonrelease" if bt.debuggable is False else "debug"
        if parent == "nonrelease":
            return "nonrelease"
    if "debug" in bt.fallbacks and "release" not in bt.fallbacks:
        return "nonrelease"
    return "release"


def _variant_names(ctx: Context) -> Tuple[Dict[str, gradle.BuildType], Set[str]]:
    """Build types and flavors declared by app modules (used when a library has none of its own)."""
    def compute():
        types: Dict[str, gradle.BuildType] = {}
        flavors: Set[str] = set()
        for m in _modules(ctx).values():
            if m.kind == "app":
                types.update(m.build_types)
                flavors.update(m.flavors)
        return types, flavors
    return _memo(ctx, "variant_names", compute)


def _variant_kind(ctx: Context, module_dir: str, variant: str) -> str:
    """Classify a source set or configuration prefix such as `nightlyStaging` or `internalDebug`."""
    if not variant or variant == "main":
        return "release"
    mod = _modules(ctx).get(module_dir)
    types, flavors = (mod.build_types, set(mod.flavors)) if mod and (mod.build_types or mod.flavors) else (
        {}, set())
    app_types, app_flavors = _variant_names(ctx)
    types = {**app_types, **types}
    flavors = flavors | app_flavors
    tokens = _camel(variant)
    kinds = set()
    for name in set(types) | flavors | {"debug", "release"}:
        nt = _camel(name)
        if not nt or len(nt) > len(tokens):
            continue
        if any(tokens[i:i + len(nt)] == nt for i in range(len(tokens) - len(nt) + 1)):
            if name in flavors and name not in types:
                kinds.add("nonrelease" if _NONRELEASE_FLAVOR.search(name) else "release")
            else:
                kinds.add(_build_type_kind(name, types))
    if not kinds and _NONRELEASE_FLAVOR.search(variant):
        kinds.add("nonrelease")
    if "debug" in kinds:
        return "debug"
    if "nonrelease" in kinds:
        return "nonrelease"
    return "release"


_TEST_VARIANT = re.compile(r"(?i)test|benchmark|screenshot|lint|ksp|kapt|detekt")


def _module_scopes(ctx: Context) -> Dict[str, str]:
    """Modules wired in only through debug or non-release configurations (`internalImplementation`)."""
    def compute() -> Dict[str, str]:
        mods = _modules(ctx)
        by_base: Dict[str, List[str]] = {}
        for d in mods:
            by_base.setdefault(d.rsplit("/", 1)[-1], []).append(d)
        refs: Dict[str, Set[str]] = {}
        for m in mods.values():
            for dep in m.deps:
                for proj in dep.projects:
                    target = proj.strip(":").replace(":", "/")
                    if target not in mods:
                        cands = by_base.get(target.rsplit("/", 1)[-1], [])
                        if len(cands) != 1:
                            continue
                        target = cands[0]
                    if _TEST_VARIANT.search(dep.variant):
                        refs.setdefault(target, set()).add("test")
                    else:
                        refs.setdefault(target, set()).add(_variant_kind(ctx, m.dir, dep.variant))
        out: Dict[str, str] = {}
        for target, kinds in refs.items():
            if mods.get(target) and mods[target].kind == "app":
                continue
            if "release" not in kinds and kinds & {"debug", "nonrelease"}:
                out[target] = "debug"
        return out
    return _memo(ctx, "module_scopes", compute)


_PLAYGROUND = {"playground", "showcase", "testharness", "test-harness"}


def _scope(ctx: Context, path: str) -> str:
    """scope_of(path), refined with Gradle variants and Android resource conventions."""
    base = scope_of(path)
    if base != "main":
        return base
    module = _module_of(path)
    if any(seg in _PLAYGROUND for seg in module.lower().split("/")):
        return "debug"
    if re.search(r"/res/xml/\w+_debug\.xml$", "/" + path):
        return "debug"          # Android loads <name>_debug.xml only in debuggable builds
    ss = _source_set(path)
    if ss and ss != "main" and _variant_kind(ctx, module, ss) != "release":
        return "debug"
    if _module_scopes(ctx).get(module) == "debug":
        return "debug"
    return "main"


def _release_path(ctx: Context, path: str) -> bool:
    """The file ships in a release build (not test, debug, sample, or a non-release variant)."""
    return _scope(ctx, path) in ("main", "build-script")


# ---------------------------------------------------------------------------- project model: identity, SDK


_GENERIC_LABELS = {"com", "org", "net", "io", "de", "app", "apps", "android", "mobile", "client", "www", "debug",
                   "release", "beta", "dev", "co", "uk", "us", "eu", "me", "ai", "main", "core"}


def _identity_tokens(ctx: Context) -> Set[str]:
    """Words that name the app's own domain: from applicationId, namespace and manifest package."""
    def compute() -> Set[str]:
        ids: List[str] = []
        for m in _modules(ctx).values():
            if m.kind == "app":
                ids += m.ids
        for _path, root in _manifests(ctx):
            if root.get("package") and not manifest.is_placeholder(root.get("package")):
                ids.append(root.get("package") or "")
        out: Set[str] = set()
        for i in ids:
            for tok in i.lower().split("."):
                if len(tok) >= 3 and tok not in _GENERIC_LABELS:
                    out.add(tok)
        return out
    return _memo(ctx, "identity", compute)


def _app_id_prefixes(ctx: Context) -> List[str]:
    def compute() -> List[str]:
        ids: Set[str] = set()
        for m in _modules(ctx).values():
            ids.update(i for i in m.ids if i.count(".") >= 1)
        for _path, root in _manifests(ctx):
            pkg = root.get("package")
            if pkg and not manifest.is_placeholder(pkg) and pkg.count(".") >= 1:
                ids.add(pkg)
        return sorted(ids)
    return _memo(ctx, "app_ids", compute)


def _sdk_entries(ctx: Context, rule_key: str) -> List[Tuple[str, int, Optional[int], str, str]]:
    """Every place targetSdk or minSdk is set: (path, line, value or None, where, raw text)."""
    def compute():
        key_re = re.compile(r"(?<![\w])(" + rule_key + r"Version|" + rule_key + r")[ \t]*(?:=\s*|\(\s*|[ \t]+)"
                            r"(?P<val>[^\s,}]+)")
        catalog_key_re = re.compile(r"(?i)(?:^|[-_.])" + re.sub(r"Sdk", r"[-_.]?sdk", rule_key) + r"(?:version)?$")
        versions: Dict[str, Tuple[str, int, str]] = {}
        out: List[Tuple[str, int, Optional[int], str, str]] = []
        for path in ctx.files(".toml"):
            for key, (val, line) in gradle.toml_versions(ctx.text(path) or "").items():
                versions[key] = (val, line, path)
                if catalog_key_re.search(key) and small_int(val) is not None:
                    out.append((path, line, small_int(val), "in the version catalog", key))
        found_in_gradle = False
        build_like = list(_build_files(ctx))
        known = {p for p, _c, _b in build_like}
        for path in ctx.files(".kt", ".kts"):
            if path not in known and ("/build-logic/" in "/" + path or "/buildSrc/" in "/" + path):
                code, blank = ctx.code(path, True), ctx.code(path, False)
                if code is not None and blank is not None:
                    build_like.append((path, code, blank))
        for path, code, blank in build_like:
            skip = _Spans([b for name in ("lint", "lintOptions", "testOptions")
                           for b in gradle.named_blocks(code, blank, name)])
            for m in key_re.finditer(code):
                prefix = code[max(0, m.start() - 12):m.start()]
                if skip.holds(m.start()) or re.search(r"(?:lint|testOptions|lintOptions)\.$", prefix):
                    continue
                val = m.group("val")
                while val.endswith(")") and val.count("(") < val.count(")"):
                    val = val[:-1]
                found_in_gradle = True
                n = gradle.int_literal(val)
                if n is not None:
                    out.append((path, ctx.line_of(code, m.start()), n, f"in {path.rsplit('/', 1)[-1]}", val))
                    continue
                accessor = gradle.catalog_key(val)
                quoted = re.search(r"\b(?:findVersion|\w*[vV]ersion)\(\s*[\"']([\w.-]+)[\"']", val)
                if accessor is None and quoted:      # libs.findVersion("targetSdk"), convention helpers
                    accessor = re.sub(r"[-_]", ".", quoted.group(1))
                entry = None
                if accessor:
                    for key, (v, line, src) in versions.items():
                        if re.sub(r"[-_]", ".", key).lower() == accessor.lower():
                            entry = (v, line, src)
                if entry is not None and small_int(entry[0]) is not None:
                    out.append((entry[2], entry[1], small_int(entry[0]), "in the version catalog", val))
                else:
                    out.append((path, ctx.line_of(code, m.start()), None, f"in {path}", f"{m.group(1)}={val}"))
        if found_in_gradle or any(catalog_key_re.search(k) for k in versions):
            return out
        attr = "android:" + rule_key + "Version"
        for path, root in _manifests(ctx):
            for el in root.children:
                if el.tag != "uses-sdk":
                    continue
                val = el.get(attr)
                if manifest.is_placeholder(val):
                    out.append((path, el.line, None, f"in {path}", f"{attr} placeholder"))
                elif small_int(val or "") is not None:
                    out.append((path, el.line, small_int(val or ""), "in the manifest", val))
        return out
    return _memo(ctx, "sdk:" + rule_key, compute)


def _sdk_value(ctx: Context, rule_key: str) -> Optional[int]:
    """The app's targetSdk (highest found) or minSdk (lowest found), or None if unknown."""
    kinds = _module_kinds(ctx)
    entries = [e for e in _sdk_entries(ctx, rule_key) if e[2] is not None]
    app_entries = [e for e in entries if kinds.get(posixpath.dirname(e[0])) == "app"]
    values = [e[2] for e in (app_entries or entries) if e[2] is not None]
    if not values:
        return None
    return max(values) if rule_key == "targetSdk" else min(values)


def _string_constants(ctx: Context) -> Dict[str, str]:
    """`const val NAME = "literal"` and `static final String NAME = "literal"` across Kotlin and Java."""
    def compute() -> Dict[str, str]:
        out: Dict[str, str] = {}
        rx = re.compile(r"\b(?:const\s+val|val|static\s+final\s+String|final\s+static\s+String|final\s+String)\s+"
                        r"(?P<name>[A-Za-z_]\w*)\s*(?::\s*String)?\s*=\s*\"(?P<val>[^\"\\\n]{1,200})\"")
        for path in ctx.files(*CODE_SUFFIXES):
            raw = ctx.text(path) or ""
            if "\"" not in raw:
                continue
            code = ctx.code(path, True) or ""
            for m in finditer_lit(rx, code, ("const", "val", "static", "final")):
                out.setdefault(m.group("name"), m.group("val"))
        return out
    return _memo(ctx, "string_constants", compute)


# ---------------------------------------------------------------------------- Lint acknowledgements


def _lint_xml_ignores(ctx: Context) -> List[Tuple[str, str, str]]:
    """(lint.xml dir, issue id, path glob or "") for every issue a lint.xml turns off."""
    def compute():
        out: List[Tuple[str, str, str]] = []
        for path in ctx.files(name="lint.xml"):
            root = _xml(ctx, path)
            if root is None or root.tag != "lint":
                continue
            base = posixpath.dirname(path)
            for issue in root.iter("issue"):
                ids = [i.strip() for i in (issue.get("id") or "").split(",") if i.strip()]
                if (issue.get("severity") or "").strip() == "ignore":
                    out += [(base, i, "") for i in ids]
                for ign in issue.children:
                    if ign.tag == "ignore" and ign.get("path"):
                        out += [(base, i, ign.get("path") or "") for i in ids]
        return out
    return _memo(ctx, "lint_xml", compute)


def _glob(pattern: str, path: str) -> bool:
    rx = re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return bool(re.fullmatch(rx, path))


def _ack(ctx: Context, path: str, el: Optional[Element], *issue_ids: str) -> str:
    """How the project tells Android Lint this is intentional: `tools:ignore` on the element or an
    ancestor (with the nearby comment as the reason), or a lint.xml rule. Empty if it doesn't."""
    if el is not None:
        text = xmlsafe.ack_text(el, *issue_ids)
        if text:
            return text
    wanted = {i.lower() for i in issue_ids}
    for base, issue, pattern in _lint_xml_ignores(ctx):
        if issue.lower() not in wanted:
            continue
        if base and not path.startswith(base + "/"):
            continue                # a module's lint.xml covers only that module; the root one covers all
        rel = path[len(base) + 1:] if base and path.startswith(base + "/") else path
        if not pattern or _glob(pattern, rel) or _glob(pattern, path) or fnmatch.fnmatch(rel, pattern):
            return f"lint.xml ignores {issue}" + (f" for {pattern}" if pattern else "")
    return ""


# ---------------------------------------------------------------------------- network security config


def _nsc_names(ctx: Context) -> Set[str]:
    """Names of the network security config files the manifests point at (`@xml/<name>`)."""
    def compute() -> Set[str]:
        out: Set[str] = set()
        for _path, root in _manifests(ctx):
            for app in manifest.applications(root):
                ref = (app.get("android:networkSecurityConfig") or "").strip()
                if ref.startswith("@xml/"):
                    out.add(ref[5:])
        return out
    return _memo(ctx, "nsc_names", compute)


def _nsc_files(ctx: Context) -> Iterator[Tuple[str, Element]]:
    """Network security config files that a build uses. When the manifests name one, only those files
    (and their `_debug` variants) count; templates nobody references are noted, not reported."""
    names = _nsc_names(ctx)
    for path, root in _res_xml(ctx, "network-security-config"):
        if names:
            stem = path.rsplit("/", 1)[-1][:-4]
            if stem not in names and not (stem.endswith("_debug") and stem[:-6] in names):
                ctx.note_unknown(f"{path} is a network security config no manifest references; not evaluated.")
                continue
        yield path, root


_IF = re.compile(r"\bif\s*\(")
_ELSE = re.compile(r"\belse\s*\{")
_WHEN = re.compile(r"\bwhen\s*(?:\([^(){}]*(?:\([^(){}]*\)[^(){}]*)*\))?\s*\{")


def _conditions(blank: str, lo: int, idx: int) -> List[str]:
    """Conditions of the if/else/when blocks between lo and idx that idx sits inside."""
    out: List[str] = []
    for m in _IF.finditer(blank, lo, idx):
        open_paren = m.end() - 1
        close = _match(blank, open_paren, "(", ")")
        if close >= idx:
            continue
        j = close + 1
        while j < len(blank) and blank[j] in " \t\r\n":
            j += 1
        cond = re.sub(r"\s+", "", blank[open_paren + 1:close])
        if j < len(blank) and blank[j] == "{":
            if j < idx < _match(blank, j, "{", "}"):
                out.append(cond)
        else:
            between = blank[close + 1:idx]
            if ";" not in between and between.count("\n") <= 1 and "}" not in between:
                out.append(cond)
    for m in _ELSE.finditer(blank, lo, idx):
        if _match(blank, m.end() - 1, "{", "}") > idx:
            out.append("else")
    for m in _WHEN.finditer(blank, lo, idx):
        if _match(blank, m.end() - 1, "{", "}") > idx:
            out.append("when" + re.sub(r"\s+", "", m.group(0)))
    line_start = blank.rfind("\n", lo, idx) + 1
    stmt = blank[max(lo, line_start):idx]
    if re.search(r"\?:|->|\?\s+\w", stmt):
        out.append("inline")
    return out


# ---------------------------------------------------------------------------- network


def _default_cleartext(ctx: Context, path: str, app: Element) -> Optional[Hit]:
    """An app manifest with no usesCleartextTraffic: apps targeting API 27 or lower allow plain HTTP by
    default, unless a network security config's base-config turns it off."""
    module = _module_of(path)
    if _module_kinds(ctx).get(module, "unknown") == "lib":
        return None
    # this module's own targetSdk when its build file sets one (a repository can hold several apps)
    own = [e[2] for e in _sdk_entries(ctx, "targetSdk") if e[2] is not None and posixpath.dirname(e[0]) == module]
    target = max(own) if own else _sdk_value(ctx, "targetSdk")
    if target is None or target > 27:
        return None           # unknown, or Android 9's default (no cleartext) applies
    if _nsc_names(ctx):
        files = list(_nsc_files(ctx))
        if not files:
            ctx.note_unknown(f"{path}: the network security config it names wasn't found; check that it turns "
                             "off cleartext traffic.")
            return None
        if any(b.get("cleartextTrafficPermitted") is not None for _p, root in files for b in root.iter("base-config")):
            return None       # turned off, or turned on and reported on the base-config itself
    return _hit(ctx, path, app.line, f"targetSdk is {target}, so Android allows plain HTTP by default, and nothing "
                                     "(usesCleartextTraffic=\"false\" or a network security config) turns it off.")


def _managed_expo(ctx: Context) -> Optional["rn_expo.ExpoApp"]:
    """The Expo app config of a managed app (no android/ folder and no app manifest): prebuild generates the
    manifest from it, so the manifest rules read it instead."""
    if not rn_expo.is_rn_app(ctx) or _main_application(ctx) is not None:
        return None
    return rn_expo.managed_android(ctx)


def _expo_dynamic_path(ctx: Context, expo: "rn_expo.ExpoApp") -> str:
    """The app.config.js/ts next to the Expo config (its own path when the config is computed)."""
    if not expo.path.endswith(".json"):
        return expo.path
    for name in ("app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs"):
        path = posixpath.join(expo.folder, name)
        if path in ctx.files(name=name):
            return path
    return expo.path


@detector("android_cleartext")
def cleartext(ctx: Context, rule: Rule) -> Iterable[Hit]:
    # Network security config: cleartext allowed in the base config.
    for path, root in _nsc_files(ctx):
        for base in root.iter("base-config"):
            if xmlsafe.is_true(base.get("cleartextTrafficPermitted")):
                yield _hit(ctx, path, base.line, "The base config allows plain HTTP for every host.",
                           ack=_ack(ctx, path, base, "InsecureBaseConfiguration"))
    # Manifest: usesCleartextTraffic="true" on <application>. Android 7+ ignores it when the app has a
    # network security config, so it only matters there for minSdk 23 and lower.
    nsc_in_use = bool(_nsc_names(ctx))
    min_sdk = _sdk_value(ctx, "minSdk") if nsc_in_use else None
    for path, root in _manifests(ctx):
        for app in manifest.applications(root):
            value = app.get("android:usesCleartextTraffic")
            if manifest.is_placeholder(value):
                ctx.note_unknown(f"{path}: android:usesCleartextTraffic comes from a placeholder.")
                continue
            if value is None and _release_path(ctx, path) and _source_set(path) == "main":
                hit = _default_cleartext(ctx, path, app)
                if hit is not None:
                    yield hit
                continue
            if not xmlsafe.is_true(value):
                continue
            if nsc_in_use:
                if min_sdk is None or min_sdk >= 24:
                    continue
                msg = (f"usesCleartextTraffic=\"true\" allows plain HTTP on Android 6 and lower (minSdk {min_sdk}), "
                       "where the network security config doesn't apply.")
            else:
                msg = "The manifest allows plain HTTP for the whole app."
            yield _hit(ctx, path, app.line, msg)
    expo = _managed_expo(ctx)
    if expo is not None:
        # expo-build-properties writes android:usesCleartextTraffic into the generated manifest.
        props = expo.plugin("expo-build-properties") or {}
        android = props.get("android") if isinstance(props.get("android"), dict) else {}
        flag = expo.js_flag("usesCleartextTraffic")
        if android.get("usesCleartextTraffic") is True:
            line = expo.line("expo-build-properties", "usesCleartextTraffic")
            yield _hit(ctx, expo.path, line, "expo-build-properties sets android.usesCleartextTraffic to true, so the "
                                             "generated manifest allows plain HTTP for the whole app.")
        elif flag is not None and flag[0] and expo.dynamic is not None:
            dyn = _expo_dynamic_path(ctx, expo)
            yield _hit(ctx, dyn, flag[1], "The app config sets usesCleartextTraffic to true, so the generated manifest "
                                          "allows plain HTTP for the whole app.")


# Loopback, private ranges, and special-use names that never resolve on the public internet (RFC 6761,
# home.arpa, mDNS .local, Tor .onion, whose transport is end-to-end encrypted by Tor itself).
_LOCAL_HOST = re.compile(
    r"^(?:(?:.*\.)?(?:localhost|local|localdomain|test|invalid|example|home\.arpa|lan|home|internal|intranet|corp"
    r"|onion)|127(?:\.\d{1,3}){3}|10\.0\.[23]\.2|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}"
    r"|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|\[?::1\]?)$")
# Certificate revocation endpoints: CRLs and OCSP responses are signed, so HTTP is their normal transport.
_REVOCATION_HOST = re.compile(r"^(?:ocsp\d*|crls?\d*|cacerts|aia)\.|(?:^|\.)(?:ocsp|crl)\d*\.|^(?:c|o|x\d|r\d+|e\d+|crt)"
                              r"\.(?:lencr|pki|digicert|sectigo|globalsign|entrust|certainly|amazontrust|godaddy"
                              r"|usertrust|comodoca|identrust|buypass|ss)\.")


def _domain_config_domains(dc: Element) -> List[Element]:
    """<domain> entries a domain-config's own cleartext setting covers (nested configs that don't
    override it inherit it)."""
    out = [c for c in dc.children if c.tag == "domain"]
    for child in dc.children:
        if child.tag == "domain-config" and child.get("cleartextTrafficPermitted") is None:
            out += _domain_config_domains(child)
    return out


@detector("android_nsc_domain_cleartext")
def nsc_domain_cleartext(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _nsc_files(ctx):
        for dc in root.iter("domain-config"):
            if not xmlsafe.is_true(dc.get("cleartextTrafficPermitted")):
                continue
            hosts, revocation = [], []
            domains = _domain_config_domains(dc)
            last = max([d.line for d in domains] + [dc.line])
            # a comment in the block saying the hosts after it serve CRLs or OCSP
            crl_from = min([first for first, _end, text, _alone in root.comments
                            if dc.line - 3 <= first <= last and re.search(r"(?i)\b(?:crls?|ocsp|revocation)\b", text)]
                           + [last + 1])
            for d in domains:
                host = (d.text or "").strip().lower()
                if not host or _LOCAL_HOST.match(host):
                    continue
                if d.line > crl_from or _REVOCATION_HOST.search(host):
                    revocation.append(host)
                    continue
                hosts.append(host + (" and its subdomains" if xmlsafe.is_true(d.get("includeSubdomains")) else ""))
            if revocation and not hosts:
                ctx.note_unknown(f"{path}:{dc.line}: plain HTTP is allowed only for certificate revocation hosts "
                                 f"({', '.join(revocation[:3])}); CRL and OCSP responses are signed.")
            if hosts:
                yield _hit(ctx, path, dc.line, f"Plain HTTP is allowed for {', '.join(hosts)}.")


def _system_only_domains(root: Element) -> List[str]:
    out = []
    for dc in root.iter("domain-config"):
        certs = [c for ta in dc.children if ta.tag == "trust-anchors" for c in ta.children if c.tag == "certificates"]
        if certs and not any((c.get("src") or "").strip() == "user" for c in certs):
            out += [(d.text or "").strip() for d in dc.children if d.tag == "domain" and (d.text or "").strip()]
    return out


@detector("android_user_certs")
def user_certs(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _nsc_files(ctx):
        protected = _system_only_domains(root)
        for cert in root.iter("certificates"):
            if (cert.get("src") or "").strip() != "user" or _under(cert, "debug-overrides"):
                continue
            if _under(cert, "base-config"):
                msg = "User-installed CAs are trusted in the base config, so a proxy CA can read release traffic"
                if protected:
                    shown = ", ".join(protected[:4]) + (", ..." if len(protected) > 4 else "")
                    msg += f" (except {shown}, which trust only system CAs)"
                msg += "."
            else:
                dc = cert.parent
                while dc is not None and dc.tag != "domain-config":
                    dc = dc.parent
                hosts = [(d.text or "").strip() for d in (dc.children if dc else []) if d.tag == "domain"]
                where = f"the domain config for {', '.join(h for h in hosts if h)}" if any(hosts) else "a domain config"
                msg = f"User-installed CAs are trusted in {where}, so a proxy CA can read release traffic."
            yield _hit(ctx, path, cert.line, msg, ack=_ack(ctx, path, cert, "AcceptsUserCertificates"))


_SSL_ERROR = re.compile(r"\bonReceivedSslError\s*\(")
_PROCEED = re.compile(r"\??\.proceed\s*\(\s*\)")
_BAD_PROCEED_COND = re.compile(r"getBoolean\(|[Pp]refs?\b|[Pp]references?\b|[Ss]ettings\.|primaryError|SSL_UNTRUSTED"
                               r"|SSL_IDMISMATCH|SSL_EXPIRED|SSL_DATE_INVALID|hasError\(")


@detector("android_webview_ssl_proceed")
def webview_ssl_proceed(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "onReceivedSslError", "proceed"):
        for m in _sites(_SSL_ERROR.finditer(blank)):
            close = _match(blank, m.end() - 1, "(", ")")
            brace = blank.find("{", close)
            if brace == -1 or not re.fullmatch(r"\s*(?::\s*Unit\s*)?", blank[close + 1:brace]):
                continue
            end = _match(blank, brace, "{", "}")
            for p in _PROCEED.finditer(blank, brace, end):
                line = ctx.line_of(blank, p.start())
                conds = _conditions(blank, brace + 1, p.start())
                if not conds:
                    yield _hit(ctx, path, line,
                               "The WebView continues past a TLS certificate error, so any certificate is accepted.")
                elif any(re.search(r"(?<!!)BuildConfig\.DEBUG\b", c) for c in conds):
                    yield _hit(ctx, path, line, "Debug builds continue past TLS certificate errors in the WebView.",
                               scope="debug")
                elif any(_BAD_PROCEED_COND.search(c) for c in conds):
                    yield _hit(ctx, path, line,
                               "The WebView continues past a TLS certificate error when a setting or the error "
                               "type allows it, which no chain validation backs.")
                else:
                    ctx.note_unknown(f"{path}:{line}: the WebView calls proceed() on a TLS error only under a "
                                     "condition; confirm the condition validates the certificate chain.")


_TRUST_EMPTY = re.compile(r"\bcheckServerTrusted\s*\(")
_VERIFY = re.compile(r"\bverify\s*\(")
_LAMBDA_TRUE = re.compile(
    r"(?:\bHostnameVerifier|\bhostnameVerifier|\bsetDefaultHostnameVerifier)\s*(?:\(\s*)?"
    r"(?:\{\s*\w+\s*(?::\s*\w+\??\s*)?,\s*\w+\s*(?::\s*\w+\??\s*)?->|\(\s*\w+\s*,\s*\w+\s*\)\s*->)\s*true\b"
)
_ALLOW_ALL = re.compile(r"\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bAllowAllHostnameVerifier\b|\bNoopHostnameVerifier\b")
_GET_INSECURE = re.compile(r"\bSSLCertificateSocketFactory\s*\.\s*getInsecure\s*\(")


@detector("android_trust_all")
def trust_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    gate = ("checkServerTrusted", "HostnameVerifier", "hostnameVerifier", "SSLSession", "getInsecure")
    for path, _code, blank in _code_files_any(ctx, gate):
        if not any(n in blank for n in gate):
            continue
        for m in _sites(_TRUST_EMPTY.finditer(blank)):
            close = _match(blank, m.end() - 1, "(", ")")
            rest = blank[close + 1:close + 400]
            if re.match(r"\s*(?::\s*Unit\s*)?(?:throws\s+[\w.\s,]+?)?\s*(?:\{\s*(?:return\s*;?\s*)?\}|=\s*Unit\b)", rest):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "checkServerTrusted() is empty, so this TrustManager accepts every certificate.")
        for m in _sites(_VERIFY.finditer(blank)):
            close = _match(blank, m.end() - 1, "(", ")")
            if "SSLSession" not in blank[m.end():close]:
                continue
            rest = blank[close + 1:close + 200]
            if re.match(r"\s*(?::\s*Boolean\s*)?(?:=\s*true\b|\{\s*return\s+true\s*;?\s*\})", rest):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line, "This HostnameVerifier returns true for every host name.")
        for m in _LAMBDA_TRUE.finditer(blank):
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line, "This HostnameVerifier returns true for every host name.")
        for m in _ALLOW_ALL.finditer(blank):
            if _is_import(blank, m.start()):
                continue
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line, "An allow-all HostnameVerifier accepts certificates for any host name.")
        for m in _GET_INSECURE.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "SSLCertificateSocketFactory.getInsecure() turns off certificate and host name checks.")


# Pinning evidence counts only in shipping code, and never in comments: a test or a comment that
# mentions "pinning" must not silence the finding.
_HANDSHAKE = re.compile(r"\.\s*startHandshake\s*\(\s*\)")
_CREATE_SOCKET = re.compile(r"\.\s*createSocket\s*\(")
# Any sign that the host name is checked: a HostnameVerifier, SSLParameters endpoint identification, or a helper.
_HOST_CHECK = re.compile(r"HostnameVerifier|\.\s*verify\s*\(|[Ee]ndpointIdentificationAlgorithm|[Hh]ostnameVerif")
# `verifyHost(`, `checkServerHost(`: the name is matched once, then searched for "Host" in Python (a nested
# `\w*Host\w*` backtracks inside one long word, which is quadratic on a crafted file).
_HOST_CALL = re.compile(r"\b(?:verify|check)(\w*)\s*\(")


def _has_host_check(blank: str) -> bool:
    return bool(_HOST_CHECK.search(blank)) or any("Host" in m.group(1) for m in _HOST_CALL.finditer(blank))


@detector("android_sslsocket_hostname")
def sslsocket_hostname(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "startHandshake", "createSocket", "SSL"):
        if _has_host_check(blank) or re.search(r"TrustManager\b", blank):
            # The file checks host names somewhere, or decides trust itself (a peer's self-signed certificate,
            # a pin): assume it covers this socket. A TrustManager that trusts everything is AND-005.
            continue
        seen: Set[int] = set()
        for m in _sites(_HANDSHAKE.finditer(blank)):
            lo, hi, _fn = _function_at(blank, m.start())
            if lo in seen or not _CREATE_SOCKET.search(blank, lo, m.start()) or \
                    re.search(r"\bsetUseClientMode\s*\(\s*false\s*\)|\buseClientMode\s*=\s*false\b", blank[lo:hi]):
                continue          # no socket made here, or the server side of the handshake
            seen.add(lo)
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "This SSLSocket completes the TLS handshake without checking the server's host name. SSLSocket "
                       "doesn't do that check itself, so a valid certificate for any other site is accepted.")


_PIN_CODE = re.compile(r"\bCertificatePinner\b|\bTrustKit\b|\w*[Pp]inning\w*|\w*Pinner\b")
_PIN_VALUE = re.compile(r"sha256/[A-Za-z0-9+/]{43}=")
_PIN_DEPS = re.compile(r"trustkit|ssl-?pinning", re.IGNORECASE)
_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _has_pinning_evidence(ctx: Context) -> bool:
    for path in ctx.files(".xml", ".kt", ".java", ".kts", ".gradle", ".toml"):
        if scope_of(path) == "test":
            continue
        if path.endswith(".xml"):
            if "<pin-set" in _XML_COMMENT.sub("", ctx.text(path) or ""):
                return True
        elif path.endswith(".toml"):
            if _PIN_DEPS.search(re.sub(r"#[^\n]*", "", ctx.text(path) or "")):
                return True
        else:
            code, blank = ctx.code(path, True) or "", ctx.code(path, False) or ""
            # Each _PIN_CODE alternative contains one of these needles; every _PIN_VALUE match "sha256/".
            if (holds_any(ctx, path, ("TrustKit", "inning", "Pinner")) and _PIN_CODE.search(blank)) \
                    or (holds_any(ctx, path, ("sha256/",)) and _PIN_VALUE.search(code)):
                return True
            if path.endswith((".kts", ".gradle")) and _PIN_DEPS.search(code):
                return True
    return False


def _main_application(ctx: Context) -> Optional[Tuple[str, Element]]:
    """The <application> of the app module's src/main manifest: where whole-app findings anchor."""
    kinds = _module_kinds(ctx)
    apps: List[Tuple[str, Element]] = []
    for path, root in _manifests(ctx):
        if _scope(ctx, path) == "main":
            apps.extend((path, a) for a in manifest.applications(root))
    if not apps:
        return None
    apps.sort(key=lambda a: ("/src/main/" not in "/" + a[0], kinds.get(_module_of(a[0])) != "app",
                             a[0].count("/"), -len(a[1].children), a[0]))
    return apps[0]


_OKHTTP_FACTORY = re.compile(r"\bOkHttpClientProvider\s*\.\s*setOkHttpClientFactory\s*\(\s*(?:new\s+)?([A-Z]\w{0,80})\s*\(")


def _hidden_okhttp_factory(ctx: Context) -> Optional[str]:
    """The class React Native's OkHttp client comes from (`OkHttpClientProvider.setOkHttpClientFactory(X())`)
    when no Kotlin or Java file in the repository declares it, else None. A declared factory is scanned like
    any other code, so its pinning counts."""
    for _path, _code, blank in _code_files(ctx, "setOkHttpClientFactory"):
        m = _OKHTTP_FACTORY.search(blank)
        if not m:
            continue
        declared = re.compile(r"\b(?:class|object)\s+" + m.group(1) + r"\b")
        if not any(declared.search(b) for _p, _c, b in _code_files(ctx, m.group(1))):
            return m.group(1)
    return None


@detector("android_pinning_missing")
def pinning_missing(ctx: Context, rule: Rule) -> Iterable[Hit]:
    is_flutter = flutter.is_flutter(ctx)
    is_rn = not is_flutter and rn_expo.is_rn_app(ctx)
    if is_rn and rn_expo.pinning_call(ctx):
        return                     # react-native-ssl-public-key-pinning or react-native-ssl-pinning is called
    expo = rn_expo.managed_android(ctx) if is_rn else None
    if expo is not None and not _main_application(ctx):
        # A managed Expo app: prebuild writes the manifest (INTERNET included) from app.json.
        if not rn_expo.config_pins(expo) and not _has_pinning_evidence(ctx):
            line = expo.line("android") if expo.get("android") is not None else expo.line("expo")
            yield _hit(ctx, expo.path, line,
                       "No certificate pinning found for this Expo app: no pinning library is called "
                       "(initializeSslPinning or an sslPinning option) and no config plugin adds a <pin-set>.")
        return
    internet = any(p.get("android:name") == "android.permission.INTERNET"
                   for _path, root in _manifests(ctx) for p in manifest.uses_permissions(root))
    anchor = _main_application(ctx)
    if anchor is None or not internet:
        return
    if not is_flutter and not is_rn and any(f.rsplit("/", 1)[-1] == "package.json" for f in ctx.project.files):
        ctx.note_unknown("Pinning check skipped: React Native code may pin outside the Android sources.")
        return
    if is_flutter and flutter.dart_pinning_evidence(ctx):
        return
    if _has_pinning_evidence(ctx):
        if is_flutter and not flutter.uses_native_http(ctx):
            ctx.note_unknown("Android pinning is configured natively, but Flutter's Dart HttpClient has its own "
                             "TLS stack and ignores it; confirm the Dart side pins too.")
        return
    for path, _code, blank in _code_files(ctx, "checkServerTrusted"):
        if "checkServerTrusted" in blank:
            ctx.note_unknown(f"Pinning check skipped: {path} has a custom TrustManager that may pin.")
            return
    if is_rn:
        hidden = _hidden_okhttp_factory(ctx)
        if hidden:
            ctx.note_unknown(f"Pinning check skipped: React Native's HTTP client comes from `{hidden}`, whose source "
                             "isn't in the repository (a private module added at build time), so it may pin.")
            return
    path, app = anchor
    if is_flutter:
        yield _hit(ctx, path, app.line,
                   "No certificate pinning found: no <pin-set>, no OkHttp CertificatePinner, no pinning library, "
                   "and no Dart-side pinning (SecurityContext or a pinning package).")
        return
    if is_rn:
        yield _hit(ctx, path, app.line,
                   "No certificate pinning found: no <pin-set>, no OkHttp CertificatePinner, and no JavaScript "
                   "pinning (initializeSslPinning or an sslPinning option of a pinning library).")
        return
    yield _hit(ctx, path, app.line,
               "No certificate pinning found: no <pin-set>, no OkHttp CertificatePinner, and no pinning library.")


@detector("android_pin_set")
def pin_set(ctx: Context, rule: Rule) -> Iterable[Hit]:
    today = datetime.date.today()
    for path, root in _nsc_files(ctx):
        for ps in root.iter("pin-set"):
            problems = []
            pins = [c for c in ps.children if c.tag == "pin"]
            if len(pins) < 2:
                problems.append("it has only one pin and no backup pin")
            exp = (ps.get("expiration") or "").strip()
            if not exp:
                problems.append("it has no expiration date")
            else:
                try:
                    when = datetime.date.fromisoformat(exp)
                except ValueError:
                    when = None
                if when is not None and when < today:
                    problems.append(f"its pins expired on {exp}, so Android no longer enforces them")
            if problems:
                yield _hit(ctx, path, ps.line, "This pin-set is risky: " + "; ".join(problems) + ".")
    if rn_expo.is_rn_app(ctx):
        # react-native-ssl-public-key-pinning: initializeSslPinning({ host: { publicKeyHashes, expirationDate } })
        for js in rn_expo.js_pin_sets(ctx):
            problems = []
            if 0 <= js.pins < 2:
                problems.append(f"it has {js.pins} public key hash{'es' if js.pins != 1 else ''} and no backup pin")
            if not js.expiration:
                problems.append("it has no expirationDate")
            if problems:
                yield _hit(ctx, js.path, js.line,
                           f"The JavaScript pin set for {js.host} is risky: " + "; ".join(problems) + ".")


_GATED_TRUST = re.compile(r"certificatePinner\s*\(|CertificatePinner|sslSocketFactory\s*\(|hostnameVerifier\s*\("
                          r"|TrustManager|\btrustAll\w*")
_BUILDCONFIG_IF = re.compile(r"\bif\s*\(\s*!?\s*BuildConfig\.\w+")


def _gated_within(gated: List[Tuple[int, int]], start: int, end: int) -> bool:
    """`_GATED_TRUST.search(blank[start:end])`, from the file's matches (`gated`, in order). Searching each
    if's block again was quadratic in a file of nested or unclosed blocks. No _GATED_TRUST match contains a
    brace, and a region starts at `{` or after whitespace and ends at `}`, a newline, or the end of the file,
    so a match in the region is a whole-file match lying inside it, and the first file match starting in
    it has the earliest end."""
    k = bisect.bisect_left(gated, (start, -1))
    return k < len(gated) and gated[k][1] <= end


@detector("android_buildconfig_trust")
def buildconfig_trust(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "BuildConfig."):
        gated: Optional[List[Tuple[int, int]]] = None
        for m in _BUILDCONFIG_IF.finditer(blank):
            open_paren = blank.index("(", m.start())
            close = _match(blank, open_paren, "(", ")")
            j = close + 1
            while j < len(blank) and blank[j] in " \t\r\n":
                j += 1
            if gated is None:
                gated = [(g.start(), g.end()) for g in _GATED_TRUST.finditer(blank)]
            if j < len(blank) and blank[j] == "{":
                end = _match(blank, j, "{", "}")
                found = _gated_within(gated, j, end)
                em = re.compile(r"\s*else\s*\{").match(blank, end + 1)
                if em:
                    found = found or _gated_within(gated, em.end() - 1, _match(blank, em.end() - 1, "{", "}"))
            else:
                nl = blank.find("\n", j)
                found = _gated_within(gated, j, nl if nl != -1 else len(blank))
            if found:
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "Certificate pinning or trust checks depend on a BuildConfig flag that can be flipped.")


# ---------------------------------------------------------------------------- components (shared by code rules)

_SYSTEM_PERMISSION = re.compile(r"^(?:android\.permission\.|com\.google\.android\.c2dm\.permission\.SEND$"
                                r"|com\.google\.android\.gms\.)")


def _permission_strength(perm: str, declared: Dict[str, str]) -> str:
    """"strong" (system or signature), "weak" (normal/dangerous, any app can get it), or "unknown"."""
    if _SYSTEM_PERMISSION.match(perm):
        return "strong"
    if perm in declared:
        return "strong" if "signature" in declared[perm] else "weak"
    return "unknown"


def _declared_permissions(ctx: Context) -> Dict[str, str]:
    def compute() -> Dict[str, str]:
        out: Dict[str, str] = {}
        for _path, root in _manifests(ctx):
            out.update(manifest.declared_permissions(root))
        return out
    return _memo(ctx, "declared_permissions", compute)


def _simple(name: str) -> str:
    return (name or "").strip().rsplit(".", 1)[-1].rsplit("$", 1)[-1]


def _component_reach(ctx: Context) -> Tuple[Set[str], Set[str]]:
    """(simple class names of components other apps can start, names declared but not reachable)."""
    def compute():
        declared = _declared_permissions(ctx)
        exported: Set[str] = set()
        private: Set[str] = set()
        for path, root in _manifests(ctx):
            if scope_of(path) == "test":
                continue
            app_perm = next((a.get("android:permission") for a in manifest.applications(root)
                             if a.get("android:permission")), None)
            for c in manifest.components(root, ("activity", "activity-alias", "service", "receiver")):
                attr = c.get("android:exported")
                filters = manifest.intent_filters(c)
                if manifest.is_placeholder(attr):
                    reach = True
                else:
                    reach = xmlsafe.is_true(attr) if attr is not None else bool(filters)
                perm = c.get("android:permission") or app_perm
                if reach and perm and not manifest.is_placeholder(perm) and \
                        _permission_strength(perm.strip(), declared) == "strong":
                    reach = False
                names = [_simple(c.get("android:name") or "")]
                if c.tag == "activity-alias" and c.get("android:targetActivity"):
                    names.append(_simple(c.get("android:targetActivity") or ""))
                for n in names:
                    if n:
                        (exported if reach else private).add(n)
        return exported, private
    return _memo(ctx, "component_reach", compute)


_KT_SUPER = re.compile(r"\bclass\s+(?P<name>[A-Z]\w*)(?:\s*<[^>{}]*>)?[^{:\n]*?(?:\([^{}]*?\))?\s*:\s*(?P<sup>(?:[a-z]\w*\.)*[A-Z][\w.]*)")
_JAVA_SUPER = re.compile(r"\bclass\s+(?P<name>[A-Z]\w*)(?:\s*<[^>{}]*>)?\s+extends\s+(?P<sup>[A-Z][\w.]*)")


# _KT_SUPER in pieces, for _kt_supers.
_KT_HEAD = re.compile(r"\bclass\s+(?P<name>[A-Z]\w*)")
_KT_GENERIC = re.compile(r"\s*<[^>{}]*>")
_KT_REST = re.compile(r"\s*:\s*(?P<sup>(?:[a-z]\w*\.)*[A-Z][\w.]*)")
_NON_SPACE = re.compile(r"\S")


class _KtSupers:
    """The (name, sup) of every _KT_SUPER match in a text, as finditer finds them, in linear time.

    The regex itself backtracks: for every `class` it tries each offset to the end of the line, and at each
    `(` it scans to the next brace for a `)`, so a file of `class A (` lines (or one long line) took time
    quadratic in its size. Its parts are deterministic except where it searches, so the search is done
    here with indexes, in the order the regex tries things:
      * the name is the longest run the regex can take (a shorter name only leaves letters for the lazy
        part to skip), and the generic `<...>` matches in at most one way; with one, the rest is tried
        first after it, then (as the regex backtracks) after the name;
      * the lazy part tries offsets y = x, x+1, ... until a `{`, `:`, or newline: at y, the paren group
        succeeds with the first `)` before the next brace that _KT_REST matches after, else _KT_REST is
        tried at y, which equals _KT_REST at the first non-space at or after y. The outcome from y onward
        doesn't depend on where the walk started, so it's remembered for every offset walked."""

    def __init__(self, text: str):
        self.text = text
        self.rest: Dict[int, Optional[Tuple[int, str]]] = {}
        self.walk: Dict[int, Optional[Tuple[int, str]]] = {}
        self.closers: Optional[List[int]] = None      # `)` offsets that _KT_REST matches after
        self.braces: List[int] = []

    def _rest(self, z: int) -> Optional[Tuple[int, str]]:
        if z not in self.rest:
            m = _KT_REST.match(self.text, z)
            self.rest[z] = (m.end(), m.group("sup")) if m else None
        return self.rest[z]

    def _group(self, y: int) -> Optional[Tuple[int, str]]:
        """`\\([^{}]*?\\)` at the `(` at y, then _KT_REST."""
        if self.closers is None:
            self.closers = [m.start() for m in re.finditer(r"\)", self.text) if self._rest(m.start() + 1)]
            self.braces = [m.start() for m in re.finditer(r"[{}]", self.text)]
        k = bisect.bisect_right(self.closers, y)
        if k == len(self.closers):
            return None
        b = bisect.bisect_right(self.braces, y)
        if b < len(self.braces) and self.braces[b] < self.closers[k]:
            return None
        return self._rest(self.closers[k] + 1)

    def _lazy(self, x: int) -> Optional[Tuple[int, str]]:
        text, n = self.text, len(self.text)
        path: List[int] = []
        found: Optional[Tuple[int, str]] = None
        y, space_end = x, -1
        while True:
            if y in self.walk:
                found = self.walk[y]
                break
            path.append(y)
            hit = self._group(y) if y < n and text[y] == "(" else None
            if hit is None:
                if y < n and text[y].isspace() and y >= space_end:
                    m = _NON_SPACE.search(text, y)
                    space_end = m.start() if m else n
                hit = self._rest(space_end if y < space_end else y)
            if hit is not None:
                found = hit
                break
            if y >= n or text[y] in "{:\n":
                break
            y += 1
        for q in path:
            self.walk[q] = found
        return found

    def matches(self) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        text = self.text
        after = 0                                  # finditer resumes after the previous match
        i = text.find("class")
        while i >= 0:
            head = _KT_HEAD.match(text, i) if i >= after else None
            if head:
                generic = _KT_GENERIC.match(text, head.end())
                found = self._lazy(generic.end()) if generic else None
                if found is None:
                    found = self._lazy(head.end())
                if found is not None:
                    out.append((head.group("name"), found[1]))
                    after = found[0]
            i = text.find("class", max(i + 1, after))
        return out


def _class_index(ctx: Context) -> Tuple[Dict[str, Set[str]], Dict[str, str], Dict[str, List[str]]]:
    """(superclass -> subclasses, class -> superclass, class -> files declaring it), from Kotlin and Java."""
    def compute():
        subs: Dict[str, Set[str]] = {}
        sup_of: Dict[str, str] = {}
        files: Dict[str, List[str]] = {}
        for path in ctx.files(*CODE_SUFFIXES):
            if scope_of(path) == "test":
                continue
            blank = ctx.code(path, False) or ""
            for m in finditer_lit(_CLASS_HEAD, blank, ("class", "object", "interface")):
                files.setdefault(m.group("name"), []).append(path)
            pairs = _KtSupers(blank).matches() + [(m.group("name"), m.group("sup"))
                                                  for m in finditer_lit(_JAVA_SUPER, blank, ("class",))]
            for name, sup in pairs:
                sup = sup.rsplit(".", 1)[-1]
                subs.setdefault(sup, set()).add(name)
                sup_of.setdefault(name, sup)
        return subs, sup_of, files
    return _memo(ctx, "class_index", compute)


def _reachable(ctx: Context, cls: str, hosts: bool = True) -> Optional[bool]:
    """Can another app start this class (or a subclass of it) as a component?

    True: an exported component. False: declared, but never exported. None: not a component (helper,
    fragment without a known host) or no manifest to check against.
    """
    exported, private = _component_reach(ctx)
    if not exported and not private:
        return None
    subs, sup_of, files = _class_index(ctx)
    seen: Set[str] = set()
    todo = [cls]
    declared = False
    while todo and len(seen) < 5000:
        c = todo.pop()
        if c in seen:
            continue
        seen.add(c)
        if c in exported:
            return True
        if c in private:
            declared = True
        todo.extend(sorted(subs.get(c, ())))
    if declared:
        return False
    if not hosts:
        return None
    # A fragment or view runs inside the activities that use it.
    chain, c = [], cls
    while c in sup_of and len(chain) < 6:
        c = sup_of[c]
        chain.append(c)
    if not any(re.search(r"Fragment|Sheet|Dialog|View|Screen", s) for s in chain + [cls]):
        return None
    verdicts = set()
    word = re.compile(r"\b" + re.escape(cls) + r"\b")
    for path in ctx.files(*CODE_SUFFIXES):
        if path in files.get(cls, []) or scope_of(path) == "test":
            continue
        raw = ctx.text(path) or ""
        if cls not in raw:
            continue
        blank = ctx.code(path, False) or ""
        if not word.search(blank):
            continue
        for m in _CLASS_HEAD.finditer(blank):
            v = _reachable(ctx, m.group("name"), hosts=False)
            if v is not None:
                verdicts.add(v)
    if True in verdicts:
        return True
    if False in verdicts:
        return False
    return None


def _exposed(ctx: Context, path: str, blank: str, idx: int, what: str) -> bool:
    """Gate for code rules that matter only in components other apps can start."""
    cls = _class_at(blank, idx)
    verdict = _reachable(ctx, cls) if cls else None
    if verdict is None:
        exported, private = _component_reach(ctx)
        if not exported and not private:
            return True               # no manifest to check against: report
        ctx.note_unknown(f"{path}:{ctx.line_of(blank, idx)}: {what} in {cls or 'code'} that masaudit can't tie "
                         "to a manifest component; check whether another app can reach it.")
        return False
    return verdict


# ---------------------------------------------------------------------------- WebView


_WV_DEBUG = re.compile(r"\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)")
_DEBUG_DECL = re.compile(
    r"\b(?:val|var|fun|boolean|Boolean)\s+(?P<name>\w+)\s*(?:\(\s*\))?\s*(?::\s*Boolean\??\s*)?"
    r"(?:=|\bget\s*\(\s*\)\s*=|\{\s*return)\s*(?P<rhs>[^\n;]{0,200})")


def _debug_names(blank: str) -> Set[str]:
    """Properties and functions in this file that only read the debug flag."""
    out: Set[str] = set()
    for m in _DEBUG_DECL.finditer(blank):
        rhs = m.group("rhs")
        if re.search(r"(?<!!)BuildConfig\.DEBUG\b", rhs) or ("FLAG_DEBUGGABLE" in rhs and "== 0" not in rhs
                                                            and "==0" not in rhs):
            out.add(m.group("name"))
    tail = re.compile(r"\b(?:val|var)\s+(?P<name>\w+)\s*(?::\s*Boolean\s*)?\n\s*get\s*\(\s*\)\s*=\s*(?P<rhs>[^\n]+)")
    for m in tail.finditer(blank):
        if "FLAG_DEBUGGABLE" in m.group("rhs") or "BuildConfig.DEBUG" in m.group("rhs"):
            out.add(m.group("name"))
    return out


def _debug_only_bools(ctx: Context) -> Set[str]:
    """`R.bool` names that are false in src/main/res and true only in debug or non-release source sets."""
    def compute() -> Set[str]:
        main_false: Set[str] = set()
        true_release: Set[str] = set()
        rx = re.compile(r"<bool\s+name=\"(\w+)\"\s*>\s*(true|false)\s*</bool>")
        for path in ctx.files(".xml"):
            if "/res/values" not in "/" + path:
                continue
            text = ctx.text(path) or ""
            if "<bool" not in text:
                continue
            for name, val in rx.findall(_XML_COMMENT.sub("", text)):
                ss = _source_set(path)
                if ss == "main" and val == "false":
                    main_false.add(name)
                elif val == "true" and (ss in ("main", "") or _release_path(ctx, path)):
                    true_release.add(name)
        return main_false - true_release
    return _memo(ctx, "debug_bools", compute)


_BUILDCONFIG_FIELD = re.compile(r"\bbuildConfigField\s*\(?\s*(?:type\s*=\s*)?[\"']boolean[\"']\s*,\s*(?:name\s*=\s*)?"
                                r"[\"'](?P<name>\w+)[\"']\s*,\s*(?:value\s*=\s*)?"
                                r"[\"'](?P<val>[^\"']*)[\"']")


def _buildconfig_release(ctx: Context) -> Dict[str, Set[str]]:
    """Boolean BuildConfig fields -> the values a shipping variant can get ({"false"} = off in release)."""
    def compute() -> Dict[str, Set[str]]:
        default: Dict[str, str] = {}
        release: Dict[str, Set[str]] = {}
        for path, code, blank in _build_files(ctx, ("app",)):
            module = posixpath.dirname(path)
            types = _build_types_of(ctx, path, code, blank)
            flavors = [b for pf in gradle.named_blocks(code, blank, "productFlavors")
                       for b in gradle.direct_children(code, blank, pf)]
            for m in _BUILDCONFIG_FIELD.finditer(code):
                name, val = m.group("name"), m.group("val").strip().lower()
                bt = next((n for n, t in types.items() if t.block.body_start <= m.start() < t.block.body_end), None)
                fl = next((f for f in flavors if f.body_start <= m.start() < f.body_end), None)
                if bt is not None:
                    if _variant_kind(ctx, module, bt) == "release":
                        release.setdefault(name, set()).add(val)
                elif fl is not None:
                    if _variant_kind(ctx, module, fl.name) == "release":
                        release.setdefault(name, set()).add(val)
                else:
                    default.setdefault(name, val)
        out: Dict[str, Set[str]] = {}
        for name in set(default) | set(release):
            out[name] = release.get(name) or {default.get(name, "?")}
        return out
    return _memo(ctx, "buildconfig", compute)


def _cond_debug(cond: str, names: Set[str], bools: Set[str], fields: Optional[Dict[str, Set[str]]] = None) -> bool:
    """Is this (whitespace-free) if condition true only in debug builds?"""
    if not cond or cond in ("else", "inline") or cond.startswith("when"):
        return False
    for disjunct in cond.split("||"):
        ok = False
        for atom in disjunct.split("&&"):
            a = atom.strip("()")
            if a.startswith("!"):
                continue
            fm = re.fullmatch(r"BuildConfig\.(\w+)(?:==true)?", a)
            if (fm and fm.group(1) == "DEBUG") or ("FLAG_DEBUGGABLE" in a and "==0" not in a):
                ok = True
            elif fm and fields and fields.get(fm.group(1)) == {"false"}:
                ok = True              # a BuildConfig flag that every release variant sets to false
            elif re.fullmatch(r"(?:this\.|\w+\.)?(\w+)(?:\(\))?", a) and \
                    re.fullmatch(r"(?:this\.|\w+\.)?(\w+)(?:\(\))?", a).group(1) in names:
                ok = True
            else:
                bm = re.search(r"getBoolean\(R\.bool\.(\w+)\)", a)
                if bm and bm.group(1) in bools:
                    ok = True
        if not ok:
            return False
    return True


_EARLY_RETURN = re.compile(r"\bif\s*\(\s*!\s*(?P<cond>[^()\n]{1,80}?(?:\(\))?)\s*\)\s*\{?\s*return\b")


def _debug_only(ctx: Context, blank: str, idx: int) -> bool:
    """idx runs only in debug builds: under BuildConfig.DEBUG, a FLAG_DEBUGGABLE check, a property that
    wraps one, a release-false BuildConfig flag, or a debug-only R.bool."""
    if _debug_guarded(blank, idx):
        return True
    lo, _hi, _fn = _function_at(blank, idx)
    names = _debug_names(blank)
    bools, fields = _debug_only_bools(ctx), _buildconfig_release(ctx)
    # `if (!BuildConfig.DEBUG) return` earlier in the same function, at its top level
    for m in _EARLY_RETURN.finditer(blank, lo, idx):
        depth = blank.count("{", lo, m.start()) - blank.count("}", lo, m.start())
        if depth == 0 and _cond_debug(re.sub(r"\s+", "", m.group("cond")), names, bools, fields):
            return True
    conds = _conditions(blank, lo, idx)
    return any(_cond_debug(c, names, bools, fields) for c in conds)


_DEBUGGISH = re.compile(r"BuildConfig\.DEBUG|FLAG_DEBUGGABLE|R\.bool\.|[Dd]ebug")


_MIXED_ALWAYS = re.compile(r"(?:mixedContentMode\s*=\s*|setMixedContentMode\s*\(\s*)(?:WebSettings\.)?"
                           r"(?:MIXED_CONTENT_ALWAYS_ALLOW\b|0\b)")


@detector("android_mixed_content")
def mixed_content(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path)
        if raw is None or "ixedContentMode" not in raw:
            continue
        blank = ctx.code(path, keep_strings=False)
        if blank is None:
            continue
        for m in _MIXED_ALWAYS.finditer(blank):
            line = ctx.line_of(blank, m.start())
            yield Hit(path, line, ctx.snippet(path, line), "The WebView always allows HTTP content inside HTTPS pages.")
    if not rn_expo.is_rn_app(ctx):
        return
    # react-native-webview: mixedContentMode="never" is the default; "always" maps to MIXED_CONTENT_ALWAYS_ALLOW
    # and "compatibility" to MIXED_CONTENT_COMPATIBILITY_MODE (images and media over HTTP, not scripts).
    for use in rn_expo.webview_prop(ctx, "mixedContentMode"):
        if use.inline_html:
            continue                     # no https page, so nothing is mixed
        scope = "debug" if use.debug else ""
        if use.value == "always":
            yield Hit(use.path, use.line, ctx.snippet(use.path, use.line),
                      "mixedContentMode=\"always\" lets this WebView load HTTP scripts inside HTTPS pages on Android.",
                      scope=scope)
        elif use.value == "compatibility":
            yield Hit(use.path, use.line, ctx.snippet(use.path, use.line),
                      "mixedContentMode=\"compatibility\" lets this WebView load HTTP images and media inside HTTPS "
                      "pages on Android, which a network attacker can replace.", scope=scope, severity="low")
        elif use.value is rn_expo.UNKNOWN and not (use.debug or use.passthrough):
            ctx.note_unknown(f"{use.path}:{use.line}: mixedContentMode is set from `{use.text[:60]}`; confirm it is "
                             "\"never\" in release builds.")


@detector("android_webview_debugging")
def webview_debugging(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "setWebContentsDebuggingEnabled"):
        names = None
        for m in _sites(_WV_DEBUG.finditer(blank)):
            if names is None:
                names = _debug_names(blank)
            lo, _hi, _fn = _function_at(blank, m.start())
            conds = _conditions(blank, lo, m.start())
            if _debug_only(ctx, blank, m.start()):
                continue
            line = ctx.line_of(blank, m.start())
            # `if (!BuildConfig.DEBUG)` is a release-only branch: report it. Other mentions of a debug flag
            # that masaudit can't resolve are noted, not reported.
            negated = r"!\(?(?:BuildConfig\.DEBUG|" + "|".join([re.escape(n) for n in names] + [r"\0"]) + r")\b\)?"
            unresolved = [re.sub(negated, "", c) for c in conds]
            if any(_DEBUGGISH.search(c) or any(re.search(r"\b" + re.escape(n) + r"\b", c) for n in names)
                   for c in unresolved):
                ctx.note_unknown(f"{path}:{line}: WebView debugging depends on a condition that mentions a debug "
                                 "flag masaudit can't resolve; confirm it's false in release.")
                continue
            yield _hit(ctx, path, line, "WebView debugging is turned on for every build, including release.")
    if rn_expo.is_rn_app(ctx):
        yield from _js_webview_debugging(ctx, "Android")


def _js_webview_debugging(ctx: Context, platform: str) -> Iterator[Hit]:
    """react-native-webview's `webviewDebuggingEnabled` prop (Chrome DevTools on Android, Safari on iOS)."""
    for use in rn_expo.webview_prop(ctx, "webviewDebuggingEnabled"):
        if use.value is True:
            yield Hit(use.path, use.line, ctx.snippet(use.path, use.line),
                      f"webviewDebuggingEnabled is on for this WebView in every build, so on {platform} anyone with "
                      "the device can inspect the page and run scripts in it.", scope="debug" if use.debug else "")
        elif use.value is rn_expo.UNKNOWN and not (use.debug or use.passthrough):
            ctx.note_unknown(f"{use.path}:{use.line}: webviewDebuggingEnabled is set from `{use.text[:60]}`; "
                             "confirm it is false in release builds.")


_URL_SOURCE = re.compile(
    r"getStringExtra\s*\(|getQueryParameter\s*\(|\bintent\??\.data(?:String)?\b"
    r"|getIntent\(\)\s*\.\s*getData(?:String)?\s*\(|\bintent\??\.extras\??\.getString\s*\("
    r"|getExtras\(\)\s*\.\s*getString\s*\("
)
_LOAD_URL = re.compile(r"\.loadUrl\s*\(")
_STRING_ASSIGN = re.compile(r"(?:\bval|\bvar|\bString)\s+(\w+)\s*(?::\s*String\??\s*)?=\s*([^;\n]*)")
_URL_CHECK = re.compile(r"\bsanitize\w*\s*\(|\b\w*[Aa]llow\w*\s*\(|\bisSafe\w*\s*\(|\bisTrusted\w*\s*\(")


@detector("android_webview_untrusted_url")
def webview_untrusted_url(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "loadUrl"):
        if re.search(r"\.host\b|getHost\s*\(", blank):
            continue          # the file inspects the host: assume an allowlist check
        tainted = {m.group(1) for m in _STRING_ASSIGN.finditer(blank)
                   if _URL_SOURCE.search(m.group(2)) and not _URL_CHECK.search(m.group(2))}
        for m in _sites(_LOAD_URL.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            first = blank[spans[0][0]:spans[0][1]]
            name = re.fullmatch(r"\s*(\w+)\s*(?:!!|\.toString\(\))?\s*", first)
            if (_URL_SOURCE.search(first) and not _URL_CHECK.search(first)) or (name and name.group(1) in tainted):
                if not _exposed(ctx, path, blank, m.start(), "a WebView loads an intent URL"):
                    continue
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "The WebView loads a URL that came from an intent or deep link, with no host check.")


_LOAD_CALL = re.compile(r"(?<![\w$])(?P<fn>loadUrl|loadDataWithBaseURL)\s*\(")
_HTTPS_LIT = re.compile(r"\s*\"https://")
_ASSET_LIT = re.compile(r"\s*\"file:///android_(?:asset|res)/")
_LOCAL_LIT = re.compile(r"\s*\"(?:file|content):")
_CONFIG_URL = re.compile(r"\s*BuildConfig\s*\.\s*\w*(?:URL|Url|HOST|Host|ORIGIN|Origin)\w*\s*")


def _webview_loads(ctx: Context, code: str, blank: str) -> Set[str]:
    """What the WebView loads in this file, one kind per loadUrl / loadDataWithBaseURL call:
    https (a fixed https:// page), asset (file:///android_asset/), config (a BuildConfig URL), local
    (another file: or content: page, or HTML with a null or file: base URL), tainted (an intent or
    deep-link URL), or var (anything masaudit can't resolve). Empty when the file loads nothing."""
    consts = _string_constants(ctx)
    tainted = {m.group(1) for m in _STRING_ASSIGN.finditer(blank)
               if _URL_SOURCE.search(m.group(2)) and not _URL_CHECK.search(m.group(2))}
    kinds: Set[str] = set()
    for m in _sites(_LOAD_CALL.finditer(blank)):
        if _is_import(blank, m.start()) or re.search(r"\bfun\s+$|\bvoid\s+$", blank[max(0, m.start() - 12):m.start()]):
            continue          # a declaration, not a call
        spans = _args(blank, m.end() - 1)
        if not spans:
            continue
        first = code[spans[0][0]:spans[0][1]].strip()
        bare = blank[spans[0][0]:spans[0][1]].strip()
        cm = re.fullmatch(r"(?:[\w.]+\.)?([A-Z][A-Z0-9_]*)", first)
        if cm and cm.group(1) in consts:
            first = "\"" + consts[cm.group(1)] + "\""
        if re.match(r"\s*\"(?:about:blank|javascript:)", first):
            continue          # an empty page, or a script run in the page already loaded
        if m.group("fn") == "loadDataWithBaseURL" and (first == "null" or _LOCAL_LIT.match(first)):
            kinds.add("local")
        elif _ASSET_LIT.match(first):
            kinds.add("asset")
        elif _LOCAL_LIT.match(first):
            kinds.add("local")
        elif _HTTPS_LIT.match(first):
            kinds.add("https")
        elif _CONFIG_URL.fullmatch(first):
            kinds.add("config")
        elif _URL_SOURCE.search(bare) or re.sub(r"!!|\.toString\(\)", "", bare).strip() in tainted:
            kinds.add("tainted")
        else:
            kinds.add("var")
    return kinds


def _browser_file(ctx: Context, path: str) -> bool:
    """A browser's own tab code: the app is a browser (category APP_BROWSER) and the file is named for it.
    Its WebView navigates to whatever URL the user types or another app sends."""
    def compute() -> bool:
        for _p, root in _manifests(ctx):
            for f in root.iter("intent-filter"):
                if "android.intent.category.APP_BROWSER" in manifest.names(f, "category"):
                    return True
        return False
    return bool(_memo(ctx, "browser_app", compute)) and "Browser" in path.rsplit("/", 1)[-1]


def _origin_kinds(ctx: Context, path: str, code: str, blank: str) -> Set[str]:
    kinds = _webview_loads(ctx, code, blank)
    if _browser_file(ctx, path):
        kinds.add("tainted")
    return kinds


# `webView.addJavascriptInterface(` or a bare call inside `webView.apply { }` or a WebView subclass.
_ADD_JS = re.compile(r"(?:\.|(?<![\w.$]))addJavascriptInterface\s*\(")
# What comes before a declaration (`fun addJavascriptInterface(`, `public void addJavascriptInterface(`).
_DECL_BEFORE = re.compile(r"(?:\bfun|\bvoid|\b(?!return\b|else\b|in\b|is\b)[A-Za-z_]\w*(?:<[^<>\n]*>)?\??)[ \t]+$")
_FIXED_ORIGINS = {"https", "asset", "config"}
# A host allowlist or an origin test on the page URL (reading webView.url alone isn't a check).
_ORIGIN_CHECK = re.compile(r"allowed(?:Domains|Hosts|Origins|Urls)|isAllowed\w*\(|\.host\s+(?:!)?in\b|\bhost\s*[!=]=|"
                           r"getHost\(\)\s*\.equals|originAllowList|\bisTrusted\w*\(|\bis\w*(?:Url|Domain|Origin|Host)\s*\(",
                           re.IGNORECASE)


@detector("android_js_bridge")
def js_bridge(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "addJavascriptInterface"):
        for m in _sites(_ADD_JS.finditer(blank)):
            if not m.group(0).startswith(".") and (
                    _is_import(blank, m.start())
                    or _DECL_BEFORE.search(blank, max(0, m.start() - 80), m.start())):
                continue          # a declaration or an override, not a call
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            obj = blank[spans[0][0]:spans[0][1]].strip()
            cm = re.match(r"(?:new\s+)?([A-Z]\w*)\s*\(", obj)
            where = [path]
            if cm:
                where += _class_index(ctx)[2].get(cm.group(1), [])
            checked = all(_ORIGIN_CHECK.search(ctx.code(p, False) or "") for p in where[1:]) if len(where) > 1 \
                else bool(text_memo(blank, ("origin_check",), lambda b=blank: _ORIGIN_CHECK.search(b)))
            line = ctx.line_of(blank, m.start())
            if checked:
                ctx.note_unknown(f"{path}:{line}: the JavaScript bridge appears to check the page origin in code; "
                                 "confirm every @JavascriptInterface method checks it.")
                continue
            kinds = text_memo(blank, ("origin_kinds", path),
                              lambda p=path, c=_code, b=blank: _origin_kinds(ctx, p, c, b))
            if kinds and kinds <= _FIXED_ORIGINS:
                yield _hit(ctx, path, line, "addJavascriptInterface exposes native methods to every frame in this "
                                            "WebView. It loads only fixed https or bundled pages, so an attacker needs "
                                            "a frame or script inside them.", severity="medium")
                continue
            yield _hit(ctx, path, line, "addJavascriptInterface exposes native methods to every frame in this WebView.")


_OVERRIDE_URL = re.compile(r"\bshouldOverrideUrlLoading\s*\(")
# Anything that inspects or compares the URL: its parts, a string test, or an allowlist helper.
_URL_INSPECT = re.compile(r"\.\s*(?:host|scheme|path|authority)\b|\bget(?:Host|Scheme|Path|Authority)\s*\(|startsWith|endsWith"
                          r"|\bcontains\s*\(|\bequals\s*\(|==|\bmatches\s*\(|\bin\b|[Aa]llow|[Tt]rust|[Ss]afe|[Dd]omain"
                          r"|[Ww]hitelist|[Bb]lacklist|[Dd]eny|[Bb]lock|[Oo]rigin|\bwhen\b|\bswitch\b|\bif\b")
_RETURN = re.compile(r"\breturn\b\s*([^;\n}]*)")


def _js_files(ctx: Context) -> List[str]:
    """Files that turn JavaScript on in a WebView."""
    return _memo(ctx, "js_files", lambda: [p for p, _c, b in _code_files(ctx, "avaScriptEnabled") if _JS_ON.search(b)])


@detector("android_webview_no_url_check")
def webview_no_url_check(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "shouldOverrideUrlLoading"):
        reported: Set[str] = set()          # one finding per class (the two overloads are one client)
        for m in _sites(_OVERRIDE_URL.finditer(blank)):
            head = blank[max(0, m.start() - 60):m.start()]
            if not re.search(r"\b(?:fun|boolean)\s*$", head):
                continue                          # a call (super.shouldOverrideUrlLoading), not the override
            close = _match(blank, m.end() - 1, "(", ")")
            after = re.match(r"\s*(?::\s*Boolean\s*)?(\{|=)", blank[close + 1:close + 40])
            if not after:
                continue
            if after.group(1) == "=":
                # The expression after `=`, which may start on the next line: `fun f(...)\n    = false`.
                start = close + 1 + after.end()
                end = blank.find("\n", start)
                body = blank[start:end if end >= 0 else len(blank)]
                if not body.strip() and end >= 0:            # `=` ends the line; the value is on the next one
                    nxt = blank.find("\n", end + 1)
                    body = blank[end + 1:nxt if nxt >= 0 else len(blank)]
                returns = [body]
            else:
                start = close + 1 + after.end() - 1
                body = blank[start:_match(blank, start, "{", "}") + 1]
                returns = [r.group(1) for r in _RETURN.finditer(body)]
            if not returns or _URL_INSPECT.search(body):
                continue
            values = {re.sub(r"\s+", "", r) for r in returns}
            loads_itself = bool(re.search(r"\.\s*loadUrl\s*\(", body))
            if not (values <= {"false"} or re.fullmatch(r"super\.shouldOverrideUrlLoading\(.*\)", "".join(values))
                    or (values <= {"true"} and loads_itself)):
                continue
            cls = _class_at(blank, m.start())
            if cls in reported:
                continue
            js = path in _js_files(ctx) or (cls and _memo(ctx, "js_ref:" + cls, lambda c=cls: any(
                re.search(r"\b" + re.escape(c) + r"\b", ctx.code(p, False) or "") for p in _js_files(ctx))))
            if not js:
                continue          # without JavaScript, a page the WebView navigates to can do much less
            reported.add(cls)
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "shouldOverrideUrlLoading lets the WebView open every URL without checking its host or scheme, "
                       "so a link or redirect can load any site into a WebView that runs JavaScript.")


_SAFE_BROWSING_OFF = re.compile(r"\bsetSafeBrowsingEnabled\s*\(\s*(?:[\w.]+\s*,\s*)?false\s*\)"
                                r"|\bsafeBrowsingEnabled\s*=\s*false\b")


@detector("android_safe_browsing_off")
def safe_browsing_off(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        for app in manifest.applications(root):
            for md in app.children:
                if md.tag != "meta-data" or md.get("android:name") != "android.webkit.WebView.EnableSafeBrowsing":
                    continue
                value = md.get("android:value")
                if manifest.is_placeholder(value):
                    ctx.note_unknown(f"{path}: WebView Safe Browsing is set from a placeholder.")
                elif (value or "").strip().lower() == "false":
                    yield _hit(ctx, path, md.line, "The manifest turns off WebView Safe Browsing for the whole app.")
    for path, _code, blank in _code_files(ctx, "afeBrowsingEnabled"):
        for m in _SAFE_BROWSING_OFF.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()), "This WebView has Safe Browsing turned off.")


_JS_ON = re.compile(r"\bsetJavaScriptEnabled\s*\(\s*true\s*\)|\bjavaScriptEnabled\s*=\s*true\b")
_CONTENT_OFF = re.compile(r"\bsetAllowContentAccess\s*\(\s*false\s*\)|\ballowContentAccess\s*=\s*false\b")


_FILE_ACCESS_ON = re.compile(r"\b(?:setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)"
                             r"\s*\(\s*true\s*\)|\b(?:allowFileAccess|allowFileAccessFromFileURLs|"
                             r"allowUniversalAccessFromFileURLs)\s*=\s*true\b")
_FILE_URL_ACCESS_ON = re.compile(r"\b(?:setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)\s*\(\s*true"
                                 r"\s*\)|\b(?:allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)\s*=\s*true\b")


@detector("android_webview_content_access")
def webview_content_access(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "avaScriptEnabled"):
        if _CONTENT_OFF.search(blank):
            continue
        sites = list(_JS_ON.finditer(blank))
        if not sites:
            continue
        kinds = _origin_kinds(ctx, path, code, blank)
        # content:// is a local scheme: a web page can't load it. Only a file: or content: page, or a WebView
        # that opens URLs other apps or the user choose, can reach the app's providers.
        local = bool(kinds & {"local", "asset", "tainted"}) or bool(_FILE_ACCESS_ON.search(blank))
        for m in sites:
            if local:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "This WebView runs JavaScript and keeps content:// access on (the default), and it loads "
                           "local or outside URLs, so a page script can read content providers the app can open.")
            else:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "This WebView runs JavaScript and keeps content:// access on (the default). It loads only "
                           "web pages, which can't open content:// URLs, so turn it off as hardening.", severity="low")


@detector("android_webview_file_access")
def webview_file_access(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "llow"):
        sites = list(_FILE_ACCESS_ON.finditer(blank))
        if not sites:
            continue
        kinds = _origin_kinds(ctx, path, code, blank)
        for m in sites:
            line = ctx.line_of(blank, m.start())
            from_file = bool(_FILE_URL_ACCESS_ON.match(m.group(0)))
            if from_file and kinds & {"local", "tainted"}:
                yield _hit(ctx, path, line, "This WebView lets file:// pages read other local files, and it loads "
                                            "file:// pages or outside URLs, so such a page can read the app's private "
                                            "files.")
            elif kinds & {"local", "asset", "tainted"}:
                yield _hit(ctx, path, line, "This WebView setting lets page content read local files, and the WebView "
                                            "loads local pages.", severity="medium")
            else:
                yield _hit(ctx, path, line, "This WebView setting lets page content read local files. The WebView loads "
                                            "only web pages here, so turn it off as hardening.", severity="low")
    yield from _default_file_access(ctx)


_FILE_ACCESS_OFF = re.compile(r"\bsetAllowFileAccess\s*\(\s*false\s*\)|\ballowFileAccess\s*=\s*false\b")
_SHARED_DIR = re.compile(r"\bgetExternalStorage(?:Public)?Directory\s*\(|\bexternalStorageDirectory\b|"
                         r"\bgetExternalFilesDir\s*\(|\bexternalCacheDir\b|\bgetExternalCacheDir\s*\(|\"/sdcard/")


def _default_file_access(ctx: Context) -> Iterator[Hit]:
    """File access is on by default for apps targeting API 29 or lower. A WebView that runs JavaScript and loads a
    file:// page from shared storage (which other apps can write), or a URL the user types, can then read local
    files without any setAllowFileAccess(true) call."""
    target: Optional[int] = None
    checked = False
    for path, code, blank in _code_files(ctx, "loadUrl"):
        if not _JS_ON.search(blank) or _FILE_ACCESS_ON.search(blank) or _FILE_ACCESS_OFF.search(blank):
            continue
        if not checked:
            target, checked = _sdk_value(ctx, "targetSdk"), True
        if target is not None and target > 29:
            return
        for m in _sites(_LOAD_URL.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            first = code[spans[0][0]:spans[0][1]].strip()
            if first.startswith("\"file:") and _SHARED_DIR.search(first):
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "This WebView runs JavaScript on a file:// page in shared storage, which other apps can "
                           "write, and file access is on by default (targetSdk 29 or lower), so that page can read "
                           "the app's local files.")
            elif target is not None and _TYPED_TEXT.search(first) and \
                    re.fullmatch(r"[\w.]+(?:\s*\(\s*\))?\s*\.\s*toString\s*\(\s*\)", first):
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "This WebView runs JavaScript and loads whatever URL the user types, and file access is on "
                           f"by default (targetSdk {target}), so a file:// URL can open the app's private files.",
                           severity="medium")


# ---------------------------------------------------------------------------- components and IPC

_FRAMEWORK_ACTION = re.compile(r"^(?:android\.|androidx\.|com\.google\.android\.gms\.|com\.google\.android\.c2dm\.)")
# Broadcasts only the system can send (frameworks/base core/res AndroidManifest <protected-broadcast>).
_PROTECTED_BROADCASTS = frozenset({f"android.intent.action.{a}" for a in (
    "BOOT_COMPLETED LOCKED_BOOT_COMPLETED MY_PACKAGE_REPLACED MY_PACKAGE_SUSPENDED MY_PACKAGE_UNSUSPENDED "
    "ACTION_POWER_CONNECTED ACTION_POWER_DISCONNECTED BATTERY_LOW BATTERY_OKAY BATTERY_CHANGED DEVICE_STORAGE_LOW "
    "DEVICE_STORAGE_OK TIMEZONE_CHANGED TIME_SET DATE_CHANGED LOCALE_CHANGED ACTION_SHUTDOWN REBOOT USER_PRESENT "
    "SCREEN_ON SCREEN_OFF PACKAGE_ADDED PACKAGE_REMOVED PACKAGE_REPLACED PACKAGE_FULLY_REMOVED PACKAGE_CHANGED "
    "PACKAGE_DATA_CLEARED PACKAGES_SUSPENDED PACKAGES_UNSUSPENDED DOWNLOAD_COMPLETE DOWNLOAD_NOTIFICATION_CLICKED "
    "AIRPLANE_MODE NEW_OUTGOING_CALL TIME_TICK UID_REMOVED USER_UNLOCKED CONFIGURATION_CHANGED "
    "APPLICATION_RESTRICTIONS_CHANGED DREAMING_STARTED DREAMING_STOPPED HEADSET_PLUG MEDIA_MOUNTED "
    "MEDIA_UNMOUNTED MEDIA_REMOVED MEDIA_EJECT MEDIA_SCANNER_FINISHED PHONE_STATE PROXY_CHANGE "
    "EXTERNAL_APPLICATIONS_AVAILABLE EXTERNAL_APPLICATIONS_UNAVAILABLE").split()} | {
    "android.net.conn.CONNECTIVITY_CHANGE", "android.net.wifi.STATE_CHANGE", "android.net.wifi.WIFI_STATE_CHANGED",
    "android.net.wifi.SCAN_RESULTS", "android.app.action.NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED",
    "android.app.action.NOTIFICATION_CHANNEL_GROUP_BLOCK_STATE_CHANGED", "android.app.action.APP_BLOCK_STATE_CHANGED",
    "android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED", "android.app.action.DEVICE_ADMIN_ENABLED",
    "android.app.action.INTERRUPTION_FILTER_CHANGED", "android.app.action.NEXT_ALARM_CLOCK_CHANGED",
    "android.appwidget.action.APPWIDGET_ENABLED", "android.appwidget.action.APPWIDGET_DISABLED",
    "android.appwidget.action.APPWIDGET_DELETED", "android.appwidget.action.APPWIDGET_UPDATE_OPTIONS",
    "android.appwidget.action.APPWIDGET_RESTORED", "android.bluetooth.adapter.action.STATE_CHANGED",
    "android.bluetooth.device.action.ACL_CONNECTED", "android.bluetooth.device.action.ACL_DISCONNECTED",
    "android.media.AUDIO_BECOMING_NOISY", "android.os.action.POWER_SAVE_MODE_CHANGED",
    "android.os.action.DEVICE_IDLE_MODE_CHANGED", "android.hardware.usb.action.USB_STATE",
    "android.provider.action.DEFAULT_SMS_PACKAGE_CHANGED"})
# Receivers whose job is to take these from other apps (media buttons, launcher widgets), and vendor boot
# broadcasts that stand in for BOOT_COMPLETED on some devices.
_RECEIVER_PUBLIC = frozenset({"android.intent.action.MEDIA_BUTTON", "android.appwidget.action.APPWIDGET_UPDATE",
                              "android.intent.action.QUICKBOOT_POWERON", "com.htc.intent.action.QUICKBOOT_POWERON"})
# Cross-app protocols whose actions other apps are meant to send: Autocrypt, PanicKit, UnifiedPush (the
# distributor app delivers messages; the registration token authenticates them).
_PUBLIC_INTEROP = frozenset({"org.autocrypt.PEER_ACTION", "info.guardianproject.panic.action.TRIGGER"})
_PUBLIC_INTEROP_PREFIX = ("org.unifiedpush.android.connector.",)
# Custom receiver actions that only refresh what a widget, media session or poll shows.
_LOW_IMPACT_ACTION = re.compile(r"(?i)widget|media|playback|player|poll")
# A provider that checks who is calling, in code.
_CALLER_CHECK = re.compile(r"\bgetCallingPackage\s*\(|\bcallingPackage\b|\bBinder\s*\.\s*getCallingUid\s*\(|"
                           r"\bcheckCallingPermission\s*\(|\benforceCalling\w*Permission\s*\(|\bgetCallingActivity\s*\(|"
                           r"\bcheckCallingOrSelfPermission\s*\(")
_STD_SCHEMES = {"http", "https", "content", "file", "mailto", "tel", "sms", "smsto", "mms", "mmsto", "geo", "market",
                "data", "about", "rtsp", "ftp"}
_SMS_RECEIVED = "android.provider.Telephony.SMS_RECEIVED"


def _private_surface(c: Element) -> Tuple[List[str], bool]:
    """Why an exported component exposes something app-specific, or [] if it only serves public
    platform contracts (share target, widget, media session, launcher shortcut, sync adapter ...).
    The flag is True when the only reason is a custom action of lower impact: one next to public
    intent filters, or a receiver's widget, media or poll action."""
    filters = manifest.intent_filters(c)
    if not filters:
        return ["it has no intent filter, so any app can start it by its class name"], False
    out: List[str] = []
    public = False
    for f in filters:
        acts, cats = manifest.names(f, "action"), manifest.names(f, "category")
        if c.tag == "receiver":
            custom = [a for a in acts if a and a not in _PROTECTED_BROADCASTS and a not in _RECEIVER_PUBLIC
                      and not a.startswith("android.appwidget.action.")]
        else:
            custom = [a for a in acts if a and not _FRAMEWORK_ACTION.match(a)]
        custom = [a for a in custom if a not in _PUBLIC_INTEROP and not a.startswith(_PUBLIC_INTEROP_PREFIX)]
        if len(custom) < len([a for a in acts if a]):
            public = True
        out += custom
        if c.tag in ("activity", "activity-alias") and "android.intent.action.VIEW" in acts \
                and "android.intent.category.BROWSABLE" not in cats:
            data = manifest.data_attrs(f)
            schemes = {(d.get("android:scheme") or "").lower() for d in data} - {""}
            private = sorted(s for s in schemes if s not in _STD_SCHEMES and not s.startswith(("@", "$")))
            if private and not any(d.get("android:mimeType") for d in data):
                out.append(f"VIEW intents for the private scheme {', '.join(p + ':' for p in private)}")
    if c.tag == "service" and public:
        # A service serving a public contract (MediaBrowserService, MediaSessionService ...) is already
        # reachable by its component name; an extra custom action adds no surface.
        return [], False
    reasons = []
    actions = [a for a in out if not a.startswith("VIEW intents")]
    if actions:
        shown = ", ".join(sorted(set(actions))[:3]) + (", ..." if len(set(actions)) > 3 else "")
        reasons.append(f"accepts the app-specific action{'s' if len(set(actions)) > 1 else ''} {shown}"
                       + (" next to its public intent filters" if public else ""))
    views = [a for a in out if a.startswith("VIEW intents")]
    reasons += views
    low = bool(actions) and not views and (
        public or (c.tag == "receiver" and all(_LOW_IMPACT_ACTION.search(a) for a in actions)))
    return reasons, low


def _launcher_targets(root: Element) -> Set[str]:
    out: Set[str] = set()
    for a in manifest.components(root, ("activity-alias",)):
        if manifest.is_launcher(a) and a.get("android:targetActivity"):
            out.add(_simple(a.get("android:targetActivity") or ""))
    return out


_LINT_EXPORTED = {"service": "ExportedService", "receiver": "ExportedReceiver", "provider": "ExportedContentProvider",
                  "activity": "ExportedActivity", "activity-alias": "ExportedActivity"}


@detector("android_exported")
def exported_components(ctx: Context, rule: Rule) -> Iterable[Hit]:
    declared = _declared_permissions(ctx)
    _subs, sup_of, _files = _class_index(ctx)
    for path, root in _manifests(ctx):
        launcher_targets = _launcher_targets(root)
        app_perm = next((a.get("android:permission") for a in manifest.applications(root)
                         if a.get("android:permission")), None)
        for c in manifest.components(root):
            name = c.get("android:name") or c.tag
            exported = c.get("android:exported")
            if manifest.is_placeholder(exported):
                ctx.note_unknown(f"{path}: {name} sets android:exported from a placeholder.")
                continue
            sms = False
            severity = ""
            if c.tag == "provider":
                if not xmlsafe.is_true(exported):
                    continue
                if any(ch.tag == "path-permission" for ch in c.children):
                    continue
                chain, k = [], _simple(name)
                while k in sup_of and len(chain) < 6:
                    k = sup_of[k]
                    chain.append(k)
                if "SliceProvider" in chain:
                    continue          # the slice framework enforces its own grant checks
                perm_attrs = [c.get(a) for a in ("android:permission", "android:readPermission",
                                                 "android:writePermission") if c.get(a)]
                why = ["any app can read or change its data"]
                if any(_CALLER_CHECK.search(ctx.code(p, False) or "") for p in _files.get(_simple(name), [])):
                    why = ["its code checks the calling app, so verify that check covers every operation"]
                    severity = "low"
            else:
                filters = manifest.intent_filters(c)
                is_exported = xmlsafe.is_true(exported) if exported is not None else bool(filters)
                if not is_exported:
                    continue
                if c.tag in ("activity", "activity-alias") and (
                        manifest.is_launcher(c) or manifest.is_browsable_only(c)
                        or (c.tag == "activity" and _simple(name) in launcher_targets)):
                    continue
                perm_attrs = [c.get("android:permission")] if c.get("android:permission") else []
                sms = c.tag == "receiver" and any(_SMS_RECEIVED in manifest.names(f, "action") for f in filters)
                why, low = _private_surface(c)
                if not why:
                    continue          # it only serves public platform contracts
                if low and not sms:
                    severity = "medium"
            if not perm_attrs and app_perm:
                perm_attrs = [app_perm]
            ack = _ack(ctx, path, c, _LINT_EXPORTED[c.tag])
            if perm_attrs:
                strengths = set()
                for perm in perm_attrs:
                    if manifest.is_placeholder(perm):
                        strengths.add("unknown")
                    else:
                        strengths.add(_permission_strength((perm or "").strip(), declared))
                if strengths != {"weak"}:
                    continue
                msg = f"{name} is exported and protected only by a permission any app can request."
            elif sms:
                msg = (f"The receiver {name} handles SMS_RECEIVED without android:permission="
                       "\"android.permission.BROADCAST_SMS\", so any app can send it fake text messages.")
            else:
                how = "exported" if exported is not None else "exported (it has an intent filter)"
                msg = f"The {c.tag} {name} is {how} with no permission: " + "; ".join(why) + "."
            yield _hit(ctx, path, c.line, msg, ack=ack, severity=severity)


def _referenced_xml(ctx: Context, meta_name: str) -> Set[str]:
    out: Set[str] = set()
    for _path, root in _manifests(ctx):
        for c in manifest.components(root, ("provider",)):
            for md in c.children:
                if md.tag == "meta-data" and md.get("android:name") == meta_name:
                    res = (md.get("android:resource") or "").strip()
                    if res.startswith("@xml/"):
                        out.add(res[5:])
    return out


_EXTERNAL_PATHS = {"external-path", "external-cache-path", "external-media-path", "external-files-path"}


@detector("android_file_provider_paths")
def file_provider_paths(ctx: Context, rule: Rule) -> Iterable[Hit]:
    referenced = _referenced_xml(ctx, "android.support.FILE_PROVIDER_PATHS")
    for path, root in _res_xml(ctx, "paths"):
        if referenced and path.rsplit("/", 1)[-1][:-4] not in referenced:
            continue
        for el in root.children:
            raw = el.get("path") or ""
            p = re.sub(r"^(?:\./?|/+)", "", raw.strip()).rstrip("/")
            p = "" if p == "." else p
            if el.tag == "root-path":
                if re.match(r"(?:storage|sdcard|mnt)(?:/|$)", p):
                    yield _hit(ctx, path, el.line, f"<root-path path=\"{raw}\"> shares /{p} and every file under it "
                                                   "(lower impact: shared storage isn't private to the app).",
                               severity="medium")
                elif p:
                    yield _hit(ctx, path, el.line, f"<root-path path=\"{raw}\"> shares /{p} and every file under it.")
                else:
                    yield _hit(ctx, path, el.line, "<root-path> shares the whole device filesystem.")
            elif p == "" and el.tag in _EXTERNAL_PATHS:
                yield _hit(ctx, path, el.line,
                           f"<{el.tag} path=\"{raw}\"> shares an entire external storage directory (lower impact: "
                           "files there aren't private to the app).", severity="medium")
            elif p == "" and el.tag in ("files-path", "cache-path"):
                yield _hit(ctx, path, el.line,
                           f"<{el.tag} path=\"{raw}\"> shares the app's whole private {el.tag[:-5]} directory.")


_START = re.compile(r"\b(?:startActivit(?:y|yForResult|ies)|startService|startForegroundService|sendBroadcast"
                    r"|bindService)\s*\(")
_PARCEL = re.compile(r"getParcelableExtra|getParcelable\s*\(")
_APP_BUNDLE = re.compile(r"requireArguments\s*\(|\bgetArguments\s*\(|\barguments\b|savedInstanceState")
_INTENT_ASSIGN = re.compile(
    r"(?P<decl>(?:\bval|\bvar|\bfinal\s+Intent|\bIntent)\s+(?P<name>\w+)\s*(?::\s*Intent\??)?)\s*=\s*(?P<rhs>[^;\n]*)")


@detector("android_intent_redirect")
def intent_redirect(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "getParcelable"):
        if "IntentSanitizer" in blank:
            continue
        installer = "EXTRA_STATUS" in blank and "PackageInstaller" in blank
        nested: Set[str] = set()
        for m in _INTENT_ASSIGN.finditer(blank):
            rhs = code[m.start("rhs"):m.end("rhs")]
            typed = "Intent" in m.group("decl") or re.search(r"Intent::class|<Intent>|\(Intent\)|as\??\s+Intent", rhs)
            if _PARCEL.search(rhs) and typed and not _APP_BUNDLE.search(rhs):
                if installer and "EXTRA_INTENT" in rhs:
                    continue      # PackageInstaller's STATUS_PENDING_USER_ACTION confirmation intent
                nested.add(m.group("name"))
        for m in _sites(_START.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            first = blank[spans[0][0]:spans[0][1]]
            first_code = code[spans[0][0]:spans[0][1]]
            name = re.fullmatch(r"\s*(\w+)\s*(?:!!)?\s*", first)
            direct = _PARCEL.search(first) and not _APP_BUNDLE.search(first_code) and not (
                installer and "EXTRA_INTENT" in first_code)
            if direct or (name and name.group(1) in nested):
                if not _exposed(ctx, path, blank, m.start(), "an Intent from another Intent's extras is started"):
                    continue
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line, "An Intent taken from another Intent's extras is started as this app.")


_WEB_SCHEMES = {"http", "https"}
_TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz",
                       "co.in", "co.za", "com.br", "com.mx", "com.tr", "com.sg", "com.cn", "com.hk", "com.tw",
                       "com.eg", "com.sa", "com.ar", "co.kr", "co.id", "com.my", "com.ng", "com.pk", "co.il",
                       "com.ua", "com.pl", "co.th", "com.vn", "com.ph", "co.ke", "com.co", "com.pe"}


def _registrable_label(host: str) -> str:
    labels = [x for x in host.lower().lstrip("*.").split(".") if x]
    if len(labels) < 2:
        return labels[0] if labels else ""
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def _own_host(host: str, tokens: Set[str]) -> bool:
    label = _registrable_label(host)
    if not label:
        return False
    return any(label == t or (len(t) >= 4 and (t in label or label in t)) for t in tokens)


@detector("android_app_links")
def app_links(ctx: Context, rule: Rule) -> Iterable[Hit]:
    tokens = _identity_tokens(ctx)
    for path, root in _manifests(ctx):
        for c in manifest.components(root, ("activity", "activity-alias")):
            for f in manifest.intent_filters(c):
                if ("android.intent.action.VIEW" not in manifest.names(f, "action")
                        or "android.intent.category.BROWSABLE" not in manifest.names(f, "category")):
                    continue
                data = manifest.data_attrs(f)
                values = [d.get(k) for d in data for k in ("android:scheme", "android:host")]
                auto = f.get("android:autoVerify")
                if any(manifest.is_placeholder(v) for v in values + [auto]):
                    ctx.note_unknown(f"{path}: an App Link intent filter uses a placeholder.")
                    continue
                schemes = {(d.get("android:scheme") or "").lower() for d in data}
                hosts = [d.get("android:host") or "" for d in data if d.get("android:host")]
                if not (schemes & _WEB_SCHEMES and hosts) or xmlsafe.is_true(auto):
                    continue
                own = [h for h in hosts if _own_host(h, tokens)] if tokens else hosts
                if not own:
                    ctx.note_unknown(f"{path}:{f.line}: {c.get('android:name')} handles web links for "
                                     f"{', '.join(hosts[:3])}{', ...' if len(hosts) > 3 else ''} without verification; "
                                     "that's expected if the app doesn't own these domains.")
                    continue
                yield _hit(ctx, path, f.line,
                           f"Web links for {', '.join(own)} open {c.get('android:name')} without "
                           "android:autoVerify, so another app can claim them.",
                           ack=_ack(ctx, path, f, "AppLinksAutoVerify", "AppLinkUrlError"))
    expo = _managed_expo(ctx)
    if expo is not None:
        yield from _expo_app_links(ctx, expo)


def _expo_app_links(ctx: Context, expo: "rn_expo.ExpoApp") -> Iterator[Hit]:
    """expo.android.intentFilters: prebuild adds each one to the main activity."""
    filters = expo.get("android", "intentFilters")
    if not isinstance(filters, list):
        return
    package = expo.get("android", "package")
    tokens = {t for t in package.lower().split(".") if len(t) >= 3 and t not in _GENERIC_LABELS} \
        if isinstance(package, str) else set()
    for i, f in enumerate(filters):
        if not isinstance(f, dict):
            continue
        actions = f.get("action") if isinstance(f.get("action"), list) else [f.get("action")]
        categories = f.get("category") if isinstance(f.get("category"), list) else [f.get("category")]
        if not any(a in ("VIEW", "android.intent.action.VIEW") for a in actions) or \
                not any(c in ("BROWSABLE", "android.intent.category.BROWSABLE") for c in categories):
            continue
        data = f.get("data") if isinstance(f.get("data"), list) else [f.get("data")]
        data = [d for d in data if isinstance(d, dict)]
        schemes = {str(d.get("scheme", "")).lower() for d in data}
        hosts = [str(d["host"]) for d in data if isinstance(d.get("host"), str) and d.get("host")]
        if not (schemes & _WEB_SCHEMES and hosts) or f.get("autoVerify") is True:
            continue
        own = [h for h in hosts if _own_host(h, tokens)] if tokens else hosts
        if not own:
            ctx.note_unknown(f"{expo.path}: intent filter {i + 1} handles web links for {', '.join(hosts[:3])} "
                             "without verification; that's expected if the app doesn't own these domains.")
            continue
        line = expo.line("android", "intentFilters", "host")
        for h in own[:1]:
            m = re.search(r"[\"']host[\"']?\s*:\s*[\"']" + re.escape(h) + r"[\"']", expo.text)
            if m:
                line = expo.text.count("\n", 0, m.start()) + 1
        yield _hit(ctx, expo.path, line, f"Web links for {', '.join(own)} open the app without autoVerify in "
                                         "android.intentFilters, so another app can claim them.")


# ---------------------------------------------------------------------------- SQL

_SQL_CALL = re.compile(r"\b(?:rawQuery|execSQL)\s*\(")
_DDL_START = re.compile(r"^\s*(?:CREATE|DROP|ALTER|PRAGMA|ANALYZE|REINDEX|VACUUM)\b", re.IGNORECASE)
_IDENT_CTX = re.compile(r"(?:\bFROM|\bINTO|\bUPDATE|\bTABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?|\bINDEX(?:\s+IF\s+(?:NOT\s+)?"
                        r"EXISTS)?|\bTRIGGER(?:\s+IF\s+(?:NOT\s+)?EXISTS)?|\bVIEW|\bJOIN|\bON|\bANALYZE|\bRENAME\s+TO"
                        r"|\bCOLUMN|\bSET|\bBY|\bSELECT|\bWHERE|\bAND|\bOR|\bNOT|\bEXISTS|\bDISTINCT|\bAS|\bWHEN|\bCASE"
                        r"|\bTHEN|\bELSE|[.(*`])\s*$", re.IGNORECASE)
_VALUE_CTX = re.compile(r"(?:[=<>]|\bLIKE|\bGLOB|\bMATCH|\bIS|\bDEFAULT|\bLIMIT|\bOFFSET|\bBETWEEN)\s*$", re.IGNORECASE)
_NUMERIC_TOKENS = {"id", "ids", "index", "count", "size", "limit", "offset", "timestamp", "time", "millis", "ms",
                   "version", "position", "year", "month", "day", "days", "length", "rank", "num", "number", "total",
                   "max", "min", "age", "hours", "seconds", "minutes", "pos", "idx", "level", "type", "flags", "code",
                   "date", "sent", "received", "expiration", "expires", "duration", "ttl", "timeout", "delay", "i",
                   "j", "k", "n"}
_FRAGMENT_NAME = re.compile(r"(?i)where|clause|selection|select|query|sql|placeholder|columns|projection|fragment"
                            r"|subquery|condition|filter|order|join|statement|types$|set$")
_CONST_TERM = r"(?:\"[^\"\n]*\"|(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*)"
# Output that can't contain a quote: Base64, hex, UUIDs.
_QUOTE_FREE = re.compile(r"Base64\s*\.\s*encode\w*\s*\(|encodeToString\s*\(|toHexString\s*\(|\.toHex\w*\(|randomUUID\(\)")


def _sql_is_constant(expr: str, code: str, blank: str = "", idx: int = -1) -> bool:
    e = expr.strip().rstrip("!").strip()
    if re.fullmatch(r"0[xX][0-9A-Fa-f_]+L?|\d[\d_]*L?|\"[^\"\n]*\"|true|false|null", e):
        return True
    if _QUOTE_FREE.search(e):
        return True
    # (flag) ? "1" : "0"   /   if (flag) "1" else "0"
    if len(e) < 300 and re.fullmatch(r"\(*.*?(?:\?|\bif\b[^\"]*\))\s*" + _CONST_TERM + r"\s*(?::|\belse\b)\s*" + _CONST_TERM + r"\s*\)*",
                    e, re.DOTALL):
        return True
    bare = re.sub(r"\(\)$", "", e)
    if not re.fullmatch(r"(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*(?:\(\))?", e):
        return False
    segs = bare.split(".")
    if any(re.fullmatch(r"[A-Z][A-Z0-9_]*(?:_v\d+)?", s) for s in segs):
        return True                           # CONST, Enum.CONST.code, X.TABLE_NAME
    if len(segs) >= 2 and segs[-1] in ("name", "code", "id", "value", "ordinal", "serialize", "tableName", "TABLE") \
            and re.fullmatch(r"[A-Z]\w*", segs[0]):
        return True
    m = re.search(r"\b(?:const\s+val|val|var|String|final\s+String)\s+" + re.escape(segs[-1]) +
                  r"\s*(?::\s*String\s*)?=\s*((?:\"[^\"\n]*\"|[^;\n\"]|\+[ \t]*\n)+)", code)
    if m and re.fullmatch(r"(?:\s*" + _CONST_TERM + r"\s*\+?)+\s*", m.group(1)):
        return True
    if m and len(segs) == 1:
        # val prefix = uidPrefixProvider.get(): a value an injected configuration object supplies
        pm = re.fullmatch(r"\s*(\w+)\s*\.\s*get\w*\(\s*\)\s*", m.group(1))
        if pm and re.search(r"\b" + re.escape(pm.group(1)) + r"\s*:\s*\w*Provider\b|\b\w*Provider(?:<[^>]{0,200}>)?\s+"
                            + re.escape(pm.group(1)) + r"\b", code):
            return True
    if len(segs) == 1 and blank and idx >= 0:
        return _param_constant(segs[0], code, blank, idx)
    return False


def _param_constant(name: str, code: str, blank: str, idx: int) -> bool:
    """`name` is a parameter of the function around idx, and every call in this file passes a constant."""
    lo, _hi, fn = _function_at(blank, idx)
    # an expression-bodied Kotlin function (`fun f(x: String) = db.rawQuery(...)`) has no braces of its own
    expr_fun = None
    for fm in _FUN_HEAD.finditer(blank, lo, idx):
        expr_fun = fm
    if expr_fun is not None:
        close = _match(blank, expr_fun.end() - 1, "(", ")")
        if close < idx and re.match(r"\s*(?::\s*[\w.<>?, ]+)?\s*=", blank[close + 1:idx]):
            fn, head_open = expr_fun.group("name"), expr_fun.end() - 1
            lo = close + 1
    if not fn:
        return False
    heads = list(re.finditer(r"\b" + re.escape(fn) + r"\s*\(", blank[:lo]))
    if not heads:
        return False
    head_open = heads[-1].end() - 1
    params = [code[s:e].strip() for s, e in _args(blank, head_open)]
    pos = next((i for i, p in enumerate(params) if re.match(r"(?:\w+\s+)*" + re.escape(name) + r"\s*:|"
                                                           r"(?:final\s+)?\w[\w<>\[\]]*\s+" + re.escape(name) + r"$",
                                                           p)), None)
    if pos is None:
        return False
    calls = 0
    for m in re.finditer(r"(?<![\w.])" + re.escape(fn) + r"\s*\(", blank):
        if m.end() - 1 == head_open:
            continue
        args = [code[s:e].strip() for s, e in _args(blank, m.end() - 1)]
        named = [a.split("=", 1)[1].strip() for a in args if re.match(re.escape(name) + r"\s*=", a)]
        value = named[0] if named else (args[pos] if pos < len(args) else None)
        if value is None or not re.fullmatch(_CONST_TERM, value):
            return False
        calls += 1
    return calls > 0


def _sql_is_numeric(expr: str, code: str = "") -> bool:
    e = expr.strip().rstrip("!").strip()
    if code and re.fullmatch(r"\w+", e):
        if re.search(r"\b" + re.escape(e) + r"\s*:\s*(?:String|CharSequence)\b|\b(?:String|CharSequence)\s+"
                     + re.escape(e) + r"\b", code):
            return False                      # declared as text, whatever its name says
        if re.search(r"\b(?:val|var)\s+" + re.escape(e) + r"\s*=\s*[^\n;]*(?:lastPathSegment|getLastPathSegment\s*\(|"
                     r"pathSegments|getQueryParameter\s*\(|getStringExtra\s*\()", code):
            return False                      # assigned text from a URI or an intent
        if re.search(r"\b" + re.escape(e) + r"\s*:\s*(?:Int|Long|Short|Byte|Double|Float|Boolean)\b|\b(?:int|long|short|"
                     r"byte|double|float|boolean|Integer|Long)\s+" + re.escape(e) + r"\b", code):
            return True
    if re.fullmatch(r"-?\d[\d_]*L?|0[xX][0-9A-Fa-f_]+L?", e):
        return True
    if re.search(r"[-+*/%]", re.sub(r"\([^()]*\)", "", e)) and '"' not in e:
        return True
    if re.search(r"\.(?:size|length|count|ordinal)\b(?:\(\))?$|\.to(?:Int|Long|Short|Byte)\(\)$|currentTimeMillis|"
                 r"nanoTime|\b(?:Long|Integer|Int)\.(?:toString|valueOf)\(|randomUUID\(\)|\.year\b|getTime\(\)$|"
                 r"\.time\b|\.inWholeMilliseconds|epochSecond|toEpochMilli|\.hashCode\(\)", e):
        return True
    wrapped = re.fullmatch(r"(?:[A-Z]\w*\()?([\w.]+)\)?\.(?:serialize|toString|toLong|toInt)\(\)", e)
    if wrapped and wrapped.group(1) != e:
        return _sql_is_numeric(wrapped.group(1), code)
    if "\"" in e:
        return False
    last = re.split(r"[.(]", e.rstrip(")"))[-1] if e else ""
    tokens = _camel(re.sub(r"[^\w]", "", last))
    return bool(tokens) and tokens[-1] in _NUMERIC_TOKENS


def _sql_pieces(code: str, a: int, b: int, kotlin: bool) -> List[Tuple[str, str]]:
    """Split a SQL argument into literal text and interpolated expressions, in order."""
    out: List[Tuple[str, str]] = []

    def literal_end(i: int) -> Tuple[int, int, int]:
        """(content start, content end, index after the literal) for the string literal at i."""
        if code.startswith('"""', i):
            end = code.find('"""', i + 3)
            end = b if end == -1 or end > b else end
            return i + 3, end, end + 3
        j = i + 1
        while j < b and code[j] != '"' and code[j] != "\n":
            j += 2 if code[j] == "\\" else 1
        return i + 1, j, j + 1

    def flush(start: int, end: int) -> None:
        """Split code[start:end] (between top-level literals) into `+` operands."""
        depth, k, part = 0, start, start
        while k < end:
            ch = code[k]
            if ch == '"':
                k = literal_end(k)[2]
                continue
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "+" and depth == 0:
                p = code[part:k].strip()
                if p and p not in (")", "("):
                    out.append(("expr", p))
                part = k + 1
            k += 1
        p = code[part:end].strip()
        if p and p not in (")", "("):
            out.append(("expr", p))

    i, depth, expr_start = a, 0, a
    while i < b:
        c = code[i]
        if c == '"':
            s, e, after = literal_end(i)
            if depth == 0:            # a literal inside a call or a ternary belongs to that expression
                flush(expr_start, i)
                out.extend(_template_pieces(code[s:e], kotlin))
                expr_start = after
            i = after
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        i += 1
    flush(expr_start, b)
    return out


def _template_pieces(lit: str, kotlin: bool) -> List[Tuple[str, str]]:
    if not kotlin:
        return [("lit", lit.replace('\\"', '"'))]
    out: List[Tuple[str, str]] = []
    i, start = 0, 0
    while i < len(lit):
        if lit[i] == "\\":
            i += 2
            continue
        if lit[i] == "$" and i + 1 < len(lit):
            if lit[i + 1] == "{":
                end = _match(lit, i + 1, "{", "}")
                out.append(("lit", lit[start:i].replace('\\"', '"')))
                out.append(("expr", lit[i + 2:end]))
                i = start = end + 1
                continue
            m = re.match(r"[A-Za-z_]\w*", lit[i + 1:])
            if m:
                out.append(("lit", lit[start:i].replace('\\"', '"')))
                out.append(("expr", m.group(0)))
                i = start = i + 1 + m.end()
                continue
        i += 1
    out.append(("lit", lit[start:].replace('\\"', '"')))
    return out


def _quote_open(sql: str) -> bool:
    """Does the SQL text so far end inside a quoted string?"""
    q = ""
    for ch in sql:
        if q:
            if ch == q:
                q = ""
        elif ch in ("'", '"'):
            q = ch
    return bool(q)


def _in_value_list(sql: str) -> bool:
    depth_stack = []
    for m in re.finditer(r"\(|\)", sql):
        if m.group(0) == "(":
            depth_stack.append(m.start())
        elif depth_stack:
            depth_stack.pop()
    if not depth_stack:
        return False
    before = sql[:depth_stack[-1]]
    return bool(re.search(r"\b(?:VALUES|IN)\s*$", before, re.IGNORECASE))


_FORMAT_SPEC = re.compile(r"%(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?([sdfxXcb])")
_MIGRATION_FUN = {"migrate", "onUpgrade", "onDowngrade"}
_MIGRATION_PATH = re.compile(r"(?i)(?:^|/)(?:migrations?|DBUpgrader)[^/]*(?:/|\.(?:kt|java)$)")
# Values a migration reads back out of the database: they can hold a quote whatever the app meant.
_DB_READ = re.compile(r"\.\s*(?:getString|requireString|requireNonNullString|getStringOrNull|optString)\s*\(|"
                      r"\b[Cc]ursor\b")


def _in_migration(path: str, blank: str, idx: int, lo: int, fn: str) -> bool:
    """A one-time schema migration: Room's Migration.migrate(), SQLiteOpenHelper.onUpgrade(), or a
    migration class or file. It runs once, over data the app wrote."""
    if fn in _MIGRATION_FUN or _MIGRATION_PATH.search(path):
        return True
    if re.search(r"\bMigration\s*\(\s*\d+\s*,\s*\d+\s*\)", blank[max(0, lo - 300):lo]):
        return True
    return "Migration" in _class_at(blank, idx)


def _from_database(expr: str, code: str, lo: int, idx: int) -> bool:
    """`expr` (or the variable it starts with) is read from a cursor in this function."""
    if _DB_READ.search(expr):
        return True
    name = re.match(r"\s*(\w+)", expr)
    if not name:
        return False
    for m in re.finditer(r"\b(?:val|var|final\s+String|String)\s+" + re.escape(name.group(1))
                         + r"\b[^=;\n]*=\s*([^;\n]+)", code[lo:idx]):
        if _DB_READ.search(m.group(1)):
            return True
    return False


def _enum_typed(ctx: Context, expr: str, code: str) -> bool:
    """`x` or `a.x` whose declared type is an enum class of this project (it prints a constant name)."""
    last = re.fullmatch(r"(?:\w+\??\.)*(\w+)", expr.strip().rstrip("!"))
    if not last:
        return False
    tm = re.search(r"\b" + re.escape(last.group(1)) + r"\s*:\s*([A-Z]\w*)\b(?!\s*[<(.])", code)
    if not tm:
        return False
    _subs, _sup, files = _class_index(ctx)
    rx = re.compile(r"\benum\s+(?:class\s+)?" + re.escape(tm.group(1)) + r"\b")
    return any(rx.search(ctx.code(f, False) or "") for f in files.get(tm.group(1), []))


@detector("android_sql_concat")
def sql_concat(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files_any(ctx, ("rawQuery", "execSQL")):
        if "rawQuery" not in blank and "execSQL" not in blank:
            continue
        kotlin = path.endswith(".kt")
        for m in _sites(_SQL_CALL.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            a, b = spans[0]
            fm = re.search(r"\bformat\s*\(", blank[a:b])
            pieces: List[Tuple[str, str]]
            if fm:
                fopen = a + fm.end() - 1
                fargs = _args(blank, fopen)
                receiver = blank[a:a + fm.start()].strip()
                if receiver.endswith('".'):          # "...".format(x) in Kotlin
                    lit_span = (a, a + fm.start() - 1)
                    values = fargs
                else:                                 # String.format("...", x)
                    if not fargs:
                        continue
                    lit_span, values = fargs[0], fargs[1:]
                lit_pieces = _sql_pieces(code, lit_span[0], lit_span[1], kotlin)
                pieces = []
                vi = 0
                for kind, text in lit_pieces:
                    if kind != "lit":
                        pieces.append((kind, text))
                        continue
                    pos = 0
                    for sm in _FORMAT_SPEC.finditer(text):
                        pieces.append(("lit", text[pos:sm.start()]))
                        if vi < len(values):
                            v = code[values[vi][0]:values[vi][1]]
                            pieces.append(("expr", "0" if sm.group(1) in "dfxXc" else v))
                        vi += 1
                        pos = sm.end()
                    pieces.append(("lit", text[pos:]))
            else:
                pieces = _sql_pieces(code, a, b, kotlin)
            sql = ""
            bad = None
            ddl = None
            for kind, text in pieces[:400]:
                if kind == "lit":
                    sql += text
                    continue
                if ddl is None:
                    ddl = bool(_DDL_START.match(sql or "x"))
                expr = text.strip()
                if expr.startswith(".") or expr.startswith("?."):
                    continue          # a call on the literal before it, such as .trimIndent()
                quoted = _quote_open(sql)
                sql_before = sql
                sql += "X"
                if _sql_is_constant(expr, code, blank, m.start()) or _sql_is_numeric(expr, code) \
                        or _enum_typed(ctx, expr, code):
                    continue
                if quoted:
                    bad = expr
                    break
                tail = sql_before.rstrip()
                if _VALUE_CTX.search(sql_before) or (tail.endswith(",") and _in_value_list(sql_before)):
                    bad = expr
                    break
                # anything else is an identifier position, a SQL fragment, or text the bind arguments complete
            if bad is not None:
                line = ctx.line_of(blank, m.start())
                shown = re.sub(r"\s+", " ", bad)[:60]
                lo, _hi, fn = _function_at(blank, m.start())
                if _in_migration(path, blank, m.start(), lo, fn):
                    if not _from_database(bad, code, lo, m.start()):
                        ctx.note_unknown(f"{path}:{line}: a one-time migration joins `{shown}` into SQL; it looks "
                                         "app-owned (an ID, enum or default), so it wasn't reported.")
                        continue
                    yield _hit(ctx, path, line,
                               f"This one-time migration puts `{shown}`, read back from the database, into a value "
                               "position by joining strings. A stored quote breaks the statement; bind it instead.",
                               severity="low")
                    continue
                yield _hit(ctx, path, line,
                           f"This SQL puts `{shown}` into a value position by joining strings, so input can change "
                           "the query.")
    yield from _query_builder(ctx)


_APPEND_WHERE = re.compile(r"\.\s*appendWhere(?:Standalone)?\s*\(")
_QB_NEW = re.compile(r"(?:\b(?:val|var)\s+(\w+)\s*(?::\s*SQLiteQueryBuilder\??)?|\bSQLiteQueryBuilder\s+(\w+))\s*=\s*"
                     r"(?:new\s+)?(?<![\w.])SQLiteQueryBuilder\s*\(\s*\)")
_QB_STRICT = re.compile(r"\bsetStrict\s*\(\s*true\s*\)|\b(?:isStrict|strict)\s*=\s*true\b|\bsetStrictGrammar\s*\(\s*true"
                        r"|\bstrictGrammar\s*=\s*true\b")
_PROVIDER_QUERY = re.compile(r"(?:\boverride\s+fun|\bpublic\s+(?:final\s+)?(?:@\w+\s+)?Cursor)\s+query\s*\(")


def _open_providers(ctx: Context) -> Set[str]:
    """Simple class names of content providers any app can query: exported, with no read permission (or only
    one any app can request) and no path permissions."""
    def compute() -> Set[str]:
        declared = _declared_permissions(ctx)
        out: Set[str] = set()
        for path, root in _manifests(ctx):
            if scope_of(path) == "test":
                continue
            for c in manifest.components(root, ("provider",)):
                if not xmlsafe.is_true(c.get("android:exported")) or \
                        any(ch.tag == "path-permission" for ch in c.children):
                    continue
                perms = [c.get(a) for a in ("android:readPermission", "android:permission") if c.get(a)]
                if any(manifest.is_placeholder(p) or _permission_strength((p or "").strip(), declared) != "weak"
                       for p in perms):
                    continue
                out.add(_simple(c.get("android:name") or ""))
        return out
    return _memo(ctx, "open_providers", compute)


def _query_builder(ctx: Context) -> Iterator[Hit]:
    """SQLiteQueryBuilder in a content provider: a WHERE fragment built from input (appendWhere), and a caller's
    selection passed to query() by a provider any app can call, with the builder not in strict mode."""
    for path, code, blank in _code_files_any(ctx, ("appendWhere", "SQLiteQueryBuilder")):
        kotlin = path.endswith(".kt")
        safe: Dict[str, bool] = {}          # expression -> constant or numeric, once per file
        for m in _sites(_APPEND_WHERE.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if len(spans) != 1:
                continue
            for kind, text in _sql_pieces(code, spans[0][0], spans[0][1], kotlin)[:400]:
                expr = text.strip()
                if kind == "lit" or expr.startswith((".", "?.")):
                    continue
                if expr not in safe:
                    safe[expr] = _sql_is_constant(expr, code, blank, m.start()) or _sql_is_numeric(expr, code) \
                        or _enum_typed(ctx, expr, code)
                if safe[expr]:
                    continue
                shown = re.sub(r"\s+", " ", expr)[:60]
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"appendWhere() adds `{shown}` to the WHERE clause as raw SQL, so input can change the "
                           "query.")
                break
        if "SQLiteQueryBuilder" not in blank or _QB_STRICT.search(blank):
            continue
        builders = {b.group(1) or b.group(2) for b in _QB_NEW.finditer(blank)}
        if not builders:
            continue
        for pm in _sites(_PROVIDER_QUERY.finditer(blank)):
            params = _args(blank, pm.end() - 1)
            if len(params) != 5:
                continue
            # The parameter's name is at its end; a declaration is short, so a crafted 40 KB one is cut first.
            sel = re.search(r"(\w+)\s*(?::\s*String\??\s*)?$", blank[params[2][0]:params[2][1]].strip()[-200:])
            if not sel:
                continue
            close = _match(blank, pm.end() - 1, "(", ")")
            body_open = blank.find("{", close)
            if body_open == -1:
                continue
            body_close = _match(blank, body_open, "{", "}")
            for qm in re.finditer(r"\b(\w+)\s*\.\s*query\s*\(", blank[body_open:body_close]):
                if qm.group(1) not in builders:
                    continue
                q_open = body_open + qm.end() - 1
                args = [blank[s:e].strip() for s, e in _args(blank, q_open)]
                if sel.group(1) not in args[1:4]:
                    continue
                cls = _class_at(blank, pm.start())
                if not cls or cls not in _open_providers(ctx):
                    continue
                yield _hit(ctx, path, ctx.line_of(blank, q_open),
                           f"The exported provider {cls} passes the caller's selection to SQLiteQueryBuilder.query() "
                           "without setStrict(true), so another app can add SQL that reads other tables.")
                break


# ---------------------------------------------------------------------------- PendingIntent and intents

_PI_CALL = re.compile(r"\bPendingIntent(?:Compat)?\s*\.\s*get(?:Activity|Activities|Broadcast|Service|ForegroundService)"
                      r"\s*\(")
_FLAG_MUTABLE = re.compile(r"\bFLAG_MUTABLE\b|\bFLAG_ALLOW_UNSAFE_IMPLICIT_INTENT\b")
_NEW_INTENT = re.compile(r"(?:\bnew\s+)?(?<![\w.])Intent\s*\(")
_EXPLICIT_CALL = r"(?:setPackage|setComponent|setClass|setClassName|setSelector)\s*\(|(?:\bpackage|`package`|\bcomponent)\s*="


def _intent_kind(ctx: Context, code: str, blank: str, open_paren: int) -> Tuple[str, Optional[str]]:
    """("explicit" | "implicit" | "unknown", action) for the `Intent(` whose "(" is at open_paren."""
    spans = _args(blank, open_paren)
    if not spans:
        return "unknown", None          # Intent(): decided later by setAction / setComponent
    texts = [code[s:e].strip() for s, e in spans]
    if len(texts) >= 2 and re.search(r"::class\.java|\.class\b|::class\b|javaClass", " ".join(texts[1:])):
        return "explicit", None
    first = texts[0]
    lit = re.fullmatch(r"\"([^\"\\\n]*)\"", first)
    if lit:
        return "implicit", lit.group(1)
    const = re.fullmatch(r"(?:[\w.]+\.)?([A-Z][A-Z0-9_]*)", first)
    if const:
        if re.match(r"(?:Intent|Settings|MediaStore|Telephony|DocumentsContract)\.", first) or \
                first.startswith(("android.", "Intent.")):
            return "implicit", "android." + const.group(1)
        return "implicit", _string_constants(ctx).get(const.group(1))
    return "unknown", None


def _intent_vars(ctx: Context, code: str, blank: str, lo: int, hi: int) -> Dict[str, Tuple[int, str, Optional[str]]]:
    """Intent variables built in [lo, hi): name -> (offset, kind, action), with setPackage/setComponent and
    setAction applied. Once per file and range: every send and PendingIntent in a function asks again."""
    return text_memo(blank, ("intent_vars", lo, hi), lambda: _intent_vars_in(ctx, code, blank, lo, hi))


def _explicit_use(blank: str, name: str, start: int, end: int) -> bool:
    """Does blank[start:end] (with `start` right after a `(`) hold a call that makes intent `name` explicit
    (the _EXPLICIT_CALL pattern after `name.`)? Answered from the file's matches: the pattern has no anchor
    at its end, its leading word boundary sees the same non-word `(` at `start` that a slice start would,
    and two matches can't overlap (inside one, only the call word starts a word, and no `.` follows it),
    so the slice holds a match exactly when a match of the whole text lies inside it."""
    spans = text_memo(blank, ("explicit_use", name), lambda: [
        (u.start(), u.end()) for u in re.finditer(r"\b" + re.escape(name) + r"\s*\.\s*(?:" + _EXPLICIT_CALL + ")",
                                                  blank)])
    k = bisect.bisect_left(spans, (start, -1))
    return k < len(spans) and spans[k][1] <= end


def _intent_vars_in(ctx: Context, code: str, blank: str, lo: int, hi: int) -> Dict[str, Tuple[int, str, Optional[str]]]:
    out: Dict[str, Tuple[int, str, Optional[str]]] = {}
    rx = re.compile(r"(?:\b(?:val|var)\s+(\w+)\s*(?::\s*Intent\??)?|\bIntent\s+(\w+))\s*=\s*(?:new\s+)?Intent\s*\(")
    for m in rx.finditer(blank, lo, hi):
        name = m.group(1) or m.group(2)
        kind, action = _intent_kind(ctx, code, blank, m.end() - 1)
        close = _match(blank, m.end() - 1, "(", ")")
        after = blank[close + 1:close + 400]
        am = re.match(r"\s*\.\s*(?:apply|also)\s*\{", after)
        body = ""
        if am:
            bstart = close + 1 + am.end() - 1
            body_c = code[bstart:_match(blank, bstart, "{", "}")]
            body = body_c
        else:
            # calls chained on the constructor: Intent("x").setPackage(packageName)
            chain = re.match(r"(?:\s*\.\s*\w+\s*\([^()\n]*(?:\([^()\n]*\)[^()\n]*)*\))+", after)
            body = chain.group(0) if chain else ""
        if re.search(_EXPLICIT_CALL, body) or _explicit_use(blank, name, m.end(), hi):
            kind = "explicit"
        if kind == "unknown":
            action_rx = re.compile(r"(?:\b" + re.escape(name) + r"\s*\.\s*)?(?:setAction\s*\(\s*|\baction\s*=\s*)"
                                   r"(\"[^\"\n]*\"|[\w.]+)")
            if body:
                sa = action_rx.search(body)
            else:
                # Searching code[m.end():hi] in place (the `\b` at m.end() sees the `(` before it, a non-word
                # character as a slice start is); every match contains "setAction" or "action", so without one
                # in the range there is nothing to search.
                at = text_memo(code, ("action_at",), lambda: [(a.start(), a.end())
                                                              for a in re.finditer("setAction|action", code)])
                k = bisect.bisect_left(at, (m.end(), -1))
                sa = action_rx.search(code, m.end(), hi) if k < len(at) and at[k][1] <= hi else None
            if sa:
                v = sa.group(1)
                kind = "implicit"
                action = v.strip('"') if v.startswith('"') else _string_constants(ctx).get(v.rsplit(".", 1)[-1], v)
        out[name] = (m.start(), kind, action)
    return out


def _pi_intent_kind(ctx: Context, code: str, blank: str, spans: List[Tuple[int, int]], idx: int) -> str:
    """"explicit" | "implicit" | "unknown": the Intent a PendingIntent.get*( call (args `spans`) wraps."""
    arg = code[spans[2][0]:spans[2][1]].strip()
    arg_b = blank[spans[2][0]:spans[2][1]]
    im = _NEW_INTENT.search(arg_b)
    if im and im.start() < 4:
        kind, _a = _intent_kind(ctx, code, blank, spans[2][0] + im.end() - 1)
        return "explicit" if re.search(_EXPLICIT_CALL, arg) else kind
    nm = re.fullmatch(r"(\w+)(?:!!)?", arg)
    if nm:
        lo, hi, _fn = _function_at(blank, idx)
        return _intent_vars(ctx, code, blank, lo, hi).get(nm.group(1), (0, "unknown", None))[1]
    return "unknown"


# Flags written out as constants and numbers (`PendingIntent.FLAG_UPDATE_CURRENT or Intent.FLAG_X`, `0`), so
# masaudit can tell that neither FLAG_IMMUTABLE nor FLAG_MUTABLE is among them.
_LITERAL_FLAGS = re.compile(r"\s*(?:(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*|\d+)(?:\s*(?:\bor\b|\|)\s*"
                            r"(?:(?:[A-Za-z_]\w*\.)*[A-Z][A-Z0-9_]*|\d+))*\s*")


@detector("android_pending_intent_mutable")
def pending_intent_mutable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "FLAG_"):
        if not _FLAG_MUTABLE.search(blank):
            continue
        for m in _sites(_FLAG_MUTABLE.finditer(blank)):
            if _is_import(blank, m.start()):
                continue
            call = None
            for c in _PI_CALL.finditer(blank, max(0, m.start() - 1500), m.start()):
                if _match(blank, c.end() - 1, "(", ")") > m.start():
                    call = c
            line = ctx.line_of(blank, m.start())
            if call is None:
                continue          # a flags helper; the PendingIntent that uses it is checked where it's built
            spans = _args(blank, call.end() - 1)
            if len(spans) < 3:
                continue
            kind = _pi_intent_kind(ctx, code, blank, spans, m.start())
            if kind == "implicit":
                yield _hit(ctx, path, line,
                           "A mutable PendingIntent wraps an implicit Intent, so the app that receives it can "
                           "redirect it and act with this app's identity.")
            elif kind == "unknown":
                ctx.note_unknown(f"{path}:{line}: a mutable PendingIntent wraps an Intent masaudit can't resolve; "
                                 "confirm it names a component or package.")
    # No mutability flag at all: before Android 12 (API 31) such a PendingIntent is mutable.
    min_sdk = None
    for path, code, blank in _code_files(ctx, "PendingIntent"):
        for c in _sites(_PI_CALL.finditer(blank)):
            spans = _args(blank, c.end() - 1)
            if len(spans) < 4 or "Compat" in c.group(0):
                continue          # PendingIntentCompat sets the mutability flag from its isMutable argument
            flags = blank[spans[3][0]:spans[3][1]]
            if not _LITERAL_FLAGS.fullmatch(flags) or "IMMUTABLE" in flags or _FLAG_MUTABLE.search(flags):
                continue          # a flags variable or helper, or a flag that sets mutability
            if _pi_intent_kind(ctx, code, blank, spans, c.start()) != "implicit":
                continue
            if min_sdk is None:
                min_sdk = _sdk_value(ctx, "minSdk") or 0
            if min_sdk >= 31:
                continue
            yield _hit(ctx, path, ctx.line_of(blank, c.start()),
                       "This PendingIntent wraps an implicit Intent and sets no FLAG_IMMUTABLE, so on Android 11 and "
                       "lower it is mutable: the app that receives it can redirect it and act with this app's "
                       "identity.")


_SEND = re.compile(r"\b(?:startActivit(?:y|yForResult)|startService|startForegroundService|sendBroadcast"
                   r"|sendOrderedBroadcast|sendBroadcastAsUser)\s*\(")
_SENSITIVE_EXTRA = re.compile(r"(?i)token|password|passwd|secret|session_?id|sessionid|\botp\b|jwt|credential"
                              r"|auth_?code|authorization|access_?key|\bpin\b|private_?key"
                              r"|(?<![a-z0-9])(?:new_?|old_?|user_?)?(?:pass|pwd)(?![a-z0-9])")
# An extra whose value is a boolean flag (`putExtra(KEY, true)`, a Boolean variable) carries no secret.
_BOOL_LITERAL = re.compile(r"\s*(?:true|false|Boolean\.(?:TRUE|FALSE))\s*")


def _sends(ctx: Context, code: str, blank: str, lo: int, hi: int) -> Iterator[Tuple[int, str, Optional[str], str]]:
    """Intents sent in [lo, hi): (offset, kind, action, intent text). Skips local broadcasts, choosers,
    and broadcasts that name a receiver permission."""
    variables = _intent_vars(ctx, code, blank, lo, hi)
    for m in _SEND.finditer(blank, lo, hi):
        before = blank[max(lo, m.start() - 80):m.start()]
        if re.search(r"(?i)LocalBroadcastManager|localBroadcast|\blbm\b|\bbroadcastManager\b", before):
            continue
        spans = _args(blank, m.end() - 1)
        if not spans:
            continue
        if "roadcast" in m.group(0) and len(spans) >= 2 and blank[spans[1][0]:spans[1][1]].strip() != "null":
            continue
        arg = code[spans[0][0]:spans[0][1]].strip()
        arg_b = blank[spans[0][0]:spans[0][1]]
        if "createChooser" in arg:
            continue
        im = _NEW_INTENT.search(arg_b)
        if im and im.start() < 6:
            kind, action = _intent_kind(ctx, code, blank, spans[0][0] + im.end() - 1)
            if re.search(_EXPLICIT_CALL, arg):
                kind = "explicit"
            yield m.start(), kind, action, arg
            continue
        nm = re.fullmatch(r"(\w+)(?:!!)?", arg)
        if nm and nm.group(1) in variables:
            off, kind, action = variables[nm.group(1)]
            body_text = code[off:m.start()]
            yield m.start(), kind, action, body_text


def _boolean_value(value: str, code: str) -> bool:
    """Is a putExtra value a boolean: a literal, or a variable declared Boolean or set from a check?"""
    if _BOOL_LITERAL.fullmatch(value):
        return True
    name = re.fullmatch(r"\s*(\w+)\s*", value)
    if not name:
        return False
    var = re.escape(name.group(1))
    return bool(text_memo(code, ("bool_var", var), lambda: re.search(r"\b(?:boolean|Boolean)\s+" + var + r"\b|\b" + var + r"\s*:\s*Boolean\b|\b(?:val|var)\s+" + var
                          + r"\s*=\s*(?:true|false|[^\n;=]*\.\s*(?:isChecked|isEnabled|isSelected)\b)", code)))


@detector("android_implicit_intent_secret")
def implicit_intent_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "putExtra"):
        seen: Set[int] = set()
        for m in _sites(_SEND.finditer(blank)):
            lo, hi, _fn = _function_at(blank, m.start())
            if lo in seen:
                continue
            seen.add(lo)
            for off, kind, action, text in _sends(ctx, code, blank, lo, hi):
                if kind != "implicit" or (action or "").endswith(("ACTION_SEND", "ACTION_SEND_MULTIPLE",
                                                                    "action.SEND", "action.SEND_MULTIPLE")):
                    continue
                extras = re.findall(r"putExtra\s*\(\s*([^,]+),\s*([^)\n]*)", text)
                hit_key = None
                for key, value in extras:
                    k = key.strip()
                    if _boolean_value(value, code) or text_memo(code, ("bool_extra", k), lambda k=k, c=code: re.search(
                            r"getBooleanExtra\s*\(\s*" + re.escape(k), c)):
                        continue
                    kc = re.fullmatch(r"(?:[\w.]+\.)?([A-Z][A-Z0-9_]*)", k)
                    k_text = k + " " + (_string_constants(ctx).get(kc.group(1), "") if kc else "")
                    # the value counts when it's a variable or getter named for a secret (not getAuthTokenType())
                    vm = re.fullmatch(r"\s*(?:[\w.]+\.)?(?:get)?(\w+?)(?:\(\s*\))?\s*", value)
                    v_tokens = _camel(vm.group(1)) if vm else []
                    v_secret = bool(v_tokens) and v_tokens[-1] in {"token", "password", "passwd", "secret", "jwt",
                                                                   "otp", "pin", "credential", "credentials", "passcode"}
                    if _SENSITIVE_EXTRA.search(k_text) or v_secret:
                        hit_key = k.strip('"')
                        break
                if hit_key:
                    yield _hit(ctx, path, ctx.line_of(blank, off),
                               f"An implicit Intent ({action or 'action'}) carries `{hit_key}`, so any app with a "
                               "matching filter can receive it.")


@detector("android_implicit_internal_intent")
def implicit_internal_intent(ctx: Context, rule: Rule) -> Iterable[Hit]:
    prefixes = [p + "." for p in _app_id_prefixes(ctx)]
    own_actions: Set[str] = set()
    for _path, root in _manifests(ctx):
        for c in manifest.components(root):
            for f in manifest.intent_filters(c):
                own_actions.update(a for a in manifest.names(f, "action") if a and not _FRAMEWORK_ACTION.match(a))
    if not prefixes and not own_actions:
        return
    for path, code, blank in _code_files(ctx, "Intent"):
        if not _SEND.search(blank):
            continue
        seen: Set[int] = set()
        for m in _sites(_SEND.finditer(blank)):
            lo, hi, _fn = _function_at(blank, m.start())
            if lo in seen:
                continue
            seen.add(lo)
            for off, kind, action, _text in _sends(ctx, code, blank, lo, hi):
                if kind != "implicit" or not action:
                    continue
                if action in own_actions or any(action.startswith(p) for p in prefixes):
                    yield _hit(ctx, path, ctx.line_of(blank, off),
                               f"The app-internal action {action} is sent as an implicit Intent, so another app can "
                               "intercept it or answer it.")


_REGISTER = re.compile(r"\bregisterReceiver\s*\(")
_SYSTEM_ACTION_CONST = re.compile(r"\b(?:Intent|ConnectivityManager|AudioManager|BluetoothAdapter|BluetoothDevice"
                                  r"|TelephonyManager|WifiManager|DownloadManager|PowerManager|UsbManager|NfcAdapter"
                                  r"|LocationManager|NotificationManager|KeyChain|Settings|AppWidgetManager"
                                  r"|AlarmManager|DevicePolicyManager|BluetoothHeadset|AudioDeviceInfo)\.\w+")


def _filter_actions(ctx: Context, code: str, blank: str, expr: str, lo: int, hi: int) -> Optional[List[str]]:
    """Actions an IntentFilter argument matches: literal values, "system" for platform constants;
    None when masaudit can't tell."""
    texts: List[str] = []
    m = re.search(r"IntentFilter\s*\(([^)]*)\)", expr)
    if m:
        texts.append(m.group(1))
        texts += re.findall(r"addAction\s*\(([^)]*)\)", expr)
    else:
        nm = re.fullmatch(r"\s*(\w+)\s*", expr)
        if not nm:
            return None
        name = nm.group(1)
        if name == "this":
            # IntentFilter().apply { addAction(..) }.run { register(receiver, this) }
            scoped = list(re.finditer(r"IntentFilter\s*\(\s*\)\s*\.\s*apply\s*\{([^{}]*)\}\s*\.\s*(?:run|let|also)\s*\{",
                                      code[lo:hi]))
            if not scoped:
                return None
            texts += re.findall(r"addAction\s*\(([^)]*)\)", scoped[-1].group(1))
            return _resolve_actions(ctx, texts)
        dm = re.search(r"\b(?:val|var|IntentFilter)\s+" + re.escape(name) + r"\s*(?::\s*IntentFilter\s*)?=\s*"
                       r"(?:new\s+)?IntentFilter\s*\(([^)]*)\)", code[lo:hi])
        if not dm:
            return None
        texts.append(dm.group(1))
        texts += re.findall(r"\b" + re.escape(name) + r"\s*\.\s*addAction\s*\(([^)]*)\)", code[lo:hi])
        after = code[lo + dm.end():lo + dm.end() + 600]
        am = re.match(r"\s*\.\s*apply\s*\{([^}]*)\}", after)
        if am:
            texts += re.findall(r"addAction\s*\(([^)]*)\)", am.group(1))
    return _resolve_actions(ctx, texts)


def _resolve_actions(ctx: Context, texts: List[str]) -> Optional[List[str]]:
    out: List[str] = []
    consts = _string_constants(ctx)
    for t in texts:
        t = t.strip()
        if not t:
            continue
        lit = re.fullmatch(r"\"([^\"\n]*)\"", t)
        if lit:
            out.append(lit.group(1))
        elif _SYSTEM_ACTION_CONST.fullmatch(t) or t.startswith("android."):
            out.append("system")
        else:
            c = re.fullmatch(r"(?:[\w.]+\.)?([A-Z][A-Z0-9_]*)", t)
            if c and c.group(1) in consts:
                out.append(consts[c.group(1)])
            else:
                return None
    return out


def _param_index(blank: str, code: str, lo: int, fn: str, name: str) -> Optional[int]:
    """Position of parameter `name` in the declaration of function `fn` whose body starts at lo."""
    if not fn:
        return None
    heads = list(re.finditer(r"\b" + re.escape(fn) + r"\s*\(", blank[:lo]))
    if not heads:
        return None
    params = [code[a:b].strip() for a, b in _args(blank, heads[-1].end() - 1)]
    return next((i for i, p in enumerate(params) if re.match(r"(?:\w+\s+)*" + re.escape(name) + r"\s*:|"
                                                             r"(?:final\s+)?[\w.<>\[\]]+\s+" + re.escape(name) + r"$",
                                                             p)), None)


def _exported_message(custom: Optional[List[str]], via: str = "") -> str:
    shown = f" for {', '.join(custom[:3])}" if custom else ""
    how = f" through {via}()" if via else ""
    return f"This receiver is registered as exported{shown}{how} with no permission, so any app can send it broadcasts."


def _custom_actions(actions: Optional[List[str]]) -> Optional[List[str]]:
    return None if actions is None else [a for a in actions if a != "system" and a not in _PROTECTED_BROADCASTS
                                         and not a.startswith("android.")]


def _wrapper_calls(ctx: Context, wrapper: str, pos: int) -> Iterator[Hit]:
    """Call sites of a helper such as `fun Context.registerExportedReceiver(r, filter)` that registers
    whatever filter it's given as exported: each caller decides what the receiver accepts."""
    call = re.compile(r"(?<![\w$])" + re.escape(wrapper) + r"\s*\(")
    for path, code, blank in _code_files(ctx, wrapper):
        for m in _sites(call.finditer(blank)):
            if _is_import(blank, m.start()) or re.search(r"\bfun\s+(?:<[^>{}]*>\s*)?(?:[\w.]+\.)?$",
                                                        blank[max(0, m.start() - 80):m.start()]):
                continue
            spans = _args(blank, m.end() - 1)
            if pos >= len(spans):
                continue
            lo, hi, _fn = _function_at(blank, m.start())
            custom = _custom_actions(_filter_actions(ctx, code, blank, code[spans[pos][0]:spans[pos][1]].strip(),
                                                     lo, hi))
            if custom == []:
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()), _exported_message(custom, wrapper))


@detector("android_receiver_registered_exported")
def receiver_registered_exported(ctx: Context, rule: Rule) -> Iterable[Hit]:
    target = None
    wrappers: Dict[str, int] = {}
    for path, code, blank in _code_files(ctx, "registerReceiver"):
        for m in _sites(_REGISTER.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            compat = bool(re.search(r"ContextCompat\s*\.\s*$", blank[max(0, m.start() - 40):m.start()]))
            args = [code[s:e].strip() for s, e in spans][1 if compat else 0:]
            if len(args) < 2:
                continue
            perm = flags = None
            if len(args) == 3:
                flags = args[2]
            elif len(args) == 4:
                perm = args[2]
            elif len(args) >= 5:
                perm, flags = args[2], args[4]
            if flags and "NOT_EXPORTED" in flags:
                continue
            if perm and perm not in ("null", "None"):
                continue
            lo, hi, fn = _function_at(blank, m.start())
            actions = _filter_actions(ctx, code, blank, args[1], lo, hi)
            custom = _custom_actions(actions)
            line = ctx.line_of(blank, m.start())
            if flags and re.search(r"\bRECEIVER_EXPORTED\b", flags):
                if custom == []:
                    continue
                pos = _param_index(blank, code, lo, fn, args[1]) if re.fullmatch(r"\w+", args[1]) else None
                if actions is None and pos is not None:
                    wrappers[fn] = pos        # a helper: report where it's called, with the caller's filter
                    continue
                yield _hit(ctx, path, line, _exported_message(custom))
            elif flags is None:
                if custom:
                    if target is None:
                        target = _sdk_value(ctx, "targetSdk") or 0
                    if 0 < target < 34:
                        yield _hit(ctx, path, line,
                                   f"This receiver for {', '.join(custom[:3])} is registered without a flag; below "
                                   "targetSdk 34 that makes it exported, so any app can send it broadcasts.")
    for wrapper, pos in sorted(wrappers.items()):
        yield from _wrapper_calls(ctx, wrapper, pos)


_GRANT_ALL = {"android:path": {"/"}, "android:pathPrefix": {"/", ""}, "android:pathPattern": {".*", "/.*"}}


@detector("android_grant_uri_all")
def grant_uri_all(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        for c in manifest.components(root, ("provider",)):
            for g in c.children:
                if g.tag != "grant-uri-permission":
                    continue
                for attr, bad in _GRANT_ALL.items():
                    value = g.get(attr)
                    if value is not None and value.strip() in bad:
                        yield _hit(ctx, path, g.line,
                                   f"The provider {c.get('android:name')} lets URI grants reach every path "
                                   f"({attr.split(':')[1]}=\"{value}\").",
                                   ack=_ack(ctx, path, g, "GrantAllUris"))
                        break


_WRITE_METHOD = re.compile(r"\b(?:override\s+fun|public\s+(?:final\s+)?\w[\w<>\[\]?]*)\s+(insert|update|delete)\s*\(")


def _writes_data(blank: str) -> List[str]:
    out = []
    for m in _WRITE_METHOD.finditer(blank):
        close = _match(blank, blank.index("(", m.start()), "(", ")")
        rest = blank[close + 1:close + 300]
        em = re.match(r"\s*(?::\s*[\w.?<>]+\s*)?=\s*([^\n]*)", rest)
        if em:
            body = em.group(1)
        else:
            brace = blank.find("{", close)
            if brace == -1:
                continue
            body = blank[brace + 1:_match(blank, brace, "{", "}")]
        b = re.sub(r"\s+", " ", body).strip()
        if re.fullmatch(r"(?:return\s+)?(?:0|null|-1|0L)\s*;?|throw\s+\w+.*|TODO\(.*\)\s*;?|(?:return\s+)?"
                        r"super\.\w+\(.*\)\s*;?|", b):
            continue
        out.append(m.group(1))
    return out


@detector("android_provider_read_only_permission")
def provider_read_only_permission(ctx: Context, rule: Rule) -> Iterable[Hit]:
    _subs, _sup, files = _class_index(ctx)
    for path, root in _manifests(ctx):
        for c in manifest.components(root, ("provider",)):
            if not xmlsafe.is_true(c.get("android:exported")):
                continue
            if not c.get("android:readPermission") or c.get("android:writePermission") or c.get("android:permission"):
                continue
            cls = _simple(c.get("android:name") or "")
            srcs = files.get(cls, [])
            if not srcs:
                ctx.note_unknown(f"{path}: provider {c.get('android:name')} protects reads only; masaudit can't find "
                                 "its class to check whether it accepts writes.")
                continue
            methods = sorted({w for p in srcs for w in _writes_data(ctx.code(p, False) or "")})
            if methods:
                yield _hit(ctx, path, c.line,
                           f"The provider {c.get('android:name')} requires a permission to read but not to write, and "
                           f"it implements {', '.join(methods)}, so any app can change its data.",
                           ack=_ack(ctx, path, c, "ProviderReadPermissionOnly"))


_SERIALIZABLE = re.compile(r"\bgetSerializableExtra\s*\(|\bgetSerializable\s*\(")
_OIS = re.compile(r"\bObjectInputStream\s*\(")
_OUTSIDE_STREAM = re.compile(r"openInputStream|ParcelFileDescriptor|\bSocket\b|getInputStream|URLConnection|EXTRA_STREAM"
                             r"|\bInputStream\s+\w+\s*[,)]|\w+\s*:\s*InputStream\b")
_JAVA_METHOD_HEAD = re.compile(r"(?P<name>\w+)\s*\([^{};]*\)\s*(?:throws\s+[\w.,\s]+)?$")


def _method_name_at(blank: str, idx: int, java: bool) -> str:
    """Name of the method around idx; for Java also when its parameters or throws clause span lines."""
    _lo, _hi, fn = _function_at(blank, idx)
    if fn or not java:
        return fn
    depth, j = 0, idx - 1
    while j >= 0:
        c = blank[j]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                head = blank[max(0, j - 600):j].rstrip()
                m = _JAVA_METHOD_HEAD.search(head)
                if m and m.group("name") not in _NOT_METHODS and \
                        not re.search(r"\b(?:new|class|interface)\s+[\w.]*\s*$", head[:m.start()]):
                    return m.group("name")
            else:
                depth -= 1
        j -= 1
    return ""


def _never_called(ctx: Context, path: str, blank: str, idx: int) -> str:
    """The name of the method around idx when nothing in the project calls it (vendored dead code), else ""."""
    java = path.endswith(".java")
    name = _method_name_at(blank, idx, java)
    if not name or name in ("main", "readObject", "readExternal", "readResolve"):
        return ""
    decl = re.search(r"(?:@Override[^;{}]*|\boverride\s+(?:\w+\s+)*fun\s+)\b" + re.escape(name) + r"\s*\(",
                     blank[max(0, idx - 20000):idx])
    if decl:
        return ""             # the framework or a supertype calls it
    ref = re.compile(r"(?<![\w$])" + re.escape(name) + r"\s*\(|::\s*" + re.escape(name) + r"\b")
    for other in ctx.files(*CODE_SUFFIXES):
        if name not in (ctx.text(other) or ""):
            continue
        ob = ctx.code(other, False) or ""
        for m in ref.finditer(ob):
            if not m.group(0).startswith("::"):
                before = ob[max(0, m.start() - 80):m.start()]
                if re.search(r"\bfun\s+(?:<[^>{}]*>\s*)?(?:[\w.]+\.)?$", before):
                    continue          # a Kotlin declaration
                close = _match(ob, m.end() - 1, "(", ")")
                if re.match(r"\s*(?:throws\b[^{;]*)?\{", ob[close + 1:close + 200]) and \
                        not re.search(r"(?:\bnew\s+[\w.<>]*|[=(,]\s*)$", before):
                    continue          # a Java declaration
            if _method_name_at(ob, m.start(), other.endswith(".java")) == name:
                continue              # an overload or recursion of itself
            return ""
    return name


def _hardened_subclass(blank: str, m: "re.Match[str]") -> bool:
    """`class X(..) : ObjectInputStream(s) { override fun resolveClass ... throw }` or the anonymous
    `new ObjectInputStream(s) { resolveClass ... throw }`: the class-allowlist mitigation itself."""
    close = _match(blank, m.end() - 1, "(", ")")
    rest = blank[close + 1:close + 400]
    om = re.match(r"\s*(?::\s*[\w.<>, ]+\s*)?\{", rest)
    if not om:
        return False
    brace = close + 1 + om.end() - 1
    body = blank[brace:_match(blank, brace, "{", "}") + 1]
    rm = re.search(r"\bresolveClass\s*\(", body)
    return bool(rm) and bool(re.search(r"\bthrow\b", body[rm.end():]))


@detector("android_object_input_stream")
def object_input_stream(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "ObjectInputStream"):
        for m in _sites(_OIS.finditer(blank)):
            if _is_import(blank, m.start()):
                continue
            line = ctx.line_of(blank, m.start())
            if _hardened_subclass(blank, m):
                continue
            spans = _args(blank, m.end() - 1)
            arg = blank[spans[0][0]:spans[0][1]].strip() if spans else ""
            lo, hi, _fn = _function_at(blank, m.start())
            body = blank[lo:hi]
            clone = re.fullmatch(r"(?:new\s+)?(?:java\.io\.)?ByteArrayInputStream\s*\(\s*(\w+)\s*\.\s*toByteArray\s*"
                                 r"\(\s*\)\s*\)", arg)
            if clone and re.search(r"\bObjectOutputStream\s*\(\s*" + re.escape(clone.group(1)) + r"\s*\)", body):
                continue              # an in-memory deep copy of the app's own object
            dead = _never_called(ctx, path, blank, m.start())
            if dead:
                ctx.note_unknown(f"{path}:{line}: ObjectInputStream in {dead}(), which nothing in the project "
                                 "calls; not reported.")
                continue
            name = re.fullmatch(r"\w+", arg)
            from_file = "FileInputStream(" in re.sub(r"\s+", "", arg) or bool(name and re.search(
                r"\b" + re.escape(arg) + r"\s*(?::\s*\w+\s*)?=\s*(?:new\s+)?FileInputStream\s*\(", body))
            if from_file and not _OUTSIDE_STREAM.search(body):
                yield _hit(ctx, path, line, "ObjectInputStream deserializes arbitrary classes from a file the app "
                                            "reads. Whoever can write that file controls what gets built.",
                           severity="medium")
            else:
                yield _hit(ctx, path, line, "ObjectInputStream deserializes arbitrary classes. Check where the bytes "
                                            "come from.")


@detector("android_serializable_extra")
def serializable_extra(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "Serializable"):
        for m in _sites(_SERIALIZABLE.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if len(spans) >= 2 and re.search(r"::class\.java|\.class\b", code[spans[1][0]:spans[1][1]]):
                continue                          # typed overload: only the named class is accepted
            before = code[max(0, m.start() - 120):m.start()]
            stmt = before[before.rfind("\n") + 1:]
            if _APP_BUNDLE.search(stmt) or "BundleCompat" in stmt and _APP_BUNDLE.search(code[m.start():m.end() + 60]):
                continue                          # a Bundle this app wrote itself
            recv = re.search(r"(\w+)\s*\??\s*\.\s*$", blank[max(0, m.start() - 60):m.start()])
            lo, _hi, fn = _function_at(blank, m.start())
            if recv and recv.group(1) in ("data", "result", "resultData") and (
                    fn == "onActivityResult" or re.search(r"ActivityResult|onResult", blank[max(0, lo - 300):lo])):
                continue                          # the result of an activity this app started
            if not _is_import(blank, m.start()) and blank[max(0, m.start() - 4):m.start()].endswith("fun "):
                continue
            if not _exposed(ctx, path, blank, m.start(), "a Serializable extra is read"):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "A Serializable object is read from an Intent another app can send, so it can deliver "
                       "any serializable class.")


# ---------------------------------------------------------------------------- storage: backup


@dataclass
class _AppBackup:
    module: str
    kind: str
    main: Optional[Tuple[str, Element]] = None                       # src/main <application>
    release: List[Tuple[str, Element]] = field(default_factory=list)  # src/main and release overlays
    other: List[Tuple[str, Element]] = field(default_factory=list)    # debug and non-release overlays

    def attr(self, name: str) -> Optional[Tuple[str, Element, str]]:
        """The explicit value a shipping manifest gives, overlays last (they win in the merge)."""
        found = None
        for path, app in self.release:
            v = app.get(name)
            if v is not None:
                found = (path, app, v)
        return found


def _backup_apps(ctx: Context) -> Tuple[Dict[str, _AppBackup], List[Tuple[str, Element]]]:
    """Per app module: its shipping <application> elements; plus every library <application>."""
    def compute():
        kinds = _module_kinds(ctx)
        apps: Dict[str, _AppBackup] = {}
        libs: List[Tuple[str, Element]] = []
        for path, root in _manifests(ctx):
            module = _module_of(path)
            kind = kinds.get(module, "unknown")
            for app in manifest.applications(root):
                if kind == "lib":
                    libs.append((path, app))
                    continue
                entry = apps.setdefault(module, _AppBackup(module, kind))
                if _source_set(path) == "main":
                    entry.main = (path, app)
                    entry.release.insert(0, (path, app))
                elif _scope(ctx, path) in ("main", "build-script"):
                    entry.release.append((path, app))
                else:
                    entry.other.append((path, app))
        return apps, libs
    return _memo(ctx, "backup_apps", compute)


def _custom_agent_only(entry: _AppBackup) -> bool:
    """A custom BackupAgent without fullBackupOnly="true" turns Auto Backup off: only the agent's
    key/value data is backed up."""
    agent = entry.attr("android:backupAgent")
    full = entry.attr("android:fullBackupOnly")
    return agent is not None and not (full and xmlsafe.is_true(full[2]))


@detector("android_backup")
def backup(ctx: Context, rule: Rule) -> Iterable[Hit]:
    apps, libs = _backup_apps(ctx)
    for entry in apps.values():
        if _custom_agent_only(entry):
            continue
        rules = entry.attr("android:dataExtractionRules") or entry.attr("android:fullBackupContent")
        ab = entry.attr("android:allowBackup")
        if ab is not None and manifest.is_placeholder(ab[2]):
            ctx.note_unknown(f"{ab[0]}: android:allowBackup comes from a placeholder.")
            continue
        if ab is not None and not xmlsafe.is_true(ab[2]):
            continue
        if rules:
            yield from _secret_files_backed_up(ctx, entry, len(apps) == 1)
            continue
        if ab is not None:
            path, app, _v = ab
            yield _hit(ctx, path, app.line, "allowBackup is true and there are no rules excluding sensitive files.",
                       ack=_ack(ctx, path, app, "AllowBackup", "DataExtractionRules"))
        elif entry.main is not None and entry.kind == "app":
            path, app = entry.main
            from_lib = [p for p, a in libs if xmlsafe.is_true(a.get("android:allowBackup"))]
            msg = ("allowBackup isn't set, so Android backs up the app's files by default, and there are no rules "
                   "excluding sensitive files.")
            if from_lib:
                msg += f" The library manifest {from_lib[0]} also sets allowBackup=\"true\"."
            yield _hit(ctx, path, app.line, msg, ack=_ack(ctx, path, app, "AllowBackup", "DataExtractionRules"))
        # debug or non-release overlays that turn backup on are reported in their own (lowered) scope
        for path, app in entry.other:
            if xmlsafe.is_true(app.get("android:allowBackup")):
                yield _hit(ctx, path, app.line, "allowBackup is true and there are no rules excluding sensitive "
                                                "files.", ack=_ack(ctx, path, app, "AllowBackup"))
    expo = _managed_expo(ctx) if not apps else None
    if expo is not None:
        yield from _expo_backup(ctx, expo)


def _expo_backup(ctx: Context, expo: "rn_expo.ExpoApp") -> Iterator[Hit]:
    """expo.android.allowBackup: Expo writes it into the generated manifest, and it defaults to true."""
    value = expo.get("android", "allowBackup")
    flag = expo.js_flag("allowBackup")
    if value is False or (flag is not None and not flag[0]):
        return
    if rn_expo.has_dep(ctx, "expo-secure-store") or expo.plugin("expo-secure-store") is not None:
        ctx.note_unknown(f"{expo.path}: expo-secure-store's config plugin can add backup rules to the generated "
                         "manifest; check android:dataExtractionRules after prebuild.")
        return
    if value is True:
        yield _hit(ctx, expo.path, expo.line("android", "allowBackup"),
                   "android.allowBackup is true in the Expo config and there are no rules excluding sensitive files.")
    elif flag is not None:
        yield _hit(ctx, _expo_dynamic_path(ctx, expo), flag[1],
                   "allowBackup is true in the Expo config and there are no rules excluding sensitive files.")
    elif rn_expo.config_mentions(ctx, expo, re.compile(r"allowBackup|dataExtractionRules|fullBackupContent")):
        ctx.note_unknown(f"{expo.path}: the app config or one of its local config plugins may set allowBackup or "
                         "backup rules.")
    else:
        line = expo.line("android") if expo.get("android") is not None or not expo.data else expo.line("expo")
        yield _hit(ctx, expo.path, line, "The Expo config doesn't set android.allowBackup, so it defaults to true: "
                                         "Android backs up the app's files, and there are no rules excluding "
                                         "sensitive files.")


# A file written under filesDir: File(filesDir, "name"), File(context.filesDir, "name"), openFileOutput("name", ...).
_FILES_DIR_WRITE = re.compile(r"\bFile\s*\(\s*(?P<dir>(?:[\w.]+\s*\.\s*)?(?:filesDir|getFilesDir\s*\(\s*\))|\w+)\s*,\s*"
                              r"\"(?P<name>[^\"\n/]{1,120})\"\s*\)|\bopenFileOutput\s*\(\s*\"(?P<out>[^\"\n/]{1,120})\"")
_SECRET_NAME = re.compile(r"(?i)secret|token|passw|credential|(?<![a-z])keys?(?![a-z])|private_?key|api_?key")


def _backed_up(section: Optional[Element], name: str) -> bool:
    """Does a backup rules section (<full-backup-content> or <cloud-backup>) back up filesDir/<name>?"""
    if section is None:
        return True
    def covers(el: Element) -> bool:
        p = (el.get("path") or ".").strip().strip("/")
        return (el.get("domain") or "") == "file" and p in (".", "", name)
    if any(covers(c) for c in section.iter("exclude")):
        return False
    includes = list(section.iter("include"))
    return not includes or any(covers(c) for c in includes)


def _secret_files_backed_up(ctx: Context, entry: _AppBackup, only_app: bool) -> Iterator[Hit]:
    """Backup rules exist, but a file the app writes under filesDir with a secret's name isn't excluded. With one
    app module, its libraries' code counts too; with several, only the module's own code."""
    sections: List[Optional[Element]] = []
    for attr, tag in (("android:dataExtractionRules", "cloud-backup"), ("android:fullBackupContent", None)):
        found = entry.attr(attr)
        if found is None or not found[2].startswith("@xml/"):
            continue
        roots = _resolve_xml(ctx, entry.module, found[2])
        if not roots:
            ctx.note_unknown(f"{found[0]}: {found[2]} wasn't found; check that it excludes sensitive files.")
            return
        for _p, root in roots:
            sections.append(next(iter(root.iter(tag)), None) if tag else root)
    if not sections:
        return
    prefix = entry.module + "/" if entry.module and not only_app else ""
    for path, code, _blank in _code_files_any(ctx, ("filesDir", "FilesDir", "openFileOutput")):
        if not path.startswith(prefix) or _scope(ctx, path) != "main":
            continue
        dirs = {d.group(1) for d in re.finditer(r"\b(?:val|var)\s+(\w+)\s*(?::\s*File\??\s*)?=\s*(?:[\w.]+\s*\.\s*)?"
                                                r"(?:filesDir|getFilesDir\s*\(\s*\))\s*$", code, re.MULTILINE)}
        for m in _sites(_FILES_DIR_WRITE.finditer(code)):
            name = m.group("name") or m.group("out")
            d = m.group("dir")
            if d is not None and not re.search(r"ilesDir", d) and d not in dirs:
                continue
            if not _SECRET_NAME.search(name) or not any(_backed_up(sec, name) for sec in sections):
                continue
            yield _hit(ctx, path, ctx.line_of(code, m.start()),
                       f"The app writes `{name}` to its files directory, and the backup rules don't exclude it, so "
                       "this secret is copied into backups.")


def _resolve_xml(ctx: Context, module: str, ref: str) -> List[Tuple[str, Element]]:
    if not ref.startswith("@xml/"):
        return []
    name = ref[5:].strip()
    found = []
    for path in ctx.files(".xml"):
        if path.endswith(f"/res/xml/{name}.xml"):
            root = _xml(ctx, path)
            if root is not None:
                found.append((path, root))
    own = [f for f in found if _module_of(f[0]) == module]
    return own or found


def _excludes(section: Element) -> bool:
    if any(c.tag == "exclude" for c in section.iter() if c is not section):
        return True
    includes = [c for c in section.iter("include")]
    return bool(includes) and not all((i.get("path") or ".").strip() in (".", "", "/") and
                                      (i.get("domain") or "") in ("root", "file", "database", "sharedpref", "")
                                      for i in includes)


@detector("android_backup_device_transfer")
def backup_device_transfer(ctx: Context, rule: Rule) -> Iterable[Hit]:
    apps, _libs = _backup_apps(ctx)
    target = None
    for entry in apps.values():
        if entry.main is None or entry.kind == "lib" or _custom_agent_only(entry):
            continue
        dxr = entry.attr("android:dataExtractionRules")
        fbc = entry.attr("android:fullBackupContent")
        ab = entry.attr("android:allowBackup")
        backup_off = ab is not None and not manifest.is_placeholder(ab[2]) and not xmlsafe.is_true(ab[2])
        if dxr is None:
            if target is None:
                target = _sdk_value(ctx, "targetSdk") or 0
            if target >= 31:
                path, app = entry.main
                if backup_off:
                    yield _hit(ctx, path, app.line,
                               "allowBackup=\"false\" stops cloud backup but not device-to-device transfer on Android "
                               f"12 and higher (targetSdk {target}); there are no dataExtractionRules to exclude "
                               "files from it.")
                    continue
                if fbc is not None and fbc[2].strip().lower() not in ("false", "true"):
                    yield _hit(ctx, path, app.line,
                               "fullBackupContent is set but dataExtractionRules isn't, so on Android 12 and higher "
                               f"(targetSdk {target}) device-to-device transfer doesn't follow these exclusions.")
                    continue
            elif target == 0:
                ctx.note_unknown("Backup rules check: masaudit couldn't find targetSdk to tell whether Android 12 "
                                 "device-transfer rules apply.")
        for attr in (dxr, fbc):
            if attr is None:
                continue
            for path, root in _resolve_xml(ctx, entry.module, attr[2]):
                if root.tag == "data-extraction-rules":
                    cloud = next((c for c in root.children if c.tag == "cloud-backup"), None)
                    d2d = next((c for c in root.children if c.tag == "device-transfer"), None)
                    if d2d is None:
                        if cloud is not None and _excludes(cloud):
                            yield _hit(ctx, path, cloud.line,
                                       "The rules exclude files from cloud backup but have no <device-transfer> "
                                       "section, so a device-to-device transfer copies those files.")
                        elif not backup_off:
                            yield _hit(ctx, path, root.line, "The data extraction rules exclude nothing from cloud "
                                                             "backup or device transfer.")
                    elif not _excludes(d2d):
                        yield _hit(ctx, path, d2d.line, "<device-transfer> excludes nothing, so every file moves to "
                                                        "a new device.")
                    if cloud is not None and not backup_off and not _excludes(cloud) and d2d is not None:
                        yield _hit(ctx, path, cloud.line, "<cloud-backup> excludes nothing, so every file is "
                                                          "uploaded to the user's cloud backup.")
                elif root.tag == "full-backup-content" and not backup_off and not _excludes(root):
                    yield _hit(ctx, path, root.line, "The backup rules exclude nothing, so every file is backed up.")


# ---------------------------------------------------------------------------- storage: libraries and prefs


def _deprecated_dependency(ctx: Context, coords: "re.Pattern[str]", imports: "re.Pattern[str]",
                           what: str, import_needle: str) -> Iterator[Hit]:
    """`import_needle`: a literal every match of `imports` contains."""
    for path in ctx.files(".gradle", ".kts", ".toml"):
        if path.endswith(".toml"):
            for lineno, line in gradle.toml_lines(ctx.text(path) or ""):
                if coords.search(line):
                    yield _hit(ctx, path, lineno, f"The version catalog declares {what}.")
            continue
        if path.rsplit("/", 1)[-1] not in BUILD_FILES:
            continue
        code = ctx.code(path) or ""
        for m in coords.finditer(code):
            yield _hit(ctx, path, ctx.line_of(code, m.start()), f"The build depends on {what}.")
    # Imports: one finding per module, at the first file, so a migration shows up once.
    per_module: Dict[str, List[Tuple[str, int]]] = {}
    for path, _code, blank in _code_files(ctx, import_needle):
        m = imports.search(blank)
        if m:
            per_module.setdefault(_module_of(path) + "|" + _scope(ctx, path), []).append(
                (path, ctx.line_of(blank, m.start())))
    for files in per_module.values():
        path, line = files[0]
        more = f" ({len(files) - 1} more file{'s' if len(files) > 2 else ''} in this module)" if len(files) > 1 else ""
        yield _hit(ctx, path, line, f"This file uses {what}{more}.")


@detector("android_security_crypto")
def security_crypto(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _deprecated_dependency(
        ctx,
        re.compile(r"androidx\.security:security-crypto|group\s*=\s*[\"']androidx\.security[\"'][^\n]*"
                   r"name\s*=\s*[\"']security-crypto|\bAndroidX\.security\.crypto\b"),
        re.compile(r"^[ \t]*import\s+androidx\.security\.crypto\.", re.MULTILINE),
        "the deprecated Jetpack Security library (androidx.security:security-crypto)",
        "androidx.security.crypto.",
    )


@detector("android_sqlcipher_legacy")
def sqlcipher_legacy(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _deprecated_dependency(
        ctx,
        re.compile(r"net\.zetetic:android-database-sqlcipher|group\s*=\s*[\"']net\.zetetic[\"'][^\n]*"
                   r"name\s*=\s*[\"']android-database-sqlcipher"),
        re.compile(r"^[ \t]*import\s+net\.sqlcipher\.", re.MULTILINE),
        "the end-of-life SQLCipher package (net.zetetic:android-database-sqlcipher)",
        "net.sqlcipher.",
    )


@detector("android_tink_keystore")
def tink_keystore(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "AndroidKeysetManager", "withMasterKeyUri"):
        if "AndroidKeysetManager" not in blank or "isUsingKeystore" in blank:
            continue
        m = re.search(r"\bwithMasterKeyUri\s*\(", blank)
        if m:
            line = ctx.line_of(blank, m.start())
            yield _hit(ctx, path, line,
                       "The keyset uses a Keystore master key, but nothing checks isUsingKeystore() "
                       "for Tink's silent cleartext fallback.")


_SENSITIVE_KEY = re.compile(r"(?i)token|password|passwd|secret|jwt|credential|api_?key|private_?key|pin_?code")
_NOT_SENSITIVE = re.compile(r"(?i)fcm|push|apns|firebase|notification|messaging|device_?token|csrf_?header")
_PREFS_WRITE = re.compile(r"(?<![\w$])putString\s*\(\s*(\"[^\"\n]*\"|[A-Za-z_][\w.]*)\s*,")
_DATASTORE_KEY = re.compile(
    r"\b(?:stringPreferencesKey|stringSetPreferencesKey|preferencesKey\s*<\s*String\s*>)\s*\(\s*"
    r"(\"[^\"\n]*\"|[A-Za-z_][\w.]*)\s*\)"
)
# A file that encrypts (Tink, a Cipher, or an encryptor) is assumed to store ciphertext.
_ENCRYPTS = re.compile(r"(?i)encrypt|\baead\b|\bcipher\b|tink")
_EDIT_BLOCK = re.compile(r"\bedit\s*(?:\([^(){}]*\))?\s*\{")
_BUNDLE_RECEIVER = re.compile(r"^(?:outState|savedInstanceState|arguments|args|bundle|extras|result|intent|data|b|"
                              r"options|values|contentValues|cv|state|out)$", re.IGNORECASE)


def _key_name(code: str, arg: str) -> str:
    """The key's text: the literal itself, or a constant's name plus its value."""
    if arg.startswith('"'):
        return arg.strip('"')
    name = arg.rsplit(".", 1)[-1]
    found = text_memo(code, ("key", name), lambda: re.search(
        r"\b" + re.escape(name) + r"\s*(?::\s*String)?\s*=\s*\"([^\"\n]*)\"", code))
    return name + " " + (found.group(1) if found else "")


class _Statements:
    """Where _is_prefs_editor's statement starts, for many offsets in one text. Walking back to the last
    `;`, `{`, or `}` and over the lines of a chain, and copying the text before each line to strip it, cost
    a pass over the file per call; this indexes the same facts once."""

    def __init__(self, blank: str):
        self.marks = [m.start() for m in re.finditer(r"[;{}]", blank)]
        self.newlines = [m.start() for m in re.finditer(r"\n", blank)]
        # For newline k: the last non-whitespace character before it ends with `.`, `(`, or `,` (the
        # walk's `blank[:nl].rstrip().endswith(...)`), and the walk passes it from the line below.
        self.prev_ends: List[bool] = []
        self.passes: List[bool] = []
        last = ""
        for k, nl in enumerate(self.newlines):
            seg = blank[(self.newlines[k - 1] if k else 0):nl].rstrip()
            if seg:
                last = seg[-1]
            self.prev_ends.append(last in (".", "(", ","))
            line_end = self.newlines[k + 1] if k + 1 < len(self.newlines) else len(blank)
            self.passes.append(blank[nl:line_end].lstrip().startswith(".") or self.prev_ends[k])
        # For newline k: the last newline at or before it that the walk stops at, or -1.
        self.stop: List[int] = []
        for k, passes in enumerate(self.passes):
            self.stop.append(self.stop[k - 1] if passes and k else (-1 if passes else k))

    def start(self, blank: str, idx: int) -> int:
        k = bisect.bisect_left(self.marks, idx) - 1
        stmt_start = self.marks[k] if k >= 0 else -1
        k = bisect.bisect_left(self.newlines, idx) - 1             # the newline before idx
        if k < 0 or self.newlines[k] <= stmt_start:
            return stmt_start
        nl = self.newlines[k]
        if not (blank[nl:idx].lstrip().startswith(".") or self.prev_ends[k]):
            return max(stmt_start, nl)
        k = self.stop[k - 1] if k else -1                           # walk on over whole lines
        return max(stmt_start, self.newlines[k]) if k >= 0 else stmt_start


# Recent texts _is_prefs_editor was asked about: [text, _Statements once asked twice].
_STATEMENTS: List[list] = []


def _statement_start(blank: str, idx: int) -> int:
    """The offset before the statement holding the `.putString(` at idx (see _is_prefs_editor)."""
    if 0 <= idx <= len(blank):
        for entry in _STATEMENTS:
            if entry[0] is blank:
                if entry[1] is None:
                    entry[1] = _Statements(blank)
                return entry[1].start(blank, idx)
        _STATEMENTS.insert(0, [blank, None])
        del _STATEMENTS[4:]
    stmt_start = max(blank.rfind(";", 0, idx), blank.rfind("{", 0, idx), blank.rfind("}", 0, idx))
    j = idx
    while True:          # walk back over a chain split across lines (`prefs.edit()\n  .putString(`)
        nl = blank.rfind("\n", 0, j)
        if nl == -1 or nl <= stmt_start:
            break
        prev = blank[:nl].rstrip()
        if blank[nl:j].lstrip().startswith(".") or prev.endswith((".", "(", ",")):
            j = nl
            continue
        stmt_start = max(stmt_start, nl)
        break
    return stmt_start


# A character no receiver expression's tail (`name`, `name!!`, `name?.`, whitespace) can contain.
_HARD = re.compile(r"[^\w\s?.!]")


def _chain_facts(blank: str, start: int, idx: int) -> Tuple[bool, str, bool]:
    """For the call chain blank[start:idx] before a `.putString(`: (it calls `.edit()`, the receiver's name,
    the chain is empty or `this`/`it` once a trailing `?.` is dropped). A chain of thousands of
    continuation lines made each of these a pass over the whole chain per call. For a long chain they
    are read from its tail after the last character no receiver can contain (so the receiver and the
    dropped `?.` lie after it, and the chain isn't empty), and `.edit()` from the file's matches (the
    pattern has no anchors, and two matches can't overlap)."""
    if idx - start > 4096:
        hard = next((j for j in range(idx - 1, idx - 4097, -1) if _HARD.match(blank, j)), None)
        if hard is not None:
            edits = text_memo(blank, ("edit_calls",), lambda: [
                (e.start(), e.end()) for e in re.finditer(r"\.\s*edit\s*\(\s*\)", blank)])
            k = bisect.bisect_left(edits, (start, -1))
            tail = re.sub(r"\s*\??\s*\.\s*$", "", blank[hard:idx])
            recv = re.search(r"(\w+)\s*(?:!!)?\s*$", tail)
            return k < len(edits) and edits[k][1] <= idx, recv.group(1) if recv else "", False
    chain = blank[start:idx]
    has_edit = bool(re.search(r"\.\s*edit\s*\(\s*\)", chain))
    chain = re.sub(r"\s*\??\s*\.\s*$", "", chain)
    recv = re.search(r"(\w+)\s*(?:!!)?\s*$", chain)
    return has_edit, recv.group(1) if recv else "", not chain.strip() or chain.strip() in ("this", "it")


def _is_prefs_editor(blank: str, idx: int) -> bool:
    """Is the `.putString(` at idx called on a SharedPreferences.Editor (not a Bundle or an Intent)?"""
    stmt_start = _statement_start(blank, idx)
    has_edit, name, bare = _chain_facts(blank, stmt_start + 1, idx)
    if has_edit:
        return True
    if name and _BUNDLE_RECEIVER.match(name):
        return False
    close = _match(blank, blank.index("(", idx), "(", ")")
    if re.match(r"\s*\.\s*(?:apply|commit)\s*\(\s*\)", blank[close + 1:close + 80]):
        return True
    if name:
        decl = text_memo(blank, ("editor", name), lambda: re.search(
            r"(?:\bEditor\s+" + re.escape(name) + r"\b|\b" + re.escape(name) +
            r"\s*(?::\s*(?:SharedPreferences\.)?Editor\??)?\s*=\s*[\w.()?!\s]*\.edit\s*\(\s*\))", blank))
        if decl:
            return True
    if bare:
        for m in _EDIT_BLOCK.finditer(blank, max(0, idx - 3000), idx):
            if _match(blank, m.end() - 1, "{", "}") > idx:
                prefix = blank[max(0, m.start() - 120):m.start()]
                return not re.search(r"\b(?:Bundle|Intent|ContentValues)\s*\(", prefix)
    return False


# Text the user typed, stored as it is.
_TYPED_TEXT = re.compile(r"\.\s*getText\s*\(\s*\)|\.\s*text\s*\.\s*toString\s*\(\s*\)")


def _plain_value(code: str, blank: str, open_paren: int) -> bool:
    """In a file that encrypts: is the value of the putString( at open_paren visibly plain text? Only a string
    literal, typed text, or a variable initialized with one counts. Anything else may be ciphertext."""
    spans = _args(blank, open_paren)
    if len(spans) < 2:
        return False
    value = code[spans[1][0]:spans[1][1]].strip()
    if _ENCRYPTS.search(value):
        return False
    if re.fullmatch(r"\"[^\"\n]*\"", value) or _TYPED_TEXT.search(value):
        return True
    name = re.fullmatch(r"(?:this\s*\.\s*)?(\w+)(?:\s*!!)?(?:\s*\.\s*toString\s*\(\s*\))?", value)
    if not name:
        return False
    plain, sealed = text_memo(code, ("plain_vars",), lambda: _plain_vars(code))
    return name.group(1) in plain and name.group(1) not in sealed


def _plain_vars(code: str) -> Tuple[Set[str], Set[str]]:
    """(variables first declared with a string literal or typed text, variables assigned an encrypt call),
    from one pass over the file."""
    plain: Set[str] = set()
    declared: Set[str] = set()
    for d in re.finditer(r"\b(?:val|var|String)\s+(\w+)\s*(?::\s*String\??\s*)?=\s*([^\n;]*)", code):
        if d.group(1) in declared:
            continue
        declared.add(d.group(1))
        if re.fullmatch(r"\s*\"[^\"\n]*\"\s*", d.group(2)) or _TYPED_TEXT.search(d.group(2)):
            plain.add(d.group(1))
    sealed = {a.group(1) for a in re.finditer(r"(?<![\w.])(\w+)[ \t]*=(?!=)([^\n;=]*)", code)
              if re.search(r"(?i)encrypt|cipher|aead|seal", a.group(2))}
    return plain, sealed


@detector("android_prefs_token")
def prefs_token(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".kt", ".java"):
        raw = ctx.text(path) or ""
        if "putString" not in raw and "PreferencesKey" not in raw and "preferencesKey" not in raw:
            continue
        if "EncryptedSharedPreferences" in raw:
            continue                                   # AND-022 covers the deprecated wrapper
        code = ctx.code(path, keep_strings=True) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        # A file that encrypts may store ciphertext: judge each value there, and skip DataStore keys (the value
        # isn't visible where the key is declared).
        encrypts = bool(_ENCRYPTS.search(blank))
        seen: Set[int] = set()
        for regex, store in ((_PREFS_WRITE, "SharedPreferences"), (_DATASTORE_KEY, "DataStore")):
            if encrypts and store == "DataStore":
                continue
            for m in regex.finditer(code):
                key = _key_name(code, m.group(1))
                if not _SENSITIVE_KEY.search(key) or _NOT_SENSITIVE.search(key):
                    continue
                if store == "SharedPreferences" and not _is_prefs_editor(blank, m.start() + m.group(0).index("putString")):
                    continue
                if encrypts and not _plain_value(code, blank, m.start() + m.group(0).index("(")):
                    continue
                line = ctx.line_of(code, m.start())
                if line in seen:
                    continue
                seen.add(line)
                yield _hit(ctx, path, line, f"A value under the key `{m.group(1).strip(chr(34))}` is stored "
                                            f"in plain {store}.")


# ---------------------------------------------------------------------------- storage: files

_PUBLIC_WRITE = re.compile(r"\bgetExternalStoragePublicDirectory\s*\(|\bEnvironment\s*\.\s*getExternalStorageDirectory"
                           r"\s*\(|\bEnvironment\s*\.\s*externalStorageDirectory\b|\bMediaStore\s*\.\s*(?:Downloads|Files)"
                           r"\s*\.\s*(?:EXTERNAL_CONTENT_URI|getContentUri)")
_PUBLIC_WRITE_NEEDLES = ("getExternalStoragePublicDirectory", "getExternalStorageDirectory", "externalStorageDirectory",
                         "MediaStore")
_SENSITIVE_FILE = re.compile(r"(?i)\"[^\"\n]*(?:token|backup|export|\.db|database|statement|report|logs?|secret|"
                             r"\.key|keystore)[^\"\n]*\"")
_SHARED_WRITE = re.compile(r"\bFileOutputStream\s*\(|\.writeBytes\s*\(|\.writeText\s*\(|\.outputStream\s*\(|\.copyTo\s*\("
                           r"|\bcreateNewFile\s*\(|\bopenOutputStream\s*\(|\bFiles\s*\.\s*(?:write|copy)\s*\(|\.renameTo\s*\("
                           r"|\bFileWriter\s*\(|\.insert\s*\(|\bsink\s*\(|\bDownloadManager\.Request\b"
                           r"|setDestinationInExternalPublicDir")


# File names and written text that mark a secret (narrower than _SENSITIVE_FILE: an export or a report saved to
# Downloads is usually what the user asked for).
_SECRET_FILE_NAME = re.compile(r"(?i)\"[^\"\n]*(?:secret|token|passw|credential|private_?key|api_?key|\.key\b|keystore"
                               r"|\.db\b|database)[^\"\n]*\"")
_SECRET_CONTENT = re.compile(r"(?i)\"[^\"\n]*(?:passw|secret|api_?key|token|private_?key)[^\"\n]*\"\s*\.\s*"
                             r"(?:toByteArray|getBytes)\s*\(")


def _mediastore_secret(ctx: Context, path: str, code: str, blank: str, idx: int, seen: Set[int]) -> Optional[Hit]:
    lo, hi, _fn = _function_at(blank, idx)
    if lo in seen or not re.search(r"\.\s*insert\s*\(", blank[lo:hi]):
        return None
    body = code[lo:hi]
    if not (_SECRET_FILE_NAME.search(body) or _SECRET_CONTENT.search(body)):
        return None
    seen.add(lo)
    return _hit(ctx, path, ctx.line_of(blank, idx),
                "The app saves a file to the shared Downloads or Files collection, which the user and other apps can "
                "open, and its name or content suggests a secret.")


@detector("android_external_storage")
def external_storage(ctx: Context, rule: Rule) -> Iterable[Hit]:
    broad = None
    for path, root in _manifests(ctx):
        if not _release_path(ctx, path):
            continue
        for p in manifest.uses_permissions(root):
            name = (p.get("android:name") or "").rsplit(".", 1)[-1]
            max_sdk = (p.get("android:maxSdkVersion") or "").strip()
            if name == "MANAGE_EXTERNAL_STORAGE" or (name == "WRITE_EXTERNAL_STORAGE" and not (
                    (small_int(max_sdk) is not None and small_int(max_sdk) <= 28))):
                broad = broad or f"{name} in {path}"
        for app in manifest.applications(root):
            if xmlsafe.is_true(app.get("android:requestLegacyExternalStorage")):
                broad = broad or f"requestLegacyExternalStorage in {path}"
    for path, code, blank in _code_files_any(ctx, _PUBLIC_WRITE_NEEDLES):
        seen: Set[int] = set()
        for m in _sites(_PUBLIC_WRITE.finditer(blank)):
            if _is_import(blank, m.start()):
                continue
            if broad is None:
                # Without broad storage access, only a MediaStore Downloads or Files insert reaches shared storage
                # (no permission is needed for it), and only one that looks sensitive is reported.
                if "MediaStore" in m.group(0):
                    hit = _mediastore_secret(ctx, path, code, blank, m.start(), seen)
                    if hit is not None:
                        yield hit
                continue
            lo, hi, _fn = _function_at(blank, m.start())
            if lo in seen:
                continue
            body = blank[lo:hi]
            # a write in the same function: a path computed for reading or display isn't a leak
            wm = _SHARED_WRITE.search(body)
            if not wm or ("MediaStore" in m.group(0) and "insert" not in body):
                continue
            seen.add(lo)
            line = ctx.line_of(blank, m.start())
            if _SENSITIVE_FILE.search(code[lo:hi]):
                yield _hit(ctx, path, line, f"The app writes to shared storage, which other apps can read ({broad}). "
                                            "The file names suggest sensitive data.")
            else:
                yield _hit(ctx, path, line,
                           f"The app writes to shared storage, which other apps can read ({broad}). Nothing here "
                           "suggests sensitive data, as with a download or export the user asked for; check what "
                           "ends up there.", severity="low")


_WORLD_MODE = re.compile(r"\bMODE_WORLD_(?:READABLE|WRITEABLE)\b|\bset(?:Readable|Writable|Executable)\s*\(\s*true\s*,"
                         r"\s*false\s*\)")


@detector("android_world_readable")
def world_readable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files_any(ctx, ("MODE_WORLD_", "setReadable", "setWritable", "setExecutable")):
        if "MODE_WORLD" not in blank and "true" not in blank:
            continue
        for m in _WORLD_MODE.finditer(blank):
            if _is_import(blank, m.start()):
                continue
            what = "Every app on the device can read or write this file." if "MODE_" in m.group(0) else \
                "This file is opened up to every app on the device (owner-only flag is false)."
            yield _hit(ctx, path, ctx.line_of(blank, m.start()), what)


# ---------------------------------------------------------------------------- biometrics and keys

_AUTHENTICATE = re.compile(r"\.authenticate\s*\(")


@detector("android_biometric_no_crypto")
def biometric_no_crypto(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "BiometricPrompt"):
        framework_only = "android.hardware.biometrics" in blank and "androidx.biometric" not in blank
        for m in _AUTHENTICATE.finditer(blank):
            n = len(_args(blank, m.end() - 1))
            if (framework_only and n == 3) or (not framework_only and n == 1):
                line = ctx.line_of(blank, m.start())
                yield _hit(ctx, path, line,
                           "BiometricPrompt.authenticate() is called without a CryptoObject, "
                           "so the result is a boolean a hook can fake.")


_INVALIDATED_FALSE = re.compile(r"\bsetInvalidatedByBiometricEnrollment\s*\(\s*false\s*\)")
_AUTH_PARAMS = re.compile(r"\bsetUserAuthenticationParameters\s*\(")
_VALIDITY = re.compile(r"\bsetUserAuthenticationValidityDurationSeconds\s*\(\s*(\d+)\s*\)")


@detector("android_biometric_enrollment")
def biometric_enrollment(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "KeyGenParameterSpec"):
        for m in _INVALIDATED_FALSE.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "setInvalidatedByBiometricEnrollment(false): the key keeps working after "
                       "someone adds a new fingerprint or face.")
        if not re.search(r"setUserAuthenticationRequired\s*\(\s*true\s*\)", blank):
            continue
        for m in _AUTH_PARAMS.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if len(spans) != 2:
                continue
            timeout = blank[spans[0][0]:spans[0][1]].strip()
            kinds = blank[spans[1][0]:spans[1][1]]
            if "AUTH_DEVICE_CREDENTIAL" in kinds and "AUTH_BIOMETRIC_STRONG" in kinds:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "The key also accepts the device PIN, so Android doesn't invalidate it when "
                           "biometrics change.")
            elif (small_int(timeout) or 0) > 0:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"The key stays unlocked for {timeout} seconds after authentication, so it isn't "
                           "tied to each use or invalidated on new enrollment.")
        for m in _VALIDITY.finditer(blank):
            if (small_int(m.group(1)) or 0) > 0:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"The key stays unlocked for {m.group(1)} seconds after authentication, so it isn't "
                           "tied to each use or invalidated on new enrollment.")


_VALIDITY_CALL = re.compile(r"\b(?:setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds)\s*\(")
_LONG_VALIDITY = 30          # seconds; a few seconds covers one unlock followed by its crypto operations


def _seconds(expr: str, code: str) -> Optional[int]:
    """The value of a duration argument: an integer literal, a product of literals (`60 * 60 * 24`), or a
    constant set to one in the same file. None when masaudit can't tell."""
    e = expr.strip()
    const = re.fullmatch(r"(?:[A-Za-z_]\w*\.)*([A-Z][A-Z0-9_]*)", e)
    if const:
        m = re.search(r"\b" + re.escape(const.group(1)) + r"\s*(?::\s*Int\s*)?=[ \t]*(-?[\d_ \t*L]+?)[ \t]*(?:;|$)", code,
                      re.MULTILINE)
        e = m.group(1).strip() if m else ""
    if not re.fullmatch(r"-?\d[\d_]*L?(?:\s*\*\s*\d[\d_]*L?)*", e):
        return None
    value = 1
    for part in e.split("*"):
        n = small_int(part.strip().rstrip("L").replace("_", ""))
        if n is None:
            return None                  # an absurd literal: no real duration needs 19 digits
        value *= n
    return value


@detector("android_auth_validity_long")
def auth_validity_long(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "KeyGenParameterSpec", "UserAuthentication"):
        for m in _sites(_VALIDITY_CALL.finditer(blank)):
            spans = _args(blank, m.end() - 1)
            if not spans:
                continue
            seconds = _seconds(code[spans[0][0]:spans[0][1]], code)
            if seconds is None or seconds <= _LONG_VALIDITY:
                continue          # 0 or -1: authentication for every use; a short window is accepted
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       f"After one authentication the key stays usable for {seconds} seconds, so anyone holding the "
                       "unlocked phone in that window can use it without the biometric prompt.")


_ALLOWED_AUTH = re.compile(r"\bsetAllowedAuthenticators\s*\(|\bcanAuthenticate\s*\(")


@detector("android_biometric_weak")
def biometric_weak(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "BIOMETRIC_WEAK"):
        for m in _ALLOWED_AUTH.finditer(blank):
            spans = _args(blank, m.end() - 1)
            arg = " ".join(code[s:e] for s, e in spans)
            if "canAuthenticate" in m.group(0) and "BIOMETRIC_STRONG" in blank:
                continue          # a capability check next to a Class 3 check, not the prompt's policy
            if "BIOMETRIC_WEAK" in arg and "BIOMETRIC_STRONG" not in arg:
                what = "accepts" if "setAllowed" in m.group(0) else "checks for"
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"The biometric prompt {what} Class 2 (weak) biometrics, which can't unlock a "
                           "Keystore key and are easier to spoof.")


_CONFIRM_FALSE = re.compile(r"\bsetConfirmationRequired\s*\(\s*false\s*\)|\bconfirmationRequired\s*=\s*false\b")


@detector("android_biometric_no_confirmation")
def biometric_no_confirmation(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "onfirmationRequired", "Biometric"):
        for m in _CONFIRM_FALSE.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "The biometric prompt doesn't ask for an explicit confirmation, so a passive face unlock "
                       "approves the action as soon as the face is seen.")


_RANDOM_IV_OFF = re.compile(r"\bsetRandomizedEncryptionRequired\s*\(\s*false\s*\)|\bisRandomizedEncryptionRequired\s*="
                            r"\s*false\b")


@detector("android_keystore_caller_iv")
def keystore_caller_iv(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "RandomizedEncryptionRequired"):
        for m in _RANDOM_IV_OFF.finditer(blank):
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "setRandomizedEncryptionRequired(false) lets callers choose the IV, so a repeated IV can "
                       "expose plaintext.")


_KGPS = re.compile(r"\bKeyGenParameterSpec\s*\.\s*Builder\s*\(")
_ENC_PURPOSE = re.compile(r"\bPURPOSE_(?:ENCRYPT|DECRYPT)\b")
_SIGN_PURPOSE = re.compile(r"\bPURPOSE_(?:SIGN|VERIFY|WRAP_KEY)\b")


@detector("android_key_multi_purpose")
def key_multi_purpose(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "KeyGenParameterSpec"):
        for m in _KGPS.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if len(spans) < 2:
                continue
            purposes = code[spans[1][0]:spans[1][1]]
            mixed = _ENC_PURPOSE.search(purposes) and _SIGN_PURPOSE.search(purposes)
            lit = purposes.strip()
            odd = small_int(lit) is not None and small_int(lit) not in (1, 2, 3, 4, 8, 12, 32)
            if mixed or odd:
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           "This Keystore key is allowed to both encrypt and sign (or wrap keys), so a weakness in "
                           "one use can break the other.")


_PROVIDER_ARG = re.compile(r"\bgetInstance\s*\(")
_BAD_PROVIDER = re.compile(r"^\s*(?:\"(?:BC|SC|Crypto|BouncyCastle|SpongyCastle)\"|(?:new\s+)?BouncyCastleProvider\s*\(\s*\)"
                           r"|BouncyCastleProvider\.PROVIDER_NAME)\s*$")
_ADD_PROVIDER = re.compile(r"\bSecurity\s*\.\s*(?:addProvider|insertProviderAt)\s*\(")


@detector("android_crypto_provider")
def crypto_provider(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files(ctx, "getInstance"):
        for m in _PROVIDER_ARG.finditer(blank):
            spans = _args(blank, m.end() - 1)
            if len(spans) != 2:
                continue
            prov = code[spans[1][0]:spans[1][1]]
            if _BAD_PROVIDER.match(prov):
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"This crypto call names the provider {prov.strip()}, which bypasses the platform's "
                           "maintained implementation.")
    for path, code, blank in _code_files(ctx, "Security"):
        for m in _ADD_PROVIDER.finditer(blank):
            spans = _args(blank, m.end() - 1)
            arg = code[spans[0][0]:spans[0][1]] if spans else ""
            if re.search(r"Conscrypt|AndroidOpenSSL|AndroidKeyStore", arg):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       f"The app installs its own security provider ({arg.strip()[:40]}), which replaces the "
                       "platform's maintained implementation for later crypto calls.")


# ---------------------------------------------------------------------------- input fields

_SECRET_WORDS = {"password", "passwd", "passcode", "pin", "pincode"}
_SENSITIVE_WORDS = {"otp", "cvv", "cvc", "cvv2", "iban", "ssn"}
_SENSITIVE_PAIRS = {("card", "number"), ("account", "number"), ("security", "code"), ("verification", "code"),
                    ("one", "time")}
_EDIT_NEW = re.compile(r"(?<![\w.])(?:new\s+)?(?:EditText|AppCompatEditText|TextInputEditText)\s*\(")
# Input types that keep the keyboard from learning: password variations and the no-suggestions flag.
_NO_LEARN = re.compile(r"PASSWORD|NO_SUGGESTIONS|NO_PERSONALIZED_LEARNING|[Pp]assword|textNoSuggestions"
                       r"|flagNoPersonalizedLearning")


_XML_EDIT_TEXT = re.compile(r"<(?:[\w.]+\.)?(?:EditText|TextInputEditText|AppCompatEditText)\b")
def _field_kind(text: str) -> str:
    """"secret" (password, PIN), "sensitive" (one-time code, card or account number), or ""."""
    tokens = [t for piece in re.findall(r"[A-Za-z0-9]+", text) for t in _camel(piece)]
    if any(t in _SECRET_WORDS for t in tokens):
        return "secret"
    if any(t in _SENSITIVE_WORDS for t in tokens) or any(p in _SENSITIVE_PAIRS for p in zip(tokens, tokens[1:])):
        return "sensitive"
    return ""


def _learns(kind: str, input_type: Optional[str]) -> bool:
    """Does a field of this kind with this input type let the keyboard learn what is typed? A password or PIN
    field needs a password type or no suggestions; another sensitive field only when it takes free text."""
    if input_type is not None and _NO_LEARN.search(input_type):
        return False
    if kind == "secret":
        return True
    return input_type is None or not re.search(r"(?i)number|phone|datetime|date\b", input_type)


@detector("android_keyboard_cache")
def keyboard_cache(ctx: Context, rule: Rule) -> Iterable[Hit]:
    # Layout XML: password and PIN fields belong to XPL-033 (shown and learned); here, other sensitive fields.
    for path in ctx.files(".xml"):
        if "/res/layout" not in "/" + path:
            continue
        text = ctx.text(path) or ""
        if "EditText" not in text:
            continue
        clean = _XML_COMMENT.sub(lambda c: re.sub(r"[^\n]", " ", c.group(0)), text)
        for at, tag in xml_tags(clean, _XML_EDIT_TEXT):
            names = " ".join(re.findall(r"android:(?:id|hint|autofillHints)\s*=\s*\"([^\"]*)\"", tag))
            if _field_kind(names) != "sensitive" or "android:password=\"true\"" in tag or _NO_LEARN.search(tag):
                continue
            it = re.search(r"android:inputType\s*=\s*\"([^\"]*)\"", tag)
            if _learns("sensitive", it.group(1) if it else None):
                yield _hit(ctx, path, ctx.line_of(clean, at),
                           "This field takes a one-time code, card or account number as free text, so the keyboard "
                           "can learn it and suggest it later (no textNoSuggestions).")
    # Code: an EditText built in Kotlin or Java, with its hint and the last input type it is given.
    for path, code, blank in _code_files_any(ctx, ("EditText(",)):
        for m in _sites(_EDIT_NEW.finditer(blank)):
            lo, hi, _fn = _function_at(blank, m.start())
            end = _match(blank, m.end() - 1, "(", ")")
            block = re.match(r"\s*\.\s*(?:apply|also)\s*\{", blank[end + 1:end + 40])
            region_end = _match(blank, end + 1 + block.end() - 1, "{", "}") if block else end
            region = code[m.start():region_end + 1]
            var = re.search(r"\b(?:val|var)\s+(\w+)\s*(?::\s*\w+\s*)?=\s*$|\b(?:EditText|\w*EditText)\s+(\w+)\s*=\s*$",
                            blank[max(lo, m.start() - 80):m.start()])
            name = (var.group(1) or var.group(2)) if var else None
            later = ""
            if name:
                later = " ".join(x.group(0) for x in re.finditer(
                    r"\b" + re.escape(name) + r"\s*\.\s*(?:hint\s*=|setHint\s*\(|inputType\s*=|setInputType\s*\("
                    r"|imeOptions\s*=|setImeOptions\s*\()[^\n;]*", code[region_end + 1:hi]))
            hint = re.search(r"(?:\bhint\s*=|\bsetHint\s*\()\s*\"([^\"\n]*)\"", region + " " + later)
            kind = _field_kind(hint.group(1)) if hint else ""
            if not kind or re.search(r"(?:imeOptions\s*=|setImeOptions\s*\()[^\n;]*NO_PERSONALIZED_LEARNING",
                                     region + " " + later):
                continue
            types = list(re.finditer(r"(?:\binputType\s*=|\bsetInputType\s*\()\s*([^\n;]*)", region + " " + later))
            input_type = types[-1].group(1) if types else None
            if input_type is not None and not re.search(r"InputType\s*\.|TYPE_", input_type):
                continue          # a type masaudit can't resolve
            if _learns(kind, input_type):
                what = "password or PIN" if kind == "secret" else "one-time code, card or account number"
                yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                           f"This {what} field's input type lets the keyboard learn what is typed and suggest it "
                           "later (no password type or TYPE_TEXT_FLAG_NO_SUGGESTIONS).")


# ---------------------------------------------------------------------------- privacy: identifiers

_HW_ID = re.compile(
    r"\bSettings\s*\.\s*Secure\s*\.\s*ANDROID_ID\b|\bSecure\s*\.\s*getString\s*\([^)]*\"android_id\"|"
    r"\bBuild\s*\.\s*(?:getSerial\s*\(\s*\)|SERIAL\b)|"
    r"(?:\b\w*(?:[Tt]elephony|[Pp]hone|\btm|\bTM)\w*\s*\??|\))\s*\.\s*(?:getDeviceId|getImei|getMeid"
    r"|getSimSerialNumber|getSubscriberId)\s*\(|"
    r"\bgetMacAddress\s*\(\s*\)|\bgetHardwareAddress\s*\(\s*\)|\.\s*hardwareAddress\b|"
    r"\b(?:wifiInfo|connectionInfo|info)\s*\??\s*\.\s*macAddress\b|"
    r"\b\w*(?:[Tt]elephony|[Pp]hone)\w*\s*\??\s*\.\s*(?:imei|meid|deviceId|simSerialNumber|subscriberId)\b|"
    r"\b\w*[Aa]dapter\s*\??\s*\.\s*(?:address\b|getAddress\s*\(\s*\))")


@detector("android_hardware_id")
def hardware_id(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _code_files_any(ctx, ("ANDROID_ID", "android_id", "Telephony", "getSerial", "SERIAL",
                                                   "MacAddress", "macAddress", "HardwareAddress", "hardwareAddress",
                                                   "BluetoothAdapter")):
        raw = ctx.text(path) or ""
        tele = "Telephony" in raw
        bt = "Bluetooth" in raw
        for m in _sites(_HW_ID.finditer(code)):
            if _is_import(blank, m.start()) or blank[m.start()] == " ":
                continue
            text = m.group(0)
            if re.search(r"get(?:DeviceId|Imei|Meid|SimSerialNumber|SubscriberId)", text) and not tele:
                continue
            if text.startswith(")") and not re.search(r"TelephonyManager|TELEPHONY_SERVICE",
                                                      code[max(0, m.start() - 150):m.start()]):
                continue          # `(... as TelephonyManager).getImei()`, not `account().getDeviceId()`
            if "dapter" in text and not bt:
                continue
            kind = "ANDROID_ID" if "ANDROID_ID" in text or "android_id" in text else "a hardware identifier"
            yield _hit(ctx, path, ctx.line_of(code, m.start()),
                       f"The app reads {kind} ({text.lstrip(').').strip()[:40]}), which can track the user across "
                       "apps or resets.")


# ---------------------------------------------------------------------------- input from other apps

_DISPLAY_NAME = re.compile(r"\bOpenableColumns\s*\.\s*DISPLAY_NAME\b|\"_display_name\"|\.\s*lastPathSegment\b|"
                           r"\bgetLastPathSegment\s*\(\s*\)|\bDocumentFile\b[^\n;]*\.\s*(?:name\b|getName\s*\(\s*\))")
_FOREIGN_URI = re.compile(r"EXTRA_STREAM|clipData|ACTION_SEND|ACTION_VIEW|getIntent\(\)\s*\.\s*getData|\bintent\??\.data\b"
                          r"|GetContent|OpenDocument|ACTION_GET_CONTENT|ACTION_OPEN_DOCUMENT")
_FILE_SINK = re.compile(r"\b(?:File|FileOutputStream|openFileOutput)\s*\(")
_SANITIZED = re.compile(r"canonical(?:Path|File)|getCanonical|normalize\s*\(|toRealPath|\.name\b(?!\s*\()|\bgetName\s*\(\s*"
                        r"\)|replace\s*\(\s*Regex|replaceAll\s*\(|\bsanitiz|\bUUID\b|\.substringAfterLast\s*\(\s*['\"/]")


@detector("android_dirty_stream")
def dirty_stream(ctx: Context, rule: Rule) -> Iterable[Hit]:
    # Every _DISPLAY_NAME alternative contains one of these ("astPathSegment" covers both spellings).
    for path, code, blank in _code_files_any(ctx, ("OpenableColumns", "_display_name", "astPathSegment",
                                                   "DocumentFile")):
        if not _DISPLAY_NAME.search(code):
            continue
        seen: Set[int] = set()
        for m in _sites(_DISPLAY_NAME.finditer(code)):
            lo, hi, _fn = _function_at(blank, m.start())
            if lo in seen:
                continue
            seen.add(lo)
            body = code[lo:hi]
            # A URI's last path segment only counts when the file handles URIs from incoming intents; the
            # display name a provider reports is always the other app's choice.
            foreign = bool(_FOREIGN_URI.search(code))
            # variables that hold the provided name
            names: Set[str] = set()
            # declarations, and bare reassignments of a variable declared earlier (`fileName = it.getString(i)`)
            for am in re.finditer(r"(?:\b(?:val|var|String)\s+|^[ \t]*)(\w+)\s*(?::\s*String\??)?\s*=(?!=)\s*([^\n;]*)",
                                  body, re.MULTILINE):
                rhs = am.group(2)
                src = _DISPLAY_NAME.search(rhs)
                if src and "display" not in src.group(0).lower() and not foreign:
                    continue
                if (src or re.search(r"getString\s*\(\s*\w*[Ii]ndex|getString\s*\(\s*"
                                     r"(?:cursor|it|c)\.getColumnIndex", rhs)) and not _SANITIZED.search(rhs):
                    names.add(am.group(1))
            if not names:
                continue
            # a path check in code counts (a canonical path shown inside a string template is not a check)
            if re.search(r"canonical(?:Path|File)|getCanonical|normalize\s*\(|toRealPath", blank[lo:hi]):
                continue
            for sm in _FILE_SINK.finditer(blank, lo, hi):
                close = _match(blank, sm.end() - 1, "(", ")")
                if re.match(r"\s*\.\s*(?:name\b|getName\s*\()", blank[close + 1:close + 20]):
                    continue                  # File(name).name keeps only the last segment
                spans = _args(blank, sm.end() - 1)
                args = " ".join(code[s:e] for s, e in spans)
                used = [n for n in names if re.search(r"(?<![\w.])" + re.escape(n) + r"\b(?!\s*\()", args)]
                if used and not _SANITIZED.search(args):
                    yield _hit(ctx, path, ctx.line_of(blank, sm.start()),
                               f"A file name another app supplied ({used[0]}) is used as a path, so `../` in it can "
                               "overwrite this app's files.")
                    break


# ---------------------------------------------------------------------------- build


class _Spans:
    """gradle.inside(index, blocks) for many indexes: the union of the blocks' bodies, merged once."""

    def __init__(self, blocks: List[gradle.Block]):
        self.starts: List[int] = []
        self.ends: List[int] = []
        for b in sorted(blocks, key=lambda b: b.body_start):
            if b.body_start >= b.body_end:
                continue                       # an empty body holds nothing
            if self.ends and b.body_start <= self.ends[-1]:
                self.ends[-1] = max(self.ends[-1], b.body_end)
            else:
                self.starts.append(b.body_start)
                self.ends.append(b.body_end)

    def holds(self, index: int) -> bool:
        k = bisect.bisect_right(self.starts, index) - 1
        return k >= 0 and index < self.ends[k]


class _Unreported:
    """The indexes in [0, n) not taken yet. A rule that meets the same build-script setting (or block) from
    several nested blocks reports it only the first time: the engine keeps only the first finding per rule
    and line anyway, and a crafted script of thousands of nested blocks made the repeats quadratic."""

    def __init__(self, n: int):
        self.next = list(range(n + 1))

    def _find(self, i: int) -> int:
        nxt = self.next
        while nxt[i] != i:
            nxt[i] = nxt[nxt[i]]
            i = nxt[i]
        return i

    def take(self, lo: int, hi: int) -> List[int]:
        """The indexes in [lo, hi) not taken before, in order; they are taken now."""
        out = []
        i = self._find(lo)
        while i < hi:
            out.append(i)
            self.next[i] = i + 1
            i = self._find(i + 1)
        return out


def _new_settings(code: str, pattern: "re.Pattern[str]", block: gradle.Block,
                  unreported: _Unreported) -> List[Tuple[int, str]]:
    """gradle.find_settings(code, pattern, body of block), less the script's matches already taken."""
    first, lo, hi = gradle.settings_in(code, pattern, block.body_start, block.body_end)
    found = gradle.settings_list(code, pattern)
    return first + [(found[i][0], found[i][2]) for i in unreported.take(lo, hi)]


_DEBUGGABLE = gradle.setting(r"isDebuggable|debuggable|setDebuggable")
_MINIFY = gradle.setting(r"isMinifyEnabled|minifyEnabled|setMinifyEnabled")
_ENABLE = gradle.setting(r"enable|isEnable")


@detector("android_debuggable")
def debuggable(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        if not _release_path(ctx, path):
            continue        # a debug-only manifest is where debuggable belongs
        for app in manifest.applications(root):
            value = app.get("android:debuggable")
            if manifest.is_placeholder(value):
                ctx.note_unknown(f"{path}: android:debuggable comes from a placeholder.")
            elif xmlsafe.is_true(value):
                yield _hit(ctx, path, app.line,
                           "android:debuggable=\"true\" in the main manifest makes every build debuggable.",
                           ack=_ack(ctx, path, app, "HardcodedDebugMode"))
    for path, code, blank in _build_files(ctx):
        # Each release block once (build_type_blocks repeats one under nested buildTypes), and each setting
        # once across nested release blocks: a repeat only repeats a finding or note already made.
        unreported = _Unreported(len(gradle.settings_list(code, _DEBUGGABLE)))
        for block in gradle.blocks_named_within(code, blank, "buildTypes", "release"):
            for idx, val in _new_settings(code, _DEBUGGABLE, block, unreported):
                if val == "true":
                    yield _hit(ctx, path, ctx.line_of(code, idx), "The release build type is debuggable.")
                elif val != "false":
                    ctx.note_unknown(f"{path}: release debuggable is set from '{val}'.")


_NATIVE_DEBUG = gradle.setting(r"isJniDebuggable|jniDebuggable|setJniDebuggable|isRenderscriptDebuggable"
                               r"|renderscriptDebuggable|setRenderscriptDebuggable|testCoverageEnabled"
                               r"|isTestCoverageEnabled|enableAndroidTestCoverage|enableUnitTestCoverage")


def _release_like_blocks(ctx: Context, path: str, code: str, blank: str) -> List[gradle.Block]:
    """Build type blocks that ship: release, and custom types that aren't debug-derived."""
    module = posixpath.dirname(path)
    out = []
    for name, bt in _build_types_of(ctx, path, code, blank).items():
        if _variant_kind(ctx, module, name) == "release":
            out.append(bt.block)
    return out


@detector("android_release_native_debug")
def release_native_debug(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, root in _manifests(ctx):
        if not _release_path(ctx, path):
            continue
        for app in manifest.applications(root):
            if xmlsafe.is_true(app.get("android:testOnly")):
                yield _hit(ctx, path, app.line, "android:testOnly=\"true\" marks the app as a test build.")
    for path, code, blank in _build_files(ctx):
        unreported = _Unreported(len(gradle.settings_list(code, _NATIVE_DEBUG)))   # see _Unreported
        for block in _release_like_blocks(ctx, path, code, blank):
            for idx, val in _new_settings(code, _NATIVE_DEBUG, block, unreported):
                if val == "true":
                    key = re.match(r"\w+", code[idx:]).group(0)
                    what = ("ships coverage instrumentation" if "overage" in key else
                            "lets a debugger attach to native code" if "Jni" in key or "jni" in key else
                            "makes RenderScript debuggable")
                    yield _hit(ctx, path, ctx.line_of(code, idx),
                               f"The {block.name} build type sets {key} = true, which {what}.")


# `def enableProguardInReleaseBuilds = false` (the React Native template), `val minify = true` (Kotlin DSL), and
# Expo's `def enableMinifyInReleaseBuilds = (findProperty('android.enableMinifyInReleaseBuilds') ?: false).toBoolean()`.
_SCRIPT_VAR = re.compile(r"^[ \t]*(?:def|val|var|boolean|final\s+def)\s+(\w+)\s*(?::\s*Boolean\s*)?=[ \t]*([^\n]{1,300})$",
                         re.MULTILINE)
_FIND_PROPERTY = re.compile(r"^\(?\s*(?:project\s*\.\s*)?(?:findProperty|property)\s*\(\s*['\"]([\w.-]{1,100})['\"]\s*\)"
                            r"\s*(?:\?\.\s*toString\s*\(\s*\)\s*)?(?:\?\.\s*toBoolean\s*\(\s*\)\s*)?\?:\s*(true|false)\s*\)?"
                            r"(?:\s*\.\s*toBoolean\s*\(\s*\))?\s*$")


_PROPERTY_LINE = re.compile(r"^[ \t]*([\w.-]{1,100})[ \t]*[=:][ \t]*(\S{1,40})[ \t]*$", re.MULTILINE)


def _gradle_property(ctx: Context, build_file: str, name: str) -> Optional[Tuple[str, str]]:
    """(value, path) of a gradle.properties entry visible to this build file (its folder or a parent)."""
    folder = posixpath.dirname(build_file)
    best: Optional[Tuple[int, str, str]] = None
    for path in ctx.files(name="gradle.properties"):
        base = posixpath.dirname(path)
        if base and not (folder == base or folder.startswith(base + "/")):
            continue
        props = _memo(ctx, "gradle_props:" + path, lambda p=path: {
            m.group(1): m.group(2).lower() for m in _PROPERTY_LINE.finditer(ctx.text(p) or "")})
        if name in props and (best is None or len(base) > best[0]):
            best = (len(base), props[name], path)
    return (best[1], best[2]) if best else None


def _script_flag(ctx: Context, path: str, code: str, name: str) -> Optional[Tuple[str, str]]:
    """("true" | "false", how) for a boolean variable the same build script defines, or None."""
    def index() -> Dict[str, Tuple[str, int]]:
        out: Dict[str, Tuple[str, int]] = {}
        for m in _SCRIPT_VAR.finditer(code):
            out.setdefault(m.group(1), (m.group(2).strip().rstrip(";").strip(), m.start()))
        return out
    found_var = _memo(ctx, "script_vars:" + path, index).get(name)
    if found_var is None:
        return None
    rhs, at = found_var
    line = ctx.line_of(code, at)
    if rhs in ("true", "false"):
        return rhs, f"{name} is {rhs} on line {line}"
    prop = _FIND_PROPERTY.match(rhs)
    if prop:
        found = _gradle_property(ctx, path, prop.group(1))
        if found is None:
            return prop.group(2), f"{name} defaults to {prop.group(2)}: no gradle.properties sets {prop.group(1)}"
        if found[0] in ("true", "false"):
            return found[0], f"{found[1]} sets {prop.group(1)}={found[0]}"
    return None


@detector("android_r8_off")
def r8_off(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _build_files(ctx):
        # Each release block, `optimization` block, and setting once (see _Unreported).
        minify = _Unreported(len(gradle.settings_list(code, _MINIFY)))
        enable = _Unreported(len(gradle.settings_list(code, _ENABLE)))
        opts: Optional[_Unreported] = None
        for block in gradle.blocks_named_within(code, blank, "buildTypes", "release"):
            for idx, val in _new_settings(code, _MINIFY, block, minify):
                via = ""
                if val not in ("true", "false"):
                    resolved = _script_flag(ctx, path, code, val)
                    if resolved is not None:
                        val, via = resolved
                if val == "false":
                    yield _hit(ctx, path, ctx.line_of(code, idx),
                               "R8 minification is off in the release build type" + (f" ({via})." if via else "."))
                elif val != "true":
                    ctx.note_unknown(f"{path}: release minification is set from '{val}'.")
            named, lo, hi = gradle.named_range(code, blank, "optimization", block)
            opts = opts or _Unreported(len(named))
            for opt in (named[i] for i in opts.take(lo, hi)):
                for idx, val in _new_settings(code, _ENABLE, opt, enable):
                    if val == "false":
                        yield _hit(ctx, path, ctx.line_of(code, idx),
                                   "App optimization (R8) is off in the release build type.")


def _sdk_levels(ctx: Context, rule_key: str, threshold: int, label: str) -> Iterator[Hit]:
    """Shared logic for targetSdk / minSdk: Gradle (both DSLs), version catalogs, and the manifest."""
    seen: Set[Tuple[str, int]] = set()
    for path, line, value, where, raw in _sdk_entries(ctx, rule_key):
        if value is None:
            ctx.note_unknown(f"{path}: {raw} is set from a value masaudit can't resolve.")
            continue
        if (path, line) in seen or value >= threshold:
            continue
        seen.add((path, line))
        yield _hit(ctx, path, line, f"{label} is {value} {where}; it should be at least {threshold}.")


@detector("android_target_sdk")
def target_sdk(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _sdk_levels(ctx, "targetSdk", 36, "targetSdk")


@detector("android_min_sdk")
def min_sdk(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _sdk_levels(ctx, "minSdk", 24, "minSdk")


_DEBUG_TOOLS = [
    (re.compile(r"^com\.facebook\.stetho:stetho"), "Stetho", "exposes databases and preferences over Chrome DevTools"),
    (re.compile(r"^com\.facebook\.flipper:flipper(?!-noop)(?:$|-)"), "Flipper",
     "exposes databases, preferences and network traffic to a desktop client"),
    (re.compile(r"^com\.github\.chuckerteam\.chucker:library$"), "Chucker", "records every HTTP request and response"),
    (re.compile(r"^com\.readystatesoftware\.chuck:library$"), "Chuck", "records every HTTP request and response"),
    (re.compile(r"^com\.squareup\.leakcanary:leakcanary-android(?!-release)(?:$|-core$|-instrumentation$)"),
     "LeakCanary", "writes heap dumps that contain in-memory secrets"),
    (re.compile(r"^com\.amitshekhar\.android:debug-db(?!-no-op)"), "Android Debug Database",
     "serves the app's databases over HTTP"),
    (re.compile(r"^com\.willowtreeapps\.hyperion:"), "Hyperion", "adds an in-app debug menu"),
    (re.compile(r"^com\.plutolib(?:\.plugins)?:(?!.*no-op)"), "Pluto", "adds an in-app debug menu with network and storage views"),
]
_DEBUG_TOOL_INIT = re.compile(r"\bStetho\s*\.\s*initialize\w*\s*\(|\bAndroidFlipperClient\s*\.\s*getInstance\s*\("
                              r"|\bDebugDB\s*\.\s*\w+\s*\(")


def _catalog_libraries(ctx: Context) -> Dict[str, Tuple[str, str, int]]:
    """Version catalog accessor key ("leakcanary.android") -> (coordinate, toml path, line)."""
    def compute():
        out: Dict[str, Tuple[str, str, int]] = {}
        for path in ctx.files(".toml"):
            for alias, (coord, line) in gradle.toml_libraries(ctx.text(path) or "").items():
                out[gradle.alias_key(alias)] = (coord, path, line)
        return out
    return _memo(ctx, "catalog_libraries", compute)


@detector("android_debug_tool_release")
def debug_tool_release(ctx: Context, rule: Rule) -> Iterable[Hit]:
    catalog = _catalog_libraries(ctx)
    for module in _modules(ctx).values():
        path = next((p for p in (module.dir + "/build.gradle.kts", module.dir + "/build.gradle",
                                 "build.gradle.kts" if not module.dir else "", "build.gradle" if not module.dir else "")
                     if p and ctx.text(p) is not None), None)
        main_src = (module.dir + "/" if module.dir else "") + "src/main/AndroidManifest.xml"
        if path is None or _scope(ctx, main_src) != "main":
            continue
        code = ctx.code(path, True) or ""
        for dep in module.deps:
            if _TEST_VARIANT.search(dep.variant) or _variant_kind(ctx, module.dir, dep.variant) != "release":
                continue
            coords = list(dep.coords) + [catalog[gradle.alias_key(a)][0] for a in dep.aliases
                                         if gradle.alias_key(a) in catalog]
            for coord in coords:
                for rx, label, what in _DEBUG_TOOLS:
                    if rx.search(coord):
                        yield _hit(ctx, path, ctx.line_of(code, dep.index),
                                   f"{label} ({coord}) is added with {dep.config}, so it ships in release builds and "
                                   f"{what}.")
    for path, _code, blank in _code_files_any(ctx, ("Stetho", "AndroidFlipperClient", "DebugDB")):
        if not _release_path(ctx, path):
            continue
        for m in _sites(_DEBUG_TOOL_INIT.finditer(blank)):
            if _debug_only(ctx, blank, m.start()):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "A debug tool is started outside a debug-only source set or BuildConfig.DEBUG check.")


_KEEP_SECURITY = re.compile(r"(?i)root|jailbreak|integrity|attest|tamper|pinning|security|detector|rasp|signals?\b")
_KEEP_MODEL = re.compile(r"(?i)\.(?:model|models|dto|dtos|data|entity|entities|api|response|request|json|network\.model"
                         r"|serial\w*)\.|\$\w+|\bR\$|\.R\b|\.BuildConfig\b")
_PROGUARD_REF = re.compile(r"(?<![\w.])(?:(?P<kind>test|consumer)P|p)roguardFiles?\b[ \t]*\(?")


@detector("android_keep_rules")
def keep_rules(ctx: Context, rule: Rule) -> Iterable[Hit]:
    kinds = _module_kinds(ctx)
    ids = [i.lower() for i in _app_id_prefixes(ctx)]
    referenced_release: Set[str] = set()
    referenced_other: Set[str] = set()
    for path, code, blank in _build_files(ctx, ("app",)):
        module = posixpath.dirname(path)
        types = _build_types_of(ctx, path, code, blank)
        per_type: Dict[str, Set[str]] = {}
        inherits: Set[str] = set()
        for m in _PROGUARD_REF.finditer(blank):
            if blank[m.end() - 1] == "(":
                end = _match(blank, m.end() - 1, "(", ")")
            else:                                   # Groovy: proguardFiles a, b (to the end of the line)
                nl = blank.find("\n", m.end())
                end = nl if nl != -1 else len(blank)
            args = code[m.end():end]
            files = {posixpath.normpath(posixpath.join(module, f))
                     for f in re.findall(r"[\"']([\w./-]+\.(?:pro|txt|cfg))[\"']", args)}
            owner = next((n for n, bt in types.items() if bt.block.body_start <= m.start() < bt.block.body_end), None)
            if m.group("kind"):                     # testProguardFiles / consumerProguardFiles
                referenced_other.update(files)
                continue
            if owner is None:
                referenced_release.update(files)    # defaultConfig applies to every build type
                continue
            per_type.setdefault(owner, set()).update(files)
            if _variant_kind(ctx, module, owner) == "release":   # proguardFiles(*buildTypes["debug"].proguardFiles...)
                for a, b in re.findall(r"buildTypes\s*(?:\[\s*\"(\w+)\"\s*\]|\.getByName\(\s*\"(\w+)\"\s*\))\s*\.\s*"
                                       r"proguardFiles", args):
                    inherits.add(a or b)
        for name, files in per_type.items():
            if _variant_kind(ctx, module, name) == "release" or name in inherits:
                referenced_release.update(files)
            else:
                referenced_other.update(files)
        for m in re.finditer(r"getDefaultProguardFile\s*\(\s*[\"']proguard-android\.txt[\"']", code):
            in_release = any(bt.block.body_start <= m.start() < bt.block.body_end for n, bt in types.items()
                             if _variant_kind(ctx, module, n) == "release")
            if in_release:
                yield _hit(ctx, path, ctx.line_of(code, m.start()),
                           "The release build uses proguard-android.txt, which turns R8 optimization off (AGP 9 "
                           "rejects it); use proguard-android-optimize.txt.")
    for path in ctx.files(".pro", ".txt", ".cfg"):
        base = path.rsplit("/", 1)[-1].lower()
        if path.endswith(".txt") and "proguard" not in base and "r8" not in base:
            continue
        if path.endswith(".cfg") and "proguard" not in base:
            continue
        module = _module_of(path) if "/src/" in "/" + path else posixpath.dirname(path)
        while module and module not in kinds:
            module = posixpath.dirname(module)
        if kinds.get(module) != "app" or not _release_path(ctx, path) or "consumer" in base:
            continue
        norm = posixpath.normpath(path)
        if norm in referenced_other and norm not in referenced_release:
            continue
        for opt in proguard.parse(ctx.text(path) or ""):
            msg = None
            if opt.name == "dontobfuscate":
                msg = "-dontobfuscate turns off name obfuscation for the whole app."
            elif opt.name in ("keep", "keepnames") and "allowobfuscation" not in opt.spec.split(" ", 1)[0]:
                cls = proguard.class_pattern(opt.spec)
                head = opt.spec.split("{", 1)[0]
                if "@" in head or re.search(r"\b(?:extends|implements)\b", head):
                    continue
                if cls in ("*", "**"):
                    msg = f"-{opt.name} class {cls} keeps the name of every class, which undoes obfuscation."
                elif cls and not _KEEP_MODEL.search("." + cls + "."):
                    pkg = cls.rstrip("*").rstrip(".").lower()
                    if cls.endswith(".**") and any(i == pkg or i.startswith(pkg + ".") and pkg.count(".") >= 1
                                                   for i in ids):
                        msg = f"-{opt.name} class {cls} keeps the names of the app's own classes."
                    elif _KEEP_SECURITY.search(cls.rsplit(".", 1)[-1]) and not cls.endswith("**"):
                        msg = f"-{opt.name} class {cls} keeps a security class's name readable for attackers."
            if msg:
                yield _hit(ctx, path, opt.line, msg)


_STRICT_MODE = re.compile(r"\bStrictMode\s*\.\s*set(?:ThreadPolicy|VmPolicy)\s*\(")
_STRICT_NOISY = re.compile(r"\bpenaltyLog\b|\bpenaltyDropBox\b|\bdetectAll\b|\bpenaltyDeath\w*\b")


def _called_only_under_debug(ctx: Context, name: str, own_path: str) -> bool:
    """Every call of function `name` in the project sits under a debug check (or in debug code)."""
    if not name:
        return False
    calls = 0
    rx = re.compile(r"(?<![\w.])(?:\w+\.)?" + re.escape(name) + r"\s*\(")
    decl = re.compile(r"\bfun\s+(?:[\w.]+\.)?" + re.escape(name) + r"\s*\(|\bvoid\s+" + re.escape(name) + r"\s*\(")
    for path in ctx.files(*CODE_SUFFIXES):
        raw = ctx.text(path) or ""
        if name not in raw:
            continue
        blank = ctx.code(path, False) or ""
        for m in _sites(rx.finditer(blank)):
            line_start = blank.rfind("\n", 0, m.start()) + 1
            if decl.search(blank[line_start:m.end()]):
                continue
            calls += 1
            if not (_debug_only(ctx, blank, m.start()) or not _release_path(ctx, path)):
                return False
    return calls > 0


@detector("android_strict_mode_release")
def strict_mode_release(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "StrictMode"):
        if not _release_path(ctx, path):
            continue
        for m in _sites(_STRICT_MODE.finditer(blank)):
            lo, hi, fn = _function_at(blank, m.start())
            if not _STRICT_NOISY.search(blank[lo:hi]):
                continue
            if _debug_only(ctx, blank, m.start()) or _called_only_under_debug(ctx, fn, path):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "StrictMode reporting is set up outside a BuildConfig.DEBUG check, so release builds log "
                       "internal file and network details.")


_KEEP_SYMBOLS = re.compile(r"\bkeepDebugSymbols\s*(?:\+=|\.add\w*\s*\(|=)|\bdoNotStrip\b")
_CMAKE_DEBUG = re.compile(r"CMAKE_BUILD_TYPE=Debug|[\"']-g[\"']|[\"']-g\d?\s")


@detector("android_native_debug_symbols")
def native_debug_symbols(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _build_files(ctx, ("app", "lib", "unknown")):
        module = posixpath.dirname(path)
        types = _build_types_of(ctx, path, code, blank)
        debug_spans = [bt.block for n, bt in types.items() if _variant_kind(ctx, module, n) != "release"]
        for m in _KEEP_SYMBOLS.finditer(code):
            if gradle.inside(m.start(), debug_spans) or blank[m.start()] == " ":
                continue
            yield _hit(ctx, path, ctx.line_of(code, m.start()),
                       "Native libraries keep their debug symbols in the release APK, which makes them easier to "
                       "reverse engineer.")
        for bt_name, bt in types.items():
            if _variant_kind(ctx, module, bt_name) != "release":
                continue
            for nb in gradle.child_blocks(code, blank, bt.block, "externalNativeBuild"):
                for cm in _CMAKE_DEBUG.finditer(code, nb.body_start, nb.body_end):
                    yield _hit(ctx, path, ctx.line_of(code, cm.start()),
                               f"The {bt_name} build compiles native code with debug settings ({cm.group(0).strip()}).")


_V2_OFF = gradle.setting(r"enableV2Signing|v2SigningEnabled|isV2SigningEnabled")
_V3_ON = gradle.setting(r"enableV3Signing|v3SigningEnabled|isV3SigningEnabled")


@detector("android_v1_signing_only")
def v1_signing_only(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, code, blank in _build_files(ctx):
        # A v2 setting a nested config repeats is reported once (see _Unreported); "true" among a config's v3
        # settings is counted, not listed.
        unreported = _Unreported(len(gradle.settings_list(code, _V2_OFF)))
        v3_all = gradle.settings_list(code, _V3_ON)
        v3_true = list(itertools.accumulate((v == "true" for _s, _e, v in v3_all), initial=0))
        for sc in gradle.named_blocks(code, blank, "signingConfigs"):
            for cfg in gradle.direct_children(code, blank, sc):
                if _variant_kind(ctx, posixpath.dirname(path), cfg.name) == "debug":
                    continue
                first3, lo3, hi3 = gradle.settings_in(code, _V3_ON, cfg.body_start, cfg.body_end)
                if any(v == "true" for _i, v in first3) or v3_true[hi3] > v3_true[lo3]:
                    continue                  # no v2 setting here is reported
                for idx, val in _new_settings(code, _V2_OFF, cfg, unreported):
                    if val == "false":
                        yield _hit(ctx, path, ctx.line_of(code, idx),
                                   f"The {cfg.name} signing config turns off APK Signature Scheme v2 and doesn't "
                                   "turn on v3, so the APK relies on the v1 (JAR) scheme.")


_DEBUG_TREE = re.compile(r"\bplant\s*\(\s*(?:new\s+)?(?:Timber\s*\.\s*)?(?P<cls>\w*DebugTree|\w+)\s*\(")


@detector("android_timber_debug_tree")
def timber_debug_tree(ctx: Context, rule: Rule) -> Iterable[Hit]:
    subs, _sup, files = _class_index(ctx)
    debug_trees = {"DebugTree"}
    todo = ["DebugTree"]
    while todo:
        for s in subs.get(todo.pop(), ()):
            if s not in debug_trees:
                debug_trees.add(s)
                todo.append(s)
    filtered: Set[str] = set()
    for cls in debug_trees - {"DebugTree"}:
        for p in files.get(cls, []):
            body = ctx.code(p, False) or ""
            if re.search(r"\bisLoggable\s*\(|priority\s*(?:>=?|<=?)\s*(?:Log\.)?(?:WARN|ERROR|INFO|ASSERT)", body):
                filtered.add(cls)
    for path, _code, blank in _code_files(ctx, "plant"):
        if not _release_path(ctx, path) or "Timber" not in (ctx.text(path) or ""):
            continue
        for m in _sites(_DEBUG_TREE.finditer(blank)):
            cls = m.group("cls")
            if cls not in debug_trees or cls in filtered:
                continue
            if _debug_only(ctx, blank, m.start()):
                continue
            lo, _hi, fn = _function_at(blank, m.start())
            if _called_only_under_debug(ctx, fn, path):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       f"Timber plants {cls} in every build, so release builds write all log calls to logcat.")


_LEVEL_BODY = re.compile(r"\bLevel\.BODY\b")


@detector("android_http_logging_body")
def http_logging_body(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "HttpLoggingInterceptor"):
        for m in _sites(_LEVEL_BODY.finditer(blank)):
            if _is_import(blank, m.start()):
                continue
            if _debug_only(ctx, blank, m.start()):
                continue
            line_start = blank.rfind("\n", 0, m.start()) + 1
            before = blank[line_start:m.start()]
            after = blank[m.end():m.end() + 120]       # may continue on the next line (`.takeIf { ... }`)
            sets = re.search(r"(?:\blevel\s*=|\bsetLevel\s*\(|\.level\s*\()\s*(?:HttpLoggingInterceptor\s*\.\s*)?$",
                             before)
            line = ctx.line_of(blank, m.start())
            if not sets:
                if re.search(r"(?:==|!=)\s*(?:HttpLoggingInterceptor\s*\.\s*)?$", before) or \
                        re.match(r"\s*(?:==|!=)", after) or "->" in before:
                    continue          # a comparison or a `when` branch, not a setting
                if re.search(r"(?:\bif\b|\?)", before) or "takeIf" in after or "?:" in after:
                    ctx.note_unknown(f"{path}:{line}: HTTP body logging is chosen by a condition; confirm it's off "
                                     "in release.")
                continue
            if re.search(r"\bif\b", before) or re.match(r"\s*\.\s*take(?:If|Unless)\b|\s*\?:|\s*else\b", after) or \
                    re.search(r"\belse\b", before):
                ctx.note_unknown(f"{path}:{line}: HTTP body logging is chosen by a condition; confirm it's off "
                                 "in release.")
                continue
            yield _hit(ctx, path, line,
                       "HttpLoggingInterceptor logs full request and response bodies, including tokens, "
                       "in every build.")


# ---------------------------------------------------------------------------- platform features and absence checks


_SAFETYNET_ATTEST = re.compile(r"\bSafetyNet\s*\.\s*getClient\s*\([^)]*\)\s*\.\s*attest\s*\(|\bSafetyNetClient\b[^\n;]*"
                               r"\.\s*attest\s*\(|\bSafetyNetApi\s*\.\s*attest\s*\(|\bSafetyNet\s*\.\s*SafetyNetApi\s*\.\s*"
                               r"attest\s*\(|\bSafetyNetAppCheckProviderFactory\b")


@detector("android_safetynet")
def safetynet(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _code, blank in _code_files(ctx, "SafetyNet"):
        for m in _SAFETYNET_ATTEST.finditer(blank):
            if _is_import(blank, m.start()):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "The app still calls SafetyNet Attestation, which Google turned off in January 2025, so "
                       "any decision based on it is broken.")


def _evidence(ctx: Context, key: str, code_rx: "re.Pattern[str]", dep_rx: "re.Pattern[str]",
              layouts: bool = False, needles: Tuple[str, ...] = ()) -> bool:
    """Is there any evidence of a control in shipping code, build files, or Flutter/RN manifests?
    With layouts=True, layout and style XML counts too (view attributes such as filterTouchesWhenObscured).
    `needles`: literals (case-sensitive) at least one of which every match of code_rx contains."""
    def compute() -> bool:
        for path in ctx.files(".kt", ".java", ".dart", ".js", ".ts", ".tsx", ".xml"):
            if path.endswith(".xml") and not (layouts and re.search(r"/res/(?:layout|values)[\w-]*/", "/" + path)):
                continue
            if scope_of(path) == "test":
                continue
            if needles and not holds_any(ctx, path, needles):
                continue
            raw = ctx.text(path) or ""
            if not code_rx.search(raw):
                continue
            if path.endswith(".xml"):
                if code_rx.search(_XML_COMMENT.sub("", raw)):
                    return True
                continue
            if code_rx.search(ctx.code(path, True) or ""):
                return True
        for path in ctx.files(".gradle", ".kts", ".toml", ".yaml", ".json", ".lock"):
            base = path.rsplit("/", 1)[-1]
            if path.endswith((".yaml", ".lock", ".json")) and base not in ("pubspec.yaml", "pubspec.lock",
                                                                            "package.json"):
                continue
            text = ctx.code(path, True) if path.endswith((".gradle", ".kts")) else ctx.text(path)
            if text and dep_rx.search(text):
                return True
        return False
    return _memo(ctx, "evidence:" + key, compute)


def _is_app_project(ctx: Context) -> bool:
    return _main_application(ctx) is not None and (
        any(k == "app" for k in _module_kinds(ctx).values()) or not _module_kinds(ctx))


# Commercial RASP SDKs, accepted as evidence by the absence rules.
_RASP = (r"(?i:com\.aheaditec\.talsec|freerasp|\bpromon\b|dexguard|io\.approov|approov|zimperium|verimatrix|onespan"
         r"|build38|appdome)")
_SCREEN_EVIDENCE = re.compile(r"\bFLAG_SECURE\b|setRecentsScreenshotEnabled\s*\(\s*false|SecureFlagPolicy\s*\.\s*SecureOn"
                              r"|\bsetSecure\s*\(\s*true|secureFlagPolicy|screen_protector|no_screenshot"
                              r"|secure_application|flutter_windowmanager|[Ss]creenshotPrevent|[Pp]reventScreenCapture"
                              r"|[Pp]reventScreenshot")
# A literal from each alternative above, in order (the [Ss] and [Pp] classes left out).
_SCREEN_NEEDLES = ("FLAG_SECURE", "setRecentsScreenshotEnabled", "SecureFlagPolicy", "setSecure", "secureFlagPolicy",
                   "screen_protector", "no_screenshot", "secure_application", "flutter_windowmanager",
                   "creenshotPrevent", "reventScreenCapture", "reventScreenshot")
_SCREEN_DEPS = re.compile(r"screen_protector|no_screenshot|secure_application|flutter_windowmanager|"
                          r"react-native-(?:screenshot-prevent|prevent-screenshot|screenguard|capture-protection"
                          r"|flag-secure)|expo-screen-capture|" + _RASP, re.IGNORECASE)


@detector("android_no_screenshot_protection")
def no_screenshot_protection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if not _is_app_project(ctx):
        return
    if _evidence(ctx, "screenshot", _SCREEN_EVIDENCE, _SCREEN_DEPS, needles=_SCREEN_NEEDLES):
        return
    path, app = _main_application(ctx)
    yield _hit(ctx, path, app.line,
               "No screen gets FLAG_SECURE (or SecureFlagPolicy.SecureOn), so screenshots, screen recording and the "
               "recents thumbnail can capture balances, card numbers or one-time codes.")


_OVERLAY_EVIDENCE = re.compile(r"filterTouchesWhenObscured|setHideOverlayWindows\s*\(\s*true|FLAG_WINDOW_IS_OBSCURED"
                               r"|FLAG_WINDOW_IS_PARTIALLY_OBSCURED|onFilterTouchEventForSecurity")
_OVERLAY_NEEDLES = ("filterTouchesWhenObscured", "setHideOverlayWindows", "FLAG_WINDOW_IS_",
                    "onFilterTouchEventForSecurity")


# A label for an action an overlay would trick the user into confirming.
_SENSITIVE_ACTION = re.compile(r"(?i)\b(?:pay(?:ment)?|transfer|send\s+money|confirm|authori[sz]e|approve|withdraw"
                               r"|purchase|grant)\b")
_BUTTON_NEW = re.compile(r"(?<![\w.])(?:new\s+)?(?:Button|MaterialButton|AppCompatButton)\s*\(")
_XML_BUTTON = re.compile(r"<(?:[\w.]+\.)?(?:Button|MaterialButton|AppCompatButton)\b")
_XML_LAYOUT = re.compile(r"<(?:[\w.]+\.)?\w*Layout\b")
_VIEW_FILTER = re.compile(r"filterTouchesWhenObscured|setFilterTouchesWhenObscured|onFilterTouchEventForSecurity"
                          r"|FLAG_WINDOW_IS_(?:PARTIALLY_)?OBSCURED")


def _window_overlay_filter(ctx: Context) -> bool:
    """Is the filter set for a whole window: on the decor view, in a theme or style (res/values), or by hiding
    overlay windows?"""
    def compute() -> bool:
        for path, _code, blank in _code_files(ctx, "setHideOverlayWindows"):
            if scope_of(path) != "test" and re.search(r"\bsetHideOverlayWindows\s*\(\s*true", blank):
                return True
        for path, _code, blank in _code_files(ctx, "filterTouchesWhenObscured"):
            if scope_of(path) != "test" and re.search(r"decorView\s*\.\s*(?:filterTouchesWhenObscured\s*=\s*true|"
                                                      r"setFilterTouchesWhenObscured\s*\(\s*true)|getDecorView\s*\("
                                                      r"\s*\)\s*\.\s*setFilterTouchesWhenObscured\s*\(\s*true", blank):
                return True
        for path in ctx.files(".xml"):
            if re.search(r"/res/values[\w-]*/", "/" + path) and "filterTouchesWhenObscured" in (ctx.text(path) or ""):
                return True
        return False
    return bool(_memo(ctx, "overlay_window", compute))


def _string_res(ctx: Context) -> Dict[str, str]:
    """`@string/name` values from res/values*/strings*.xml (the first one found wins)."""
    def compute() -> Dict[str, str]:
        out: Dict[str, str] = {}
        for path in ctx.files(".xml"):
            if not re.search(r"/res/values[\w-]*/[^/]*strings[^/]*\.xml$", "/" + path):
                continue
            for m in re.finditer(r"<string\s+name=\"(\w+)\"[^>]{0,400}>([^<]{0,200})</string>", ctx.text(path) or ""):
                out.setdefault(m.group(1), m.group(2))
        return out
    return _memo(ctx, "string_res", compute)


def _unprotected_sensitive_buttons(ctx: Context) -> Iterator[Hit]:
    """The app filters obscured touches on some views only: report buttons for sensitive actions (pay, confirm,
    transfer) that don't, in code (`Button(context).apply { text = ... }`) and in layout XML."""
    msg = ("This button confirms a sensitive action but doesn't filter touches when another window covers it, while "
           "other views in the app do. A partial overlay can trick the user into tapping it.")
    for path, code, blank in _code_files_any(ctx, ("Button(",)):
        if scope_of(path) == "test":
            continue
        for m in _sites(_BUTTON_NEW.finditer(blank)):
            end = _match(blank, m.end() - 1, "(", ")")
            rest = re.match(r"\s*\{", blank[end + 1:end + 40])
            if rest:                                       # object : Button(context) { ... }
                end = _match(blank, end + 1 + rest.end() - 1, "{", "}")
            block = re.match(r"\s*\.\s*(?:apply|also)\s*\{", blank[end + 1:end + 40])
            if not block:
                continue
            open_brace = end + 1 + block.end() - 1
            region = code[m.start():_match(blank, open_brace, "{", "}") + 1]
            label = re.search(r"(?:\btext\s*=|\bsetText\s*\()\s*\"([^\"\n]*)\"", region)
            if not label or not _SENSITIVE_ACTION.search(label.group(1)) or _VIEW_FILTER.search(region):
                continue
            var = re.search(r"\b(?:val|var)\s+(\w+)\s*(?::\s*\w+\s*)?=\s*$|\b(\w+)\s*=\s*$",
                            blank[max(0, m.start() - 80):m.start()])
            name = (var.group(1) or var.group(2)) if var else None
            if name and re.search(r"\b" + re.escape(name) + r"\s*\.\s*(?:filterTouchesWhenObscured\s*=\s*true|"
                                  r"setFilterTouchesWhenObscured\s*\(\s*true)", blank):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()), msg)
    strings = None
    for path in ctx.files(".xml"):
        if "/res/layout" not in "/" + path or scope_of(path) == "test":
            continue
        text = ctx.text(path) or ""
        if "Button" not in text:
            continue
        clean = _XML_COMMENT.sub(lambda c: re.sub(r"[^\n]", " ", c.group(0)), text)
        if "filterTouchesWhenObscured=\"true\"" in clean and any(
                "filterTouchesWhenObscured=\"true\"" in tag for _at, tag in xml_tags(clean, _XML_LAYOUT)):
            continue          # a container filters touches for everything inside it
        for at, tag in xml_tags(clean, _XML_BUTTON):
            if "filterTouchesWhenObscured=\"true\"" in tag:
                continue
            lm = re.search(r"android:text\s*=\s*\"([^\"]*)\"", tag)
            if not lm:
                continue
            label = lm.group(1)
            if label.startswith("@string/"):
                if strings is None:
                    strings = _string_res(ctx)
                label = label[8:].replace("_", " ") + " " + strings.get(label[8:], "")
            if _SENSITIVE_ACTION.search(label):
                yield _hit(ctx, path, ctx.line_of(clean, at), msg)


@detector("android_no_overlay_protection")
def no_overlay_protection(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if not _is_app_project(ctx):
        # no app manifest to anchor a whole-app finding, but code that protects some views can still be checked
        if _evidence(ctx, "overlay", _OVERLAY_EVIDENCE, re.compile(_RASP), layouts=True, needles=_OVERLAY_NEEDLES) \
                and not _window_overlay_filter(ctx):
            yield from _unprotected_sensitive_buttons(ctx)
        return
    hide_perm = None
    for path, root in _manifests(ctx):
        if not _release_path(ctx, path):
            continue
        for p in manifest.uses_permissions(root):
            if p.get("android:name") == "android.permission.HIDE_OVERLAY_WINDOWS":
                hide_perm = (path, p.line)
    calls = []
    for path, _code, blank in _code_files(ctx, "setHideOverlayWindows"):
        for m in re.finditer(r"\bsetHideOverlayWindows\s*\(\s*true", blank):
            calls.append((path, ctx.line_of(blank, m.start())))
    if hide_perm and not calls:
        yield _hit(ctx, hide_perm[0], hide_perm[1],
                   "HIDE_OVERLAY_WINDOWS is declared but no screen calls setHideOverlayWindows(true), so overlays "
                   "are never hidden.")
        return
    if calls and not hide_perm:
        path, line = calls[0]
        yield _hit(ctx, path, line,
                   "setHideOverlayWindows(true) needs the HIDE_OVERLAY_WINDOWS permission, which the manifest doesn't "
                   "declare, so the call does nothing.")
        return
    if _evidence(ctx, "overlay", _OVERLAY_EVIDENCE, re.compile(_RASP), layouts=True, needles=_OVERLAY_NEEDLES):
        if not (calls and hide_perm) and not _window_overlay_filter(ctx):
            yield from _unprotected_sensitive_buttons(ctx)
        return
    path, app = _main_application(ctx)
    yield _hit(ctx, path, app.line,
               "No screen filters touches when another window covers it (filterTouchesWhenObscured or "
               "setHideOverlayWindows), so a partial overlay can trick users into confirming actions. Android 12+ "
               "blocks most full overlays, but not partial ones.")


_INTEGRITY_EVIDENCE = re.compile(r"IntegrityManagerFactory|StandardIntegrityManager|prepareIntegrityToken|requestIntegrityToken"
                                 r"|PlayIntegrityAppCheckProviderFactory|AndroidProvider\s*\.\s*playIntegrity"
                                 r"|app_integrity_checker")
_INTEGRITY_NEEDLES = ("IntegrityManagerFactory", "StandardIntegrityManager", "prepareIntegrityToken",
                      "requestIntegrityToken", "PlayIntegrityAppCheckProviderFactory", "playIntegrity",
                      "app_integrity_checker")
# React Native: @react-native-firebase/app-check, react-native-google-play-integrity, @expo/app-integrity.
_INTEGRITY_DEPS = re.compile(r"com\.google\.android\.play:integrity|play[-.]integrity|firebase[-_/]app[-_]?check|"
                             r"app_integrity_checker|appcheck-playintegrity|@expo/app-integrity|" + _RASP, re.IGNORECASE)


@detector("android_no_play_integrity")
def no_play_integrity(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if not _is_app_project(ctx):
        return
    if _evidence(ctx, "integrity", _INTEGRITY_EVIDENCE, _INTEGRITY_DEPS, needles=_INTEGRITY_NEEDLES):
        return
    if _evidence(ctx, "safetynet", _SAFETYNET_ATTEST, re.compile(r"play-services-safetynet"), needles=("SafetyNet",)):
        return                       # AND-044 reports the SafetyNet call instead
    path, app = _main_application(ctx)
    yield _hit(ctx, path, app.line,
               "No Play Integrity integration found (no integrity dependency, IntegrityManager call, or App Check "
               "provider), so the backend can't tell this app from a modified copy or a script.")


_SECURE_CLEARED = re.compile(r"\bclearFlags\s*\([^)]*FLAG_SECURE|\bsetFlags\s*\(\s*0\s*,[^)]*FLAG_SECURE"
                             r"|SecureFlagPolicy\s*\.\s*SecureOff\b|\bsetRecentsScreenshotEnabled\s*\(\s*true\s*\)")


_SECURE_SET = re.compile(r"\baddFlags\s*\([^)]*FLAG_SECURE|\bsetFlags\s*\([^)]*FLAG_SECURE[^)]*,[^)]*FLAG_SECURE"
                         r"|SecureFlagPolicy\s*\.\s*SecureOn\b|\bsetRecentsScreenshotEnabled\s*\(\s*false\s*\)")


@detector("android_screen_capture_cleared")
def screen_capture_cleared(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in ctx.files(".kt", ".java", ".dart"):
        raw = ctx.text(path) or ""
        if "FLAG_SECURE" not in raw and "SecureOff" not in raw and "setRecentsScreenshotEnabled" not in raw:
            continue
        blank = ctx.code(path, False) or ""
        # Turning the protection on and off in the same file is a toggle (a user setting, or a screen that
        # removes the flag it added when it closes); clearing a flag set somewhere else is the risk.
        if _SECURE_SET.search(blank):
            continue
        for m in _SECURE_CLEARED.finditer(blank):
            if "RecentsScreenshot" in m.group(0):
                continue
            yield _hit(ctx, path, ctx.line_of(blank, m.start()),
                       "Screen-capture protection is switched off here; check that this screen never shows "
                       "secrets.")


# ---------------------------------------------------------------------------- privacy: permissions

DANGEROUS_PERMISSIONS = {
    "ACCESS_FINE_LOCATION": "precise location",
    "ACCESS_BACKGROUND_LOCATION": "location in the background",
    "ACCESS_MEDIA_LOCATION": "the location stored in photos",
    "READ_EXTERNAL_STORAGE": "all shared files",
    "WRITE_EXTERNAL_STORAGE": "all shared files",
    "MANAGE_EXTERNAL_STORAGE": "every file on shared storage",
    "READ_MEDIA_IMAGES": "the whole photo library",
    "READ_MEDIA_VIDEO": "every video",
    "READ_MEDIA_AUDIO": "every audio file",
    "QUERY_ALL_PACKAGES": "the list of every installed app",
    "SYSTEM_ALERT_WINDOW": "drawing over other apps",
    "REQUEST_INSTALL_PACKAGES": "installing other apps",
    "READ_CONTACTS": "the contact list",
    "WRITE_CONTACTS": "changing contacts",
    "READ_CALENDAR": "the calendar",
    "WRITE_CALENDAR": "changing the calendar",
    "READ_SMS": "text messages",
    "RECEIVE_SMS": "incoming text messages",
    "SEND_SMS": "sending text messages",
    "READ_CALL_LOG": "the call log",
    "READ_PHONE_STATE": "phone identity and call state",
    "READ_PHONE_NUMBERS": "the phone number",
    "RECORD_AUDIO": "the microphone",
    "CAMERA": "the camera",
    "BODY_SENSORS": "body sensors",
    "BLUETOOTH_SCAN": "nearby Bluetooth devices (and location)",
    "USE_FULL_SCREEN_INTENT": "full-screen notifications over the lock screen",
}
# Fraud-relevant: OTP interception, overlays, package visibility, sideloading. Background location and
# all-files access are Play-restricted too, but they are privacy surface (AND-033), not fraud tooling.
HIGH_RISK_PERMISSIONS = {"READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_CALL_LOG", "QUERY_ALL_PACKAGES",
                         "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"}
_LEGACY_ONLY = {"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "BLUETOOTH_SCAN"}
_LINT_PERMISSION = ("QueryAllPackagesPermission", "ScopedStorage", "PhotoAndVideoPolicy")


@dataclass
class _Perm:
    name: str
    sites: List[Tuple[str, Element]] = field(default_factory=list)
    acks: List[str] = field(default_factory=list)


def _expo_permissions(ctx: Context) -> Optional[Tuple["rn_expo.ExpoApp", int, List[str]]]:
    """A managed Expo app's android.permissions (less blockedPermissions): (config, line, short names)."""
    expo = _managed_expo(ctx)
    listed = expo.get("android", "permissions") if expo is not None else None
    if not isinstance(listed, list):
        return None
    blocked = {str(b).rsplit(".", 1)[-1] for b in rn_expo.rn.as_list(expo.get("android", "blockedPermissions"))
               if isinstance(b, str)}
    names = []
    for p in listed:
        if isinstance(p, str) and (p.startswith("android.permission.") or "." not in p):
            short = p.rsplit(".", 1)[-1]
            if short in DANGEROUS_PERMISSIONS and short not in blocked and short not in names:
                names.append(short)
    return expo, expo.line("android", "permissions"), sorted(names)


def _permission_inventory(ctx: Context) -> Tuple[Optional[Tuple[str, Element]], Dict[str, _Perm], str]:
    """The app's effective sensitive permissions, merged across modules: (anchor, permissions, scope)."""
    def compute():
        perms: Dict[str, _Perm] = {}
        release = False
        for path, root in _manifests(ctx):
            scope = _scope(ctx, path)
            if scope == "test":
                continue
            for p in manifest.uses_permissions(root):
                name = (p.get("android:name") or "").strip()
                short = name.rsplit(".", 1)[-1]
                if not name.startswith("android.permission.") or short not in DANGEROUS_PERMISSIONS:
                    continue
                max_sdk = (p.get("android:maxSdkVersion") or "").strip()
                if short in _LEGACY_ONLY and small_int(max_sdk) is not None and small_int(max_sdk) <= 32:
                    continue          # the narrow legacy grant paired with READ_MEDIA_* / NEARBY_WIFI_DEVICES
                if short == "BLUETOOTH_SCAN" and "neverForLocation" in (p.get("android:usesPermissionFlags") or ""):
                    continue
                entry = perms.setdefault(short, _Perm(short))
                entry.sites.append((path, p))
                ack = _ack(ctx, path, p, *_LINT_PERMISSION)
                if ack:
                    entry.acks.append(ack)
                release = release or scope == "main"
        anchor = _main_application(ctx)
        return anchor, perms, "main" if release else "debug"
    return _memo(ctx, "permissions", compute)


def _perm_sites(entry: _Perm) -> str:
    modules = sorted({_module_of(p) or "." for p, _el in entry.sites})
    return entry.name + (f" ({', '.join(modules)})" if len(modules) > 1 else "")


@detector("android_dangerous_permissions")
def dangerous_permissions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    anchor, perms, scope = _permission_inventory(ctx)
    expo = _expo_permissions(ctx) if not perms else None
    if expo is not None and expo[2]:
        items = [f"{p}: {DANGEROUS_PERMISSIONS[p]}" for p in expo[2]]
        yield _hit(ctx, expo[0].path, expo[1],
                   f"The Expo config asks for {len(items)} sensitive permission{'s' if len(items) != 1 else ''}: "
                   + "; ".join(items) + ". Check that a feature needs each one and that a narrower option won't do.")
        return
    if not perms:
        return
    release_perms = {k: v for k, v in perms.items() if any(_scope(ctx, p) == "main" for p, _e in v.sites)}
    shown = release_perms or perms
    if anchor is None:
        first = next(iter(shown.values())).sites[0]
        anchor = (first[0], first[1])
    path, el = anchor
    items = [f"{_perm_sites(v)}: {DANGEROUS_PERMISSIONS[k]}" for k, v in sorted(shown.items())]
    write = shown.get("WRITE_EXTERNAL_STORAGE")
    if write and (_sdk_value(ctx, "targetSdk") or 0) >= 30 and \
            not any((el.get("android:maxSdkVersion") or "").strip() for _p, el in write.sites):
        items = [i + (" (it has no effect on Android 11 and higher; add android:maxSdkVersion=\"29\")"
                      if i.startswith("WRITE_EXTERNAL_STORAGE") else "") for i in items]
    yield _hit(ctx, path, el.line,
               f"The app asks for {len(items)} sensitive permission{'s' if len(items) != 1 else ''}: "
               + "; ".join(items) + ". Check that a feature needs each one and that a narrower option won't do.",
               scope="" if release_perms else "debug")


@detector("android_high_risk_permissions")
def high_risk_permissions(ctx: Context, rule: Rule) -> Iterable[Hit]:
    anchor, perms, _scope_ = _permission_inventory(ctx)
    risky = {k: v for k, v in perms.items() if k in HIGH_RISK_PERMISSIONS}
    accessibility = []
    for path, root in _manifests(ctx):
        for c in manifest.components(root, ("service",)):
            if c.get("android:permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                accessibility.append((path, c))
    if not risky and not accessibility:
        expo = _expo_permissions(ctx) if not perms else None
        shown_expo = [p for p in expo[2] if p in HIGH_RISK_PERMISSIONS] if expo else []
        if shown_expo:
            yield _hit(ctx, expo[0].path, expo[1],
                       f"The Expo config requests fraud-relevant access: {', '.join(shown_expo)}. These let it read "
                       "one-time codes, draw over other apps, list installed apps or install packages; Play restricts "
                       "them and reviewers expect a written justification.")
        return
    release = {k: v for k, v in risky.items() if any(_scope(ctx, p) == "main" for p, _e in v.sites)}
    acc_release = [a for a in accessibility if _scope(ctx, a[0]) == "main"]
    shown = release if (release or acc_release) else risky
    acc_shown = acc_release if (release or acc_release) else accessibility
    if anchor is None:
        site = next(iter(shown.values())).sites[0] if shown else acc_shown[0]
        anchor = (site[0], site[1])
    path, el = anchor
    items = [_perm_sites(v) for _k, v in sorted(shown.items())]
    if acc_shown:
        items.append(f"an accessibility service ({_simple(acc_shown[0][1].get('android:name') or '')})")
    acked = [a for v in shown.values() for a in v.acks]
    all_acked = bool(acked) and not acc_shown and all(v.acks for v in shown.values())
    msg = (f"The app requests fraud-relevant access: {', '.join(items)}. These let it read one-time codes, draw "
           "over other apps, list installed apps or install packages; Play restricts them and reviewers expect "
           "a written justification.")
    yield _hit(ctx, path, el.line, msg, ack="; ".join(sorted(set(acked))) if all_acked else "",
               scope="" if (release or acc_release) else "debug")
