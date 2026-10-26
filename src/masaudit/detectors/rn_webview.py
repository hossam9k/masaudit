# SPDX-License-Identifier: Apache-2.0
"""React Native detectors: react-native-webview. Shared helpers are in reactnative.py.

The rules read the opening tags of `<WebView>` elements (and of wrappers such as `styled(WebView)`) in files that
import the component. The tags are found once per scan and shared by RN-005 to RN-008. react-native-webview's
defaults are safe for everything checked here (file access off, originWhitelist http and https), so only explicit
overrides are reported. JavaScript is on by default, so no rule asks for `javaScriptEnabled`.

Everything is bounded and linear: each file is indexed once (declarations, state, handlers), every value or
handler body is read up to a fixed size, and each script template is walked once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from masaudit.detect import scope_of
from masaudit.detectors.reactnative import (UNKNOWN, Element, imports, in_dev, js_files, jsx_elements, literal,
                                            memo)
from masaudit.engine import Context, Hit, Rule, detector
from masaudit.textscan import bracket_match

# Packages whose WebView has react-native-webview's props (MetaMask ships a fork; the community name is the old one).
_MODULES = ("react-native-webview", "@metamask/react-native-webview", "@react-native-community/webview")
_SKIP_SCOPES = ("test", "build-script")   # mocks and tests render WebViews too; they don't ship
_MAX_VALUE = 3000                   # a prop value, an object literal, or a script read for analysis
_MAX_BODY = 20_000                  # a message handler's body
_IDENT = r"[A-Za-z_$][\w$]*"
_IDENT_RX = re.compile(_IDENT)
_MEMBER = re.compile(r"\s*(" + _IDENT + r"(?:\s*\??\.\s*" + _IDENT + r"){0,20})\s*!?\s*(?:as\s+string\s*)?")
_CONST_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
# `const Styled = styled(WebView)(...)`, `Animated.createAnimatedComponent(WebView)`, `React.memo(WebView)`.
_WRAPPER = re.compile(r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*=\s*(?:styled|(?:Animated\s*\.\s*)?"
                      r"createAnimatedComponent|(?:React\s*\.\s*)?memo)\s*\(\s*(" + _IDENT + r")\s*\)")

_DECL = re.compile(r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*(?::[^=;\n]{0,200})?=(?![=>])\s*")
_DESTRUCT = re.compile(r"\b(?:const|let|var)\s*\{([^{};]{0,400})\}\s*(?::[^=;\n]{0,200})?=\s*")
_STATE = re.compile(r"\[\s*(" + _IDENT + r")\s*,\s*(" + _IDENT + r")\s*\]\s*=\s*(?:React\s*\.\s*)?useState\b")
_SET_CALL = re.compile(r"\b(set[A-Z][\w$]*)\s*\(\s*(" + _IDENT + r")\s*\)")
_TEXT_FED = re.compile(r"\bonChange(?:Text)?\s*=\s*\{\s*(?:(" + _IDENT + r")\s*\}|\(?\s*" + _IDENT +
                       r"\s*\)?\s*=>\s*(" + _IDENT + r")\s*\()")
# A function definition: `const h = ...`, `function h(`, a class field `h = (e) =>`, a class method `h(e) {`.
_FUNC_DEF = re.compile(r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*(?::[^=;\n]{0,200})?=(?![=>])\s*"
                       r"|\bfunction\s+(" + _IDENT + r")\s*(?=\()"
                       r"|^[ \t]*(?:(?:private|public|protected|readonly|async)\s+){0,3}(" + _IDENT +
                       r")\s*(?::[^=;\n]{0,200})?=(?![=>])\s*"
                       r"|^[ \t]*(?:async\s+)?(" + _IDENT + r")\s*(?=\([^()\n]{0,200}\)\s*(?::[^{;\n]{0,200})?\{)",
                       re.M)


@dataclass
class _Source:
    kind: str
    uri: str = ""                     # the uri value's text, for URI_VAR
    uri_at: int = -1                  # its offset in the file


@dataclass
class _Site:
    path: str
    el: Element
    debug: bool                       # inside `if (__DEV__)` or after `__DEV__ &&`
    source: Optional[_Source] = None


@dataclass
class _File:
    path: str
    code: str                         # comments blanked, strings kept
    blank: str                        # comments and string contents blanked
    sites: List[_Site] = field(default_factory=list)
    _index: Optional[dict] = None
    _templates: Dict[int, Optional[Tuple[int, str]]] = field(default_factory=dict)

    def index(self) -> dict:
        """Declarations, destructured names, state, setters, and functions of the file, found in one pass each."""
        if self._index is None:
            ix: dict = {"decl": {}, "destruct": {}, "state": {}, "set_args": {}, "fed": set(), "func": {}}
            for m in _DECL.finditer(self.blank):
                ix["decl"].setdefault(m.group(1), m.end())
            for m in _DESTRUCT.finditer(self.blank):
                for item in m.group(1).split(","):
                    local = item.split("=", 1)[0].split(":")[-1].strip()
                    if _IDENT_RX.fullmatch(local):
                        ix["destruct"].setdefault(local, m.end())
            for m in _STATE.finditer(self.blank):
                ix["state"].setdefault(m.group(1), m.group(2))
            for m in _SET_CALL.finditer(self.blank):
                args = ix["set_args"].setdefault(m.group(1), [])
                if len(args) < 20:
                    args.append(m.group(2))
            for m in _TEXT_FED.finditer(self.blank):
                ix["fed"].add(m.group(1) or m.group(2))
            for m in _FUNC_DEF.finditer(self.blank):
                name = next(g for g in m.groups() if g)
                ix["func"].setdefault(name, m.end())
            ix["checked"] = bool(_CHECKED.search(self.blank))
            self._index = ix
        return self._index

    def decl(self, name: str) -> Optional[int]:
        """Offset just past `=` of the first `const|let|var name =` in the file."""
        return self.index()["decl"].get(name)

    def line(self, ctx: Context, offset: int) -> int:
        return ctx.line_of(self.code, offset)

    def value(self, s: _Site, name: str) -> Optional[str]:
        p = s.el.props.get(name)
        if p is None or p.kind != "expr" or p.end - p.start > _MAX_VALUE:
            return None
        return self.code[p.start:p.end]


def _webview_names(code: str, blank: str) -> List[str]:
    names = []
    for local, (module, imported) in imports(code).items():
        if module in _MODULES:
            if imported in ("default", "WebView"):
                names.append(local)
            elif imported == "*":
                names.append(local + ".WebView")
        elif module == "react-native" and imported == "WebView":
            names.append(local)               # the core WebView that react-native-webview replaced
    simple = set(n for n in names if "." not in n)
    if simple:
        for m in _WRAPPER.finditer(blank):
            if m.group(2) in simple:
                names.append(m.group(1))
    return names


def _webview_files(ctx: Context) -> List[_File]:
    def build() -> List[_File]:
        out: List[_File] = []
        for path in js_files(ctx):
            if scope_of(path) in _SKIP_SCOPES:
                continue
            raw = ctx.text(path)
            if not raw or "WebView" not in raw:
                continue
            code, blank = ctx.code(path), ctx.code(path, False)
            if code is None or blank is None:
                continue
            names = _webview_names(code, blank)
            if not names:
                continue
            f = _File(path, code, blank)
            for el in jsx_elements(code, blank, names):
                f.sites.append(_Site(path, el, in_dev(code, blank, el.start)))
            out.append(f)
        return out
    return memo(ctx, "rn:webview:files", build)


def _sites(ctx: Context) -> Iterator[Tuple[_File, _Site]]:
    for f in _webview_files(ctx):
        for s in f.sites:
            yield f, s


def _hit(ctx: Context, f: _File, s: _Site, offset: int, message: str, severity: str = "") -> Hit:
    line = f.line(ctx, offset)
    return Hit(f.path, line, ctx.snippet(f.path, line), message, scope="debug" if s.debug else "",
               severity=severity)


def _is_true(f: _File, s: _Site, name: str) -> bool:
    p = s.el.props.get(name)
    if p is None:
        return False
    return p.kind == "true" or (p.kind == "expr" and p.end - p.start < 100 and literal(f.code[p.start:p.end]) is True)


# ---------------------------------------------------------------------------- what the WebView loads

BUNDLED = "bundled"                   # require('./page.html'), or { html } with no interpolation
HTML_DYNAMIC = "html-dynamic"         # { html: `...${x}...` }
REMOTE = "remote"                     # { uri: 'https://...' }, a constant, or a URL built on a fixed base
URI_VAR = "uri-var"                   # { uri: someVariable }: the whole URL comes from a variable
UNKNOWN_SOURCE = "unknown"


def _source(f: _File, s: _Site) -> _Source:
    if s.source is None:
        p = s.el.props.get("source")
        s.source = _Source(UNKNOWN_SOURCE) if p is None or p.kind != "expr" else _classify_source(f, p.start, p.end)
    return s.source


def _classify_source(f: _File, start: int, end: int) -> _Source:
    if end - start > _MAX_VALUE:
        return _Source(UNKNOWN_SOURCE)
    text = f.blank[start:end]
    t = text.strip()
    at = start + len(text) - len(text.lstrip())
    if re.match(r"require\s*\(", t):
        return _Source(BUNDLED)
    if t.startswith("{") and t.endswith("}"):
        return _classify_object(f, at, at + len(t))
    if _IDENT_RX.fullmatch(t):
        decl = f.decl(t)
        if decl is not None:
            obj = _object_after(f.blank, decl)
            if obj is not None:
                return _classify_object(f, obj[0], obj[1])
    return _Source(UNKNOWN_SOURCE)


_MEMO_CALL = re.compile(r"(?:React\s*\.\s*)?useMemo\s*\(\s*(?:\(\s*\)|_)\s*=>\s*\(?\s*")


def _object_after(blank: str, at: int) -> Optional[Tuple[int, int]]:
    """The `{...}` object literal assigned at `at` (directly, or returned by `useMemo(() => ({...}))`)."""
    m = _MEMO_CALL.match(blank, at)
    if m:
        at = m.end()
    if at < len(blank) and blank[at] == "{":
        close = bracket_match(blank, at, "{", "}")
        if close < len(blank) and close - at <= _MAX_VALUE:
            return at, close + 1
    return None


_SEG_KEY = re.compile(r"\s*(uri|html)\s*(:)?")
_VALUE_STOP = re.compile(r"[,{(\[]")
_CLOSER = {"{": "}", "(": ")", "[": "]"}


def _object_keys(blank: str, start: int, end: int) -> Dict[str, Tuple[int, int]]:
    """Value spans of the top-level `uri` and `html` keys (`{ uri }` maps uri to itself) of the object literal
    blank[start:end], in one walk over its top-level commas."""
    keys: Dict[str, Tuple[int, int]] = {}
    last = end - 1                            # the object's closing `}`
    seg = j = start + 1
    while seg < last:
        n = _VALUE_STOP.search(blank, j, last)
        if n and n.group() != ",":
            j = bracket_match(blank, n.start(), n.group(), _CLOSER[n.group()]) + 1
            continue
        stop = n.start() if n else last
        m = _SEG_KEY.match(blank, seg, stop)
        if m and m.group(1) not in keys:
            if m.group(2):
                keys[m.group(1)] = (m.end(), stop)
            elif not blank[m.end():stop].strip():
                keys[m.group(1)] = (m.start(1), m.end(1))
        if not n:
            break
        seg = j = n.end()
    return keys


def _classify_object(f: _File, start: int, end: int) -> _Source:
    keys = _object_keys(f.blank, start, end)
    html = keys.get("html")
    if html is not None:
        v = f.blank[html[0]:html[1]].strip()
        return _Source(HTML_DYNAMIC if v.startswith("`") and "${" in v else BUNDLED)
    uri = keys.get("uri")
    if uri is None:
        return _Source(UNKNOWN_SOURCE)
    raw = f.blank[uri[0]:uri[1]]
    v = raw.strip()
    at = uri[0] + len(raw) - len(raw.lstrip())
    if not v or v[0] in "'\"`":
        return _Source(REMOTE)        # a literal, or a template on a fixed base or `${BASE}/path`
    # `url ?? ''` and `url || 'about:blank'` still load the variable.
    v = re.split(r"\?\?|\|\|", v, maxsplit=1)[0].strip()
    m = _MEMBER.fullmatch(v)
    if m is None:
        return _Source(UNKNOWN_SOURCE)
    last = re.split(r"\s*\??\.\s*", m.group(1))[-1]
    if _CONST_NAME.fullmatch(last):
        return _Source(REMOTE)        # `HELP_URL`, `Config.HELP_URL`
    return _Source(URI_VAR, f.code[at:at + len(v)], at)


# ---------------------------------------------------------------------------- RN-005

_READ_ROOT = re.compile(r"\s*(?:'file:///?'|\"file:///?\"|`file:///?`|(?:RNFS|FileSystem|RNFetchBlob\.fs\.dirs|Dirs|"
                        r"ReactNativeBlobUtil\.fs\.dirs)\s*\.\s*(?:DocumentDirectoryPath|documentDirectory|DocumentDir|"
                        r"LibraryDirectoryPath|MainBundlePath|MainBundleDir|bundleDirectory|CachesDirectoryPath|"
                        r"cacheDirectory|CacheDir)|`file://\$\{\s*(?:RNFS|FileSystem)\s*\.\s*(?:DocumentDirectoryPath|"
                        r"documentDirectory|LibraryDirectoryPath|MainBundlePath)\s*\}/?`)\s*")
_WEB_BASE = re.compile(r"\bbaseUrl\s*:\s*['\"`]https?://")
# A source that is, or may be, a file:// page: bundled HTML through require(), a file: URL, or an app folder.
_FILE_PAGE = re.compile(r"\brequire\s*\(|file:|Directory|MainBundle|BundleDir|BundlePath|DocumentDir|CacheDir|"
                        r"\bPaths\s*\.")


def _filtered(s: _Site) -> bool:
    """The app vets every navigation itself: an explicit onShouldStartLoadWithRequest. A spread (`{...props}`)
    can only swap it for another handler."""
    return "onShouldStartLoadWithRequest" in s.el.props


@detector("rn_webview_file_access")
def webview_file_access(ctx: Context, rule: Rule) -> Iterator[Hit]:
    for f, s in _sites(ctx):
        props = s.el.props
        # HTML given a web baseUrl isn't a file:// page, so the file-URL switches change nothing today.
        source = f.value(s, "source") or ""
        web_page = _WEB_BASE.search(source) is not None
        # The file-URL switches act only on a file:// page. When the first page isn't one and the app vets
        # every navigation, no file:// page loads unless that check lets it.
        if _filtered(s) and source and not _FILE_PAGE.search(source) \
                and _source(f, s).kind in (REMOTE, BUNDLED, HTML_DYNAMIC):
            props = {k: v for k, v in props.items()
                     if k not in ("allowUniversalAccessFromFileURLs", "allowFileAccessFromFileURLs")}
        if "allowUniversalAccessFromFileURLs" in props and _is_true(f, s, "allowUniversalAccessFromFileURLs"):
            yield _hit(ctx, f, s, props["allowUniversalAccessFromFileURLs"].start,
                       "allowUniversalAccessFromFileURLs is on: a script in a file:// page can read any local file "
                       "the app can read and send it to any web site.", severity="low" if web_page else "")
        elif "allowFileAccessFromFileURLs" in props and _is_true(f, s, "allowFileAccessFromFileURLs"):
            yield _hit(ctx, f, s, props["allowFileAccessFromFileURLs"].start,
                       "allowFileAccessFromFileURLs is on: a script in a file:// page can read other local files.",
                       severity="low" if web_page else "")
        elif _is_true(f, s, "allowFileAccess"):
            if _source(f, s).kind == BUNDLED:
                yield _hit(ctx, f, s, props["allowFileAccess"].start,
                           "allowFileAccess is on, and this WebView shows bundled HTML. Pass the HTML with "
                           "`source={{ html }}` or `require()` and turn file access off.", severity="medium")
            else:
                yield _hit(ctx, f, s, props["allowFileAccess"].start,
                           "allowFileAccess is on: pages in this WebView can open file:// URLs inside the app.")
        else:
            p = props.get("allowingReadAccessToURL")
            if p is not None and p.kind == "expr" and p.end - p.start < 200 and _READ_ROOT.fullmatch(
                    f.code, p.start, p.end):
                yield _hit(ctx, f, s, p.start, "allowingReadAccessToURL grants read access to a whole app "
                           "directory. Grant it to the one folder that holds the page.", severity="medium")


# ---------------------------------------------------------------------------- RN-006

def _origin_list(f: _File, s: _Site):
    """The originWhitelist value: a list of strings, or UNKNOWN."""
    v = f.value(s, "originWhitelist")
    if v is None:
        return UNKNOWN
    val = literal(v)
    if val is UNKNOWN and _IDENT_RX.fullmatch(v.strip()):
        at = f.decl(v.strip())
        if at is not None:
            m = _MEMO_CALL.match(f.blank, at)
            if m:
                at = m.end()
            if at < len(f.blank) and f.blank[at] == "[":
                close = bracket_match(f.blank, at, "[", "]")
                if close < len(f.blank) and close - at <= _MAX_VALUE:
                    val = literal(f.code[at:close + 1])
    return val if isinstance(val, list) else UNKNOWN


@detector("rn_webview_origin_wildcard")
def webview_origin_wildcard(ctx: Context, rule: Rule) -> Iterator[Hit]:
    for f, s in _sites(ctx):
        origins = _origin_list(f, s)
        if origins is UNKNOWN or "*" not in origins:
            continue
        kind = _source(f, s).kind
        if kind in (BUNDLED, HTML_DYNAMIC):
            continue                  # react-native-webview's docs use ['*'] for HTML strings
        if _filtered(s):
            continue                  # every URL goes through the app's own onShouldStartLoadWithRequest check
        at = s.el.props["originWhitelist"].start
        if kind == REMOTE:
            yield _hit(ctx, f, s, at, "originWhitelist is ['*'] on a WebView that loads a remote page. The page, "
                       "or a redirect, can take the WebView to any URL scheme, file:// and data: included.")
        else:
            yield _hit(ctx, f, s, at, "originWhitelist is ['*'] on a WebView whose page comes from a variable. "
                       "Any URL in any scheme, file:// and data: included, loads inside the app.")


# ---------------------------------------------------------------------------- RN-007

# Where a URL comes from when a link, another screen, or another app chooses it.
_ROUTE_RX = re.compile(r"\broute\s*\??\.\s*params\b|\bnavigation\s*\??\.\s*(?:getParam\s*\(|state\s*\??\.\s*params\b)"
                       r"|\buse(?:Local|Global)?SearchParams\s*(?:<[^<>()]{0,200}>)?\s*\(|\buseParams\s*"
                       r"(?:<[^<>()]{0,200}>)?\s*\(|\buseRoute\s*(?:<[^<>()]{0,200}>)?\s*\(\s*\)\s*\??\.\s*params\b"
                       r"|\bLinking\s*\.\s*useURL\s*\(|\buseURL\s*\(\s*\)")
# The file checks a URL's host somewhere: parsing it, comparing hosts, or calling an allowlist helper.
_CHECKED = re.compile(r"\bnew\s+URL\s*\(|\bURL\s*\.\s*parse\s*\(|\burl-parse\b|\.\s*(?:hostname|host|origin)\b|"
                      r"\b(?:allow|white|trust)(?:ed)?_?(?:list|hosts?|domains?|origins?|urls?)\b|"
                      r"\b(?:ALLOWED|TRUSTED|WHITELISTED)_[A-Z]|"
                      r"\b(?:is|check|validate|verify|assert)[A-Za-z]{0,30}(?:Url|URL|Host|Origin|Domain|Link)"
                      r"[A-Za-z]{0,20}\s*\(")


def _url_origin(f: _File, src: _Source) -> str:
    """How the variable URL reaches the WebView, when the file shows it: "route" (navigation or route params,
    search params, a link) or "input" (state the user types into), else ""."""
    if _ROUTE_RX.search(src.uri):
        return "route"
    root = _IDENT_RX.match(src.uri.strip())
    if not root or root.group() in ("props", "this"):
        return ""
    name = root.group()
    ix = f.index()
    for at in (ix["decl"].get(name), ix["destruct"].get(name)):
        if at is not None:
            end = f.blank.find(";", at, at + 300)
            if _ROUTE_RX.search(f.blank, at, end if end >= 0 else min(len(f.blank), at + 300)):
                return "route"
    setter = ix["state"].get(name)
    if setter is not None:
        # `const [url, setUrl] = useState()` fed by a text field, directly or one step away.
        if setter in ix["fed"]:
            return "input"
        for arg in ix["set_args"].get(setter, ()):
            other = ix["state"].get(arg)
            if other is not None and other in ix["fed"]:
                return "input"
    return ""


def _narrow(origins) -> bool:
    """An originWhitelist naming hosts: no bare `*` and no `scheme://*` entries."""
    return isinstance(origins, list) and bool(origins) and all(
        isinstance(o, str) and not re.fullmatch(r"\*|[\w+.-]{1,30}:(?://)?\*?", o) for o in origins)


@detector("rn_webview_variable_url")
def webview_variable_url(ctx: Context, rule: Rule) -> Iterator[Hit]:
    for f, s in _sites(ctx):
        if s.el.spread or "onShouldStartLoadWithRequest" in s.el.props:
            continue                  # spread props may carry the navigation check
        src = _source(f, s)
        if src.kind != URI_VAR or _narrow(_origin_list(f, s)):
            continue
        origin = _url_origin(f, src)
        if not origin or f.index()["checked"]:
            continue
        shown = " ".join(src.uri.split())[:80]
        if origin == "route":
            msg = (f"The WebView loads `{shown}`, a URL from navigation params, with no host check. A deep link "
                   "or another screen that passes params decides which page runs inside the app.")
        else:
            msg = (f"The WebView loads `{shown}`, a URL the user types, with no host check and no "
                   "onShouldStartLoadWithRequest.")
        if re.search(r"\bheaders\b[\s\S]{0,300}?\b(?:Authorization|Cookie|token)\b", f.value(s, "source") or "", re.I):
            msg += " The request also sends credentials in its headers to that URL."
        yield _hit(ctx, f, s, src.uri_at, msg)


# ---------------------------------------------------------------------------- RN-008

_ORIGIN_CHECK = re.compile(r"\bnativeEvent\s*\??\.\s*url\b|\bnativeEvent\s*:\s*\{[^{}]{0,200}\burl\b|"
                           r"\b(?:e|ev|evt|event|message|msg|payload)\s*\??\.\s*url\b|"
                           r"\{[^{}]{0,200}\burl\b[^{}]{0,200}\}\s*=\s*(?:\w+\s*\??\.\s*)?nativeEvent\b|"
                           r"\borigin\b|\bhost(?:name)?\b|\bsourceUrl\b")
_READS_DATA = re.compile(r"\.\s*data\b|\bdata\s*[}:,]|\bnativeEvent\s*:\s*\{[^{}]{0,200}\bdata\b")
# Acting on the message: parsing it, dispatching on it, or handing it to app code.
_ACTS = re.compile(r"\bJSON\s*\.\s*parse\s*\(|\bswitch\s*\(|\bdispatch\s*\(|\bnavigat\w{0,20}\s*\.|\bnavigate\s*\(|"
                   r"\bLinking\s*\.|\bopenURL\s*\(|\bfetch\s*\(|\bawait\b|\.\s*(?:type|action|method|name|event)\b")
_ARROW = re.compile(r"\s*(?::[^=;{]{0,200})?=>\s*")
_BLOCK = re.compile(r"\s*(?::[^{;=]{0,200})?\{")
_FUNCTION_HEAD = re.compile(r"\s*(?:async\s+)?(?:function\b\s*(?:" + _IDENT + r")?\s*)?")
_CALLBACK = re.compile(r"(?:React\s*\.\s*)?use(?:Callback|Memo)\s*(?:<[^<>()]{0,200}>)?\s*\(\s*")


def _function_span(blank: str, at: int) -> Optional[Tuple[int, int]]:
    """The text of the function that starts at `at`: an arrow, a `function`, or a method's parameters and body."""
    m = _CALLBACK.match(blank, at)
    if m:
        at = m.end()
    m = _FUNCTION_HEAD.match(blank, at)
    at = m.end() if m else at
    if at >= len(blank):
        return None
    if blank[at] == "(":
        close = bracket_match(blank, at, "(", ")")
    else:
        p = _IDENT_RX.match(blank, at)
        if not p:
            return None
        close = p.end() - 1
    a = _ARROW.match(blank, close + 1)
    b = None if a else _BLOCK.match(blank, close + 1)
    if a:
        body = a.end()
        if body < len(blank) and blank[body] in "({":
            end = bracket_match(blank, body, blank[body], ")" if blank[body] == "(" else "}")
        else:
            nl = blank.find("\n", body, body + 2000)
            end = nl if nl >= 0 else min(len(blank), body + 2000)
    elif b:
        end = bracket_match(blank, b.end() - 1, "{", "}")
    else:
        return None
    if end >= len(blank) or end - at > _MAX_BODY:
        return None
    return at, end + 1


def _handler_body(f: _File, start: int, end: int) -> Optional[str]:
    """The onMessage handler's text: the inline function, or the local function its name refers to."""
    t = f.blank[start:end].strip()
    if "=>" in t or t.startswith(("function", "async")):
        return t if len(t) <= _MAX_BODY else None
    m = re.fullmatch(r"(?:this\s*\.\s*)?(" + _IDENT + r")", t)
    if not m or t.startswith("props"):
        return None
    at = f.index()["func"].get(m.group(1))
    if at is None:
        return None
    span = _function_span(f.blank, at)
    return f.blank[span[0]:span[1]] if span else None


_QUOTED = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")
_SPECIFIC_ORIGIN = re.compile(r"https://(?:\*\.)?[\w-]+(?:\.[\w-]+)+(?::\d+)?/?")


def _specific_origins(f: _File, s: _Site) -> bool:
    """originWhitelist is a literal list of named https origins (`["https://*.typeform.com"]`): the WebView only
    loads those, so only they can send messages. `*`, `http://*` or a variable don't count."""
    p = s.el.props.get("originWhitelist")
    if p is None or p.kind != "expr":
        return False
    text = f.code[p.start:p.end].strip()
    if len(text) > 2000 or not (text.startswith("[") and text.endswith("]")):
        return False
    entries = [a or b for a, b in _QUOTED.findall(text)]
    # Nothing but the quoted entries, commas, and spaces between the brackets (no variables, no spreads).
    rest = _QUOTED.sub("", text[1:-1])
    return bool(entries) and not rest.replace(",", "").strip() and all(_SPECIFIC_ORIGIN.fullmatch(e) for e in entries)


def _message_hit(ctx: Context, f: _File, s: _Site) -> Optional[Hit]:
    p = s.el.props.get("onMessage")
    if p is None or p.kind != "expr" or p.end - p.start > _MAX_BODY:
        return None
    if _source(f, s).kind not in (REMOTE, URI_VAR):
        return None                   # bundled HTML, or a source this scan can't read
    if s.el.spread or "onShouldStartLoadWithRequest" in s.el.props or _specific_origins(f, s):
        return None                   # the app already decides which pages load, so which pages send messages
    body = _handler_body(f, p.start, p.end)
    if body is None or not _READS_DATA.search(body) or _ORIGIN_CHECK.search(body) or not _ACTS.search(body):
        return None
    return _hit(ctx, f, s, p.start, "onMessage acts on messages from the page without checking "
                "event.nativeEvent.url. Any page the WebView reaches, or an iframe inside it, can send them.")


_INJECT_CALL = re.compile(r"\.\s*injectJavaScript\s*\(")
# Values that can't break out of a string: encoded, or numeric.
_SAFE_EXPR = re.compile(r"\s*(?:(?:JSON\s*\.\s*stringify|encodeURI(?:Component)?|escape[A-Za-z]{0,30}|[a-z]{0,30}"
                        r"(?:Escape|Sanitize|sanitize)[A-Za-z]{0,30}|Number|parseInt|parseFloat|Math\s*\.\s*[a-z]{1,10}|"
                        r"toHex)\s*\(|-?\d|(?:true|false|null|undefined)\s*$)")
# Names of values that are numbers, identifiers, or settings rather than text from a person or a server.
_SAFE_NAME = re.compile(r"(?:id|Id|ID|address|Address|hash|Hash|count|Count|index|Index|height|Height|width|Width|"
                        r"size|Size|scale|Scale|top|bottom|left|right|Top|Bottom|Left|Right|color|Color|theme|"
                        r"Theme|nonce|Nonce|version|Version|platform|Platform|OS|locale|Locale|lang|"
                        r"language|Language|mode|Mode|px|ms|offset|Offset|zoom|Zoom|enabled|Enabled|key|Key)$")
_CONCAT = re.compile(r"(['\"])\s*\+\s*(" + _IDENT + r"(?:\s*\??\.\s*" + _IDENT + r"){0,20})\s*\+\s*['\"]")


def _unsafe(expr: str) -> bool:
    """A plain name or member chain that isn't a constant or named for a number or an identifier. Calls and other
    expressions are left alone: they are mostly formatting and translation helpers."""
    e = expr.strip()
    if not e or _SAFE_EXPR.match(e):
        return False
    m = _MEMBER.fullmatch(e)
    if not m:
        return False
    last = re.split(r"\s*\??\.\s*", m.group(1))[-1]
    return not (_CONST_NAME.fullmatch(last) or _SAFE_NAME.search(last))


def _template_scan(f: _File, i: int, limit: int) -> Optional[Tuple[int, str]]:
    """Walk the template literal opening at i once. The first `${expr}` inside a '...' or "..." string of the
    script whose value isn't encoded: (offset, expression), or None. Results are kept per template."""
    if i in f._templates:
        return f._templates[i]
    code, blank = f.code, f.blank
    found = None
    quote = ""
    j = i + 1
    while j < limit:
        c = code[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            break
        if c == "$" and code.startswith("${", j):
            close = bracket_match(blank, j + 1, "{", "}")
            if close >= limit:
                break
            if quote and found is None and _unsafe(code[j + 2:close]):
                found = (j + 2, " ".join(code[j + 2:close].split()))
            j = close + 1
            continue
        if c == "\n":
            quote = ""
        elif quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        j += 1
    f._templates[i] = found
    return found


def _script_vars(f: _File, start: int, end: int) -> Optional[Tuple[int, str]]:
    """The first value put into a quoted string of the script at [start:end] without encoding: a `${expr}`
    inside quotes of a template, or `'...' + name + '...'`. (offset, expression text) or None."""
    text = f.blank[start:end]
    t = text.lstrip()
    if t.startswith("`"):
        return _template_scan(f, start + len(text) - len(t), end)
    for m in _CONCAT.finditer(text):
        if _unsafe(m.group(2)):
            return start + m.start(2), " ".join(m.group(2).split())
    return None


def _script_hit(ctx: Context, f: _File, start: int, end: int, debug: bool, what: str) -> Optional[Hit]:
    found = _script_vars(f, start, end)
    if found is None:
        t = f.blank[start:end].strip()
        if _IDENT_RX.fullmatch(t):           # `injectedJavaScript={script}`: read the local script it names
            at = f.decl(t)
            if at is not None and at < len(f.blank) and f.blank[at] in "`'\"":
                found = _script_vars(f, at, min(len(f.blank), at + _MAX_VALUE))
    if found is None:
        return None
    at, expr = found
    line = f.line(ctx, at)
    return Hit(f.path, line, ctx.snippet(f.path, line),
               f"{what} puts `{expr[:60]}` into a string in the script without encoding. If that value comes from "
               "the user or a server, it can run its own JavaScript in the page. Send it with postMessage, or "
               "encode it with JSON.stringify.", scope="debug" if debug else "")


@detector("rn_webview_bridge")
def webview_bridge(ctx: Context, rule: Rule) -> Iterator[Hit]:
    seen: Set[Tuple[str, int]] = set()
    files = {f.path: f for f in _webview_files(ctx)}
    for f in files.values():
        for s in f.sites:
            h = _message_hit(ctx, f, s)
            if h is not None:
                yield h
            for name in ("injectedJavaScript", "injectedJavaScriptBeforeContentLoaded"):
                p = s.el.props.get(name)
                if p is not None and p.kind == "expr" and p.end - p.start <= _MAX_VALUE:
                    h = _script_hit(ctx, f, p.start, p.end, s.debug, name)
                    if h is not None and (h.path, h.line) not in seen:
                        seen.add((h.path, h.line))
                        yield h
    for path in js_files(ctx):
        if scope_of(path) in _SKIP_SCOPES:
            continue
        raw = ctx.text(path)
        if not raw or "injectJavaScript" not in raw:
            continue
        f = files.get(path)
        if f is None:
            code, blank = ctx.code(path), ctx.code(path, False)
            if code is None or blank is None:
                continue
            f = _File(path, code, blank)
        last = -1
        for m in _INJECT_CALL.finditer(f.blank):
            if m.start() < last:
                continue                      # a call inside the previous call's arguments
            close = bracket_match(f.blank, m.end() - 1, "(", ")")
            last = close
            if close >= len(f.blank) or close - m.end() > _MAX_VALUE:
                continue
            h = _script_hit(ctx, f, m.end(), close, False, "injectJavaScript")
            if h is not None and (h.path, h.line) not in seen:
                seen.add((h.path, h.line))
                yield h
