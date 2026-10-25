# SPDX-License-Identifier: Apache-2.0
"""React Native detectors: deep links, native bridges, eval, SQLite, biometrics, and crypto-js. Shared helpers are
in reactnative.py.

RN-009 deep-link data reaching a sink, RN-010 code built from a string, RN-011 SQLite SQL built from strings,
RN-012 a boolean-only biometric check, RN-013 crypto-js passphrase mode, RN-020 a native module that runs a shell
command or opens a file path received from JavaScript. Every search is bounded: a crafted file stays linear.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit.detect import scope_of
from masaudit.detectors import reactnative as rn
from masaudit.detectors.reactnative import call_args, has_dep, imports, js_files, jsx_elements, memo
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.textscan import bracket_match

# ---------------------------------------------------------------------------- shared

_SKIP_SCOPES = {"test", "build-script", "ci"}
# Vendored or generated JavaScript: third-party bundles are not the app's own code.
_VENDORED = re.compile(r"(?:^|/)(?:vendor|vendors|third[_-]?party|dist|web-build|lib-dist)/|\.(?:min|bundle)\.[cm]?js$")
_LONG_LINE = 2000                   # a line this long means minified or generated code
_MAX_HITS_PER_RULE_FILE = 50


def _minified(text: str) -> bool:
    if len(text) < _LONG_LINE:
        return False
    start = 0
    n = len(text)
    while start < n:
        end = text.find("\n", start)
        if end < 0:
            end = n
        if end - start > _LONG_LINE:
            return True
        start = end + 1
    return False


def _app_js(ctx: Context, needles: Tuple[str, ...]) -> Iterator[Tuple[str, str]]:
    """(path, raw text) of the app's own JavaScript files that hold one of `needles`."""
    for path in js_files(ctx):
        if scope_of(path) in _SKIP_SCOPES or _VENDORED.search(path):
            continue
        raw = ctx.text(path)
        if not raw or not any(n in raw for n in needles):
            continue
        if _minified(raw):
            continue
        yield path, raw


def _hit(ctx: Context, path: str, text: str, idx: int, message: str, blank: Optional[str] = None) -> Hit:
    line = ctx.line_of(text, idx)
    scope = "debug" if blank is not None and rn.in_dev(text, blank, idx) else ""
    return Hit(path, line, ctx.snippet(path, line), message, scope=scope)


_IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def _first_arg(blank: str, paren: int) -> Optional[Tuple[int, int]]:
    args = call_args(blank, paren)
    return args[0] if args else None


def _strip_parens(code: str, blank: str, s: int, e: int) -> Tuple[int, int]:
    """Trim whitespace (and one layer of wrapping parentheses) from an argument span."""
    while s < e and blank[s] in " \t\r\n":
        s += 1
    while e > s and blank[e - 1] in " \t\r\n":
        e -= 1
    if s < e and blank[s] == "(" and bracket_match(blank, s, "(", ")") == e - 1:
        return _strip_parens(code, blank, s + 1, e - 1)
    return s, e


def _is_string_literal(code: str, blank: str, s: int, e: int) -> bool:
    """The whole span is one quoted string, or a template literal with no `${…}`."""
    s, e = _strip_parens(code, blank, s, e)
    if e - s < 2 or blank[s] not in "'\"`" or blank[e - 1] != blank[s]:
        return False
    inner = blank[s + 1:e - 1]
    return inner.strip() == "" and (blank[s] != "`" or "${" not in inner)


def _all_literal_args(code: str, blank: str, spans: List[Tuple[int, int]]) -> bool:
    return all(_is_string_literal(code, blank, s, e) for s, e in spans)


# ---------------------------------------------------------------------------- RN-010

_EVAL = re.compile(r"(?<![\w$.])(?:(eval)|(?:new\s+)?(Function)|(setTimeout|setInterval))\s*\(")
_OBFUSCATED = re.compile(r"\batob\s*\(|\bBuffer\s*\.\s*from\s*\(|base64|fromCharCode|\bdecode\w*\s*\(", re.I)


@detector("rn_eval")
def rn_eval(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, _raw in _app_js(ctx, ("eval", "Function", "setTimeout", "setInterval")):
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        n = 0
        for m in _EVAL.finditer(blank):
            paren = m.end() - 1
            spans = call_args(blank, paren)
            if not spans:
                continue
            if m.group(1):
                if _all_literal_args(code, blank, spans[:1]):
                    continue
                arg = code[spans[0][0]:spans[0][1]]
                if _OBFUSCATED.search(arg):
                    msg = ("`eval` runs text that is decoded at runtime. That is how injected or obfuscated code "
                           "hides; check that a dependency or build step was not compromised.")
                else:
                    msg = "`eval` runs a string built at runtime as code. If any part of it comes from outside, " \
                          "an attacker's text runs with the app's full access."
            elif m.group(2):
                if _function_is_declaration(blank, m.start()) or _all_literal_args(code, blank, spans):
                    continue
                msg = ("`Function(...)` compiles a string built at runtime into code. If any part of it comes "
                       "from outside, an attacker's text runs inside the app.")
            else:
                s, e = _strip_parens(code, blank, *spans[0])
                if not _string_built(blank, s, e):
                    continue
                msg = (f"`{m.group(3)}` gets a string, which JavaScript runs as code. Pass a function instead.")
            yield _hit(ctx, path, blank, m.start(), msg, blank)
            n += 1
            if n >= _MAX_HITS_PER_RULE_FILE:
                break


def _function_is_declaration(blank: str, start: int) -> bool:
    """`Function(` that is a TypeScript type or a method named Function, not a call to the constructor."""
    j = start - 1
    while j >= 0 and blank[j] in " \t":
        j -= 1
    return j >= 0 and blank[j] in ":<|&"


def _string_built(blank: str, s: int, e: int) -> bool:
    """A template literal with `${…}`, or a `+` concatenation that includes a quoted string."""
    if s >= e:
        return False
    if blank[s] == "`" and "${" in blank[s:e]:
        return True
    depth = 0
    has_plus = has_quote = False
    for k in range(s, e):
        c = blank[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "+":
            has_plus = True
        elif depth == 0 and c in "'\"`":
            has_quote = True
    return has_plus and has_quote


# ---------------------------------------------------------------------------- RN-013

_CRYPTOJS_MODULES = ("crypto-js", "react-native-crypto-js", "crypto-es")
_AES_CALL = re.compile(r"(?<![\w$])AES\s*\.\s*(encrypt|decrypt)\s*\(")
# Key expressions that give a WordArray (a raw key), not a passphrase string.
_WORDARRAY = re.compile(r"\.\s*parse\s*\(|\bPBKDF2\s*\(|\bWordArray\b|\b(?:SHA\d*|SHA3|MD5|RIPEMD160|Hmac\w+|EvpKDF)\s*\("
                        r"|\blib\s*\.|\.\s*random\s*\(")


def _decl_value(code: str, blank: str, name: str, before: int) -> Optional[str]:
    """The value of the last `const|let|var name = …` before `before`, in `code` coordinates, bounded."""
    rx = re.compile(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\s*(?::[^=;\n]{0,200})?=(?![=>])")
    last = None
    for m in rx.finditer(blank, max(0, before - 20_000), before):
        last = m
    if last is None:
        return None
    end = _statement_end(blank, last.end(), min(len(blank), last.end() + 2000))
    return code[last.end():end]


def _skip_string(blank: str, k: int, limit: int) -> int:
    """The index just past the string or template literal that opens at k (blanked code keeps the quotes)."""
    q = blank[k]
    j = k + 1
    while j < limit and blank[j] != q:
        if q == "`" and blank.startswith("${", j):
            j = bracket_match(blank, j + 1, "{", "}") + 1
            continue
        if q != "`" and blank[j] == "\n":
            break
        j += 1
    return min(j + 1, limit)


def _statement_end(blank: str, i: int, limit: int) -> int:
    """The end of the expression starting at i: `;`, or a newline at bracket depth 0 that doesn't continue."""
    depth = 0
    k = i
    while k < limit:
        c = blank[k]
        if c in "'\"`":
            k = _skip_string(blank, k, limit)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return k
            depth -= 1
        elif depth == 0 and c in ";,":
            return k
        elif depth == 0 and c == "\n":
            rest = blank[k:min(limit, k + 200)].lstrip()
            if not rest or rest[0] not in ".+-*/?:|&=":
                prev = blank[i:k].rstrip()
                if prev and prev[-1] not in "=+-*/?:|&(,{[":
                    return k
        k += 1
    return k


def _key_kind(code: str, blank: str, s: int, e: int, depth: int = 0) -> str:
    """'raw' (a WordArray key), 'literal' (a string in the code), or 'string' (a passphrase or unknown)."""
    text = code[s:e].strip()
    if _WORDARRAY.search(text):
        return "raw"
    if re.fullmatch(r"\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`$]*`)\s*", text):
        return "literal"
    name = re.fullmatch(r"(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)", text)
    if name and depth < 2:
        value = _decl_value(code, blank, name.group(1), s)
        if value is not None:
            if _WORDARRAY.search(value):
                return "raw"
            if re.fullmatch(r"\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`$]*`)\s*", value):
                return "literal"
    return "string"


@detector("rn_cryptojs_passphrase")
def rn_cryptojs_passphrase(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, raw in _app_js(ctx, ("AES",)):
        if "crypto-js" not in raw and "crypto-es" not in raw:
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        if not any(module.startswith(_CRYPTOJS_MODULES) for module, _ in imports(code).values()):
            continue
        n = 0
        for m in _AES_CALL.finditer(blank):
            spans = call_args(blank, m.end() - 1)
            if len(spans) < 2:
                continue
            if len(spans) >= 3:
                cfg = blank[spans[2][0]:spans[2][1]]
                if re.search(r"\biv\b|\bECB\b", cfg) or not cfg.lstrip().startswith("{"):
                    continue                      # an IV (or ECB) means the developer passes a raw key
            kind = _key_kind(code, blank, *spans[1])
            if kind == "raw":
                continue
            where = " The passphrase is also written in the code." if kind == "literal" else ""
            yield _hit(ctx, path, blank, m.start(),
                       f"`AES.{m.group(1)}` gets a string key, so crypto-js treats it as a passphrase and derives "
                       "the real key and IV with one round of MD5 (OpenSSL EVP_BytesToKey). A guessed passphrase "
                       f"opens the data.{where}", blank)
            n += 1
            if n >= _MAX_HITS_PER_RULE_FILE:
                break


# ---------------------------------------------------------------------------- RN-011

_SQLITE_MODULES = ("expo-sqlite", "react-native-sqlite-storage", "@op-engineering/op-sqlite", "react-native-quick-sqlite",
                   "@journeyapps/react-native-quick-sqlite", "react-native-sqlite-2", "@nozbe/sqlite")
# Method names only SQLite drivers use; generic ones (`execute`, `exec`) count only in a file that imports a driver.
_SQL_DISTINCT = ("executeSql", "execAsync", "runAsync", "getAllAsync", "getFirstAsync", "getEachAsync", "prepareAsync",
                 "execSync", "runSync", "getAllSync", "getFirstSync", "prepareSync", "executeRawAsync", "executeAsync")
_SQL_GENERIC = ("execute", "executeRaw", "exec", "run", "all", "get")
_SQL_CALL = re.compile(r"\.\s*(" + "|".join(_SQL_DISTINCT + _SQL_GENERIC) + r")\s*\(")
_SQL_WORD = re.compile(r"(?i)\b(?:select|insert|update|delete|replace|create|drop|alter|pragma|where|values|from)\b")
_SAFE_EXPR = re.compile(r"['\"`]\s*\?\s*['\"`]|placeholder|\bNumber\s*\(|\bparseInt\s*\(|\bparseFloat\s*\(|\bMath\s*\."
                        r"|\.\s*length\b|\bDate\s*\.\s*now\s*\(|\.\s*toFixed\s*\(|escape|quote|sanitiz", re.I)
_CONST_NAME = re.compile(r"[A-Z][A-Z0-9_]*")


def _module_consts(code: str, blank: str) -> Set[str]:
    """Names declared `const NAME = <string or number literal>` in this file."""
    out: Set[str] = set()
    for m in re.finditer(r"\bconst\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,80})?=\s*", blank):
        v = code[m.end():m.end() + 300]
        if re.match(r"(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`$]*`|-?\d[\d.]*)\s*(?:;|\n|$)", v):
            out.add(m.group(1))
    return out


def _expr_is_constant(code: str, blank: str, s: int, e: int, consts: Set[str]) -> bool:
    expr_code, expr_blank = code[s:e], blank[s:e]
    if _SAFE_EXPR.search(expr_code):
        return True
    # A ternary choosing between string literals: `asc ? 'ASC' : 'DESC'`.
    if re.fullmatch(r"[^?]{1,200}\?\s*(?:'[^']*'|\"[^\"]*\")\s*:\s*(?:'[^']*'|\"[^\"]*\")\s*", expr_code.strip()):
        return True
    names = [m.group(0) for m in _IDENT.finditer(expr_blank)
             if m.start() == 0 or expr_blank[m.start() - 1] != "."]
    for name in names:
        if name in ("true", "false", "null", "undefined") or name in consts or _CONST_NAME.fullmatch(name):
            continue
        return False
    return True


def _sql_parts(code: str, blank: str, s: int, e: int) -> Tuple[str, List[Tuple[int, int]]]:
    """The literal SQL text of an argument and the spans of the expressions spliced into it."""
    s, e = _strip_parens(code, blank, s, e)
    literal_chars: List[str] = []
    exprs: List[Tuple[int, int]] = []
    k = s
    depth = 0
    piece = s
    while k < e:
        c = blank[k]
        if c in "'\"" and depth == 0:
            close = blank.find(c, k + 1, e)
            close = e if close < 0 else close
            literal_chars.append(code[k + 1:close] + " ")
            k = close + 1
            piece = k
            continue
        if c == "`" and depth == 0:
            j = k + 1
            while j < e and blank[j] != "`":
                if blank.startswith("${", j):
                    close = bracket_match(blank, j + 1, "{", "}")
                    if close >= e:
                        return "", []
                    exprs.append((j + 2, close))
                    literal_chars.append(" ")
                    j = close + 1
                else:
                    literal_chars.append(code[j])
                    j += 1
            k = j + 1
            piece = k
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "+" and depth == 0:
            if blank[piece:k].strip():
                exprs.append((piece, k))
            piece = k + 1
        k += 1
    if piece < e and blank[piece:e].strip() and (exprs or literal_chars):
        exprs.append((piece, e))
    return "".join(literal_chars), exprs


@detector("rn_sqlite_concat")
def rn_sqlite_concat(ctx: Context, rule: Rule) -> Iterable[Hit]:
    if not has_dep(ctx, *_SQLITE_MODULES):
        return
    for path, _raw in _app_js(ctx, ("Sync", "Async", "Sql", "exec", ".run", ".all", ".get")):
        code = ctx.code(path) or ""
        blank = ctx.code(path, keep_strings=False) or ""
        imported = any(module.startswith(_SQLITE_MODULES) for module, _ in imports(code).values())
        consts: Optional[Set[str]] = None
        n = 0
        for m in _SQL_CALL.finditer(blank):
            if m.group(1) not in _SQL_DISTINCT and not imported:
                continue
            arg = _first_arg(blank, m.end() - 1)
            if arg is None:
                continue
            s, e = _strip_parens(code, blank, *arg)
            if consts is None:
                consts = _module_consts(code, blank)
            name = re.fullmatch(r"[A-Za-z_$][\w$]*", blank[s:e])
            if name:                                       # `executeSql(query, …)`: read the query's declaration
                found = _sql_from_decl(code, blank, name.group(0), s)
                if found is None:
                    continue
                s, e = found
            literal_sql, exprs = _sql_parts(code, blank, s, e)
            if not exprs or not _SQL_WORD.search(literal_sql):
                continue
            if all(_expr_is_constant(code, blank, a, b, consts) for a, b in exprs):
                continue
            yield _hit(ctx, path, blank, m.start(),
                       f"`{m.group(1)}` runs SQL built by joining strings with values that are not constants. "
                       "A value with a quote in it changes the query; pass it as a `?` parameter.", blank)
            n += 1
            if n >= _MAX_HITS_PER_RULE_FILE:
                break


def _sql_from_decl(code: str, blank: str, name: str, before: int) -> Optional[Tuple[int, int]]:
    rx = re.compile(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\s*(?::[^=;\n]{0,80})?=(?![=>])")
    last = None
    for m in rx.finditer(blank, max(0, before - 5000), before):
        last = m
    if last is None:
        return None
    end = _statement_end(blank, last.end(), min(len(blank), last.end() + 4000))
    return last.end(), end


# ---------------------------------------------------------------------------- RN-012

# (module, method, library label)
_BIOMETRIC_LIBS = (
    ("expo-local-authentication", "authenticateAsync", "expo-local-authentication's `authenticateAsync()`"),
    ("react-native-biometrics", "simplePrompt", "react-native-biometrics' `simplePrompt()`"),
    ("react-native-touch-id", "authenticate", "react-native-touch-id's `authenticate()`"),
    ("react-native-fingerprint-scanner", "authenticate", "react-native-fingerprint-scanner's `authenticate()`"),
)
# Biometrics bound to a key: a Keychain/Keystore item that needs the biometric, or a signature the server checks.
_JS_BOUND = re.compile(r"\bcreateSignature\s*\(|\brequireAuthentication\s*:\s*true\b|\bACCESS_CONTROL\s*\.\s*BIOMETRY"
                       r"|\baccessControl\s*:\s*['\"]?(?:Biometry|BIOMETRY)|\bkSecAccessControl\w*Biometry"
                       r"|\bauthenticationType\s*:\s*\w*\.?\s*AUTHENTICATION_TYPE\s*\.\s*BIOMETRICS")
_NATIVE_BOUND = re.compile(r"\bCryptoObject\b|\bsetUserAuthenticationRequired\s*\(\s*true|\bSecAccessControlCreateWithFlags\b"
                           r"|\bkSecAttrAccessControl\b|\.biometryCurrentSet\b|\.biometryAny\b")


def _biometric_bound(ctx: Context) -> bool:
    def build() -> bool:
        for path in ctx.files(".js", ".jsx", ".ts", ".tsx", ".kt", ".java", ".swift", ".m", ".mm"):
            if scope_of(path) == "test" or "node_modules/" in path:
                continue
            native = not path.endswith((".js", ".jsx", ".ts", ".tsx"))
            regex = _NATIVE_BOUND if native else _JS_BOUND
            if regex.search(ctx.text(path) or "") and regex.search(ctx.code(path) or ""):
                return True
        return False
    return bool(memo(ctx, "rn:biometric-bound", build))


@detector("rn_biometric_boolean")
def rn_biometric_boolean(ctx: Context, rule: Rule) -> Iterable[Hit]:
    hits: List[Hit] = []
    for path, raw in _app_js(ctx, ("authenticateAsync", "simplePrompt", "authenticate")):
        code = ctx.code(path) or ""
        blank = None
        for module, method, label in _BIOMETRIC_LIBS:
            if module not in raw or method not in raw:
                continue
            bound = [(local, name) for local, (mod, name) in imports(code).items() if mod == module]
            if not bound:
                continue
            blank = blank if blank is not None else (ctx.code(path, keep_strings=False) or "")
            receivers = [re.escape(local) for local, name in bound if name != method]
            direct = [re.escape(local) for local, name in bound if name == method]
            alts = []
            if receivers:
                alts.append(r"(?<![\w$.])(?:" + "|".join(receivers) + r")\s*\.\s*" + method + r"\s*\(")
            if direct:
                alts.append(r"(?<![\w$.])(?:" + "|".join(direct) + r")\s*\(")
            if module == "react-native-biometrics":
                alts.append(r"\.\s*simplePrompt\s*\(")       # `new ReactNativeBiometrics().simplePrompt(…)`
            for m in re.finditer("|".join(alts), blank):
                hits.append(_hit(ctx, path, blank, m.start(),
                                 f"{label} only returns true or false and unlocks no key. A hooked app returns "
                                 "true, and since nothing needed the biometric to decrypt or sign, the check "
                                 "protects nothing.", blank))
                if len(hits) >= 200:
                    break
    if hits and not _biometric_bound(ctx):
        yield from hits


# ---------------------------------------------------------------------------- RN-020

# A bridge method: Kotlin `@ReactMethod fun name(params) {`, Java `@ReactMethod public void name(params) {`.
_REACT_METHOD = re.compile(r"@ReactMethod\b(?:\s*\([^()]{0,200}\))?\s*(?:(?:override|public|private|protected|internal"
                           r"|final|static|synchronized|suspend)\s+){0,4}(?:fun\s+|[\w<>\[\],.?]{1,80}\s+)"
                           r"([A-Za-z_]\w*)\s*\(")
# Objective-C: `RCT_EXPORT_METHOD(readFile:(NSString *)path resolve:…)`, `RCT_REMAP_METHOD(js, sel:(T)x …)`.
_RCT_METHOD = re.compile(r"\bRCT_(?:EXPORT|REMAP)_(?:BLOCKING_SYNCHRONOUS_)?METHOD(?:_WITH_RETURN_TYPE)?\s*\(")
_JVM_SHELL = re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(")
_JVM_FILE = re.compile(r"\b(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\("
                       r"|\bPaths\s*\.\s*get\s*\(|\bPath\s*\.\s*of\s*\(")
_OBJC_SHELL = re.compile(r"\bNSTask\b|\bpopen\s*\(|(?<![\w.])system\s*\(|\bposix_spawnp?\s*\(|\bexecv\w*\s*\(")
_OBJC_FILE = re.compile(r"\b(?:dataWithContentsOfFile|stringWithContentsOfFile|initWithContentsOfFile|contentsAtPath"
                        r"|createFileAtPath|removeItemAtPath|copyItemAtPath|moveItemAtPath|writeToFile|fileURLWithPath"
                        r"|inputStreamWithFileAtPath|outputStreamToFileAtPath|fileHandleForReadingAtPath"
                        r"|fileHandleForWritingAtPath|fopen)\s*[:(]")
_PATH_CHECK = re.compile(r"(?i)canonical|standardiz|resolvingSymlinks|startsWith|hasPrefix|normalize\s*\(|\"\.\.\""
                         r"|@\"\.\.\"|allow|whitelist|isValid|validat")
_NOT_JS_PARAM = re.compile(r"\b(?:Promise|Callback|RCTPromiseResolveBlock|RCTPromiseRejectBlock|RCTResponseSenderBlock)\b")


def _jvm_params(text: str) -> List[str]:
    names = []
    for part in _split_commas(text):
        part = part.strip()
        if not part or _NOT_JS_PARAM.search(part):
            continue
        if ":" in part:                               # Kotlin `path: String`
            name = part.split(":", 1)[0].split()[-1] if part.split(":", 1)[0].split() else ""
        else:                                         # Java `final String path`
            words = re.findall(r"[A-Za-z_]\w*", part)
            name = words[-1] if words else ""
        if name:
            names.append(name)
    return names


def _split_commas(text: str) -> List[str]:
    out, depth, start = [], 0, 0
    for k, c in enumerate(text):
        if c in "(<[{":
            depth += 1
        elif c in ")>]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(text[start:k])
            start = k + 1
    out.append(text[start:])
    return out


def _tainted_in_body(body: str, params: List[str]) -> Set[str]:
    """Parameters plus local variables assigned from them (`val p = path + x`, `NSString *p = [path …]`)."""
    names = set(params)
    if not names:
        return names
    decl = re.compile(r"(?:\b(?:val|var|final|String|File|NSString|NSURL|let)\b[\s*]*|\*\s*)([A-Za-z_]\w*)\s*(?::\s*[\w.?<>]+\s*)?"
                      r"=(?!=)([^;\n]{0,400})")
    for _ in range(2):
        for m in decl.finditer(body):
            if m.group(1) not in names and _mentions(m.group(2), names):
                names.add(m.group(1))
    return names


def _mentions(text: str, names: Set[str]) -> bool:
    if not names:
        return False
    for m in _IDENT.finditer(text):
        if m.group(0) in names and (m.start() == 0 or text[m.start() - 1] != "."):
            return True
    return False


def _sink_args(blank: str, m: "re.Match[str]", limit: int) -> str:
    """The argument text of the call or Objective-C message that a sink match starts."""
    j = m.end() - 1
    if blank[j] == "(":
        close = bracket_match(blank, j, "(", ")")
        return blank[j + 1:min(close, limit)]
    end = blank.find("]", j, min(limit, j + 400))      # `selector:arg]` in a message send
    return blank[j + 1:end if end > 0 else min(limit, j + 400)]


def _native_methods(ctx: Context) -> Iterator[Tuple[str, str, int, str, List[str], int, int]]:
    """(path, blank, start, method name, JS parameter names, body start, body end) of every bridge method."""
    for path in ctx.files(".java", ".kt", ".m", ".mm"):
        low = "/" + path.lower()
        if "/android/" not in low and "/ios/" not in low:
            continue
        if scope_of(path) != "main" or "node_modules/" in path:
            continue
        raw = ctx.text(path) or ""
        objc = path.endswith((".m", ".mm"))
        if ("RCT_" if objc else "@ReactMethod") not in raw:
            continue
        blank = ctx.code(path, keep_strings=False) or ""
        for m in (_RCT_METHOD if objc else _REACT_METHOD).finditer(blank):
            paren = m.end() - 1
            close = bracket_match(blank, paren, "(", ")")
            if close >= len(blank):
                continue
            sig = blank[paren + 1:close]
            if objc:
                params = [p for p in re.findall(r"\)\s*([A-Za-z_]\w*)", sig)]
                kinds = re.findall(r"\(([^()]*)\)\s*[A-Za-z_]\w*", sig)
                params = [p for p, k in zip(params, kinds) if not _NOT_JS_PARAM.search(k)]
                name = re.match(r"\s*([A-Za-z_]\w*)", sig)
                method = name.group(1) if name else "?"
            else:
                params = _jvm_params(sig)
                method = m.group(1)
            j = close + 1
            limit = min(len(blank), j + 300)
            while j < limit and blank[j] not in "{=;":
                j += 1
            if j >= limit or blank[j] != "{":
                continue
            end = bracket_match(blank, j, "{", "}")
            if end >= len(blank) or end - j > 50_000:
                continue
            yield path, blank, m.start(), method, params, j, end


@detector("rn_native_module_exec")
def rn_native_module_exec(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path, blank, _start, method, params, b0, b1 in _native_methods(ctx):
        body = blank[b0:b1]
        tainted = _tainted_in_body(body, params)
        if not tainted:
            continue
        objc = path.endswith((".m", ".mm"))
        shell_rx, file_rx = (_OBJC_SHELL, _OBJC_FILE) if objc else (_JVM_SHELL, _JVM_FILE)
        found = None
        for sm in shell_rx.finditer(body):
            if _mentions(_sink_args(body, sm, len(body)), tainted) or (objc and sm.group(0) == "NSTask"
                                                                       and _mentions(body, tainted)):
                found = ("shell", sm.start())
                break
        if found is None and not _PATH_CHECK.search(body):
            for fm in file_rx.finditer(body):
                if _mentions(_sink_args(body, fm, len(body)), tainted):
                    found = ("file", fm.start())
                    break
        if found is None:
            continue
        kind, at = found
        line = ctx.line_of(blank, b0 + at)
        if kind == "shell":
            msg = (f"The bridge method `{method}` runs a shell command built from a value JavaScript passes in. "
                   "Any script that runs in the app, such as one injected into a WebView or shipped in a bad "
                   "update, gets a command line with the app's permissions.")
        else:
            msg = (f"The bridge method `{method}` opens a file path that JavaScript passes in, with no check that "
                   "it stays inside the app's folder. A path with `../` or an absolute path reads or writes any "
                   "file the app can reach.")
        yield Hit(path, line, ctx.snippet(path, line), msg)


# ---------------------------------------------------------------------------- RN-009

_REGION = 30_000                     # how far a source's data is followed, in characters
_MAX_SOURCES = 40                    # per file
_MAX_DEPTH = 2                       # calls followed into other functions

_FN_DECL = re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^<>(){}]{0,200}>)?\s*\(")
_FN_ASSIGN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,200})?=\s*(?:useCallback\s*\(\s*)?"
                        r"(?:async\s+)?(?:function\b\s*[\w$]*\s*)?(?=\(|[A-Za-z_$][\w$]*\s*=>)")
_FN_METHOD = re.compile(r"^[ \t]*(?:(?:async|static|private|public|protected)\s+){0,3}([A-Za-z_$][\w$]*)\s*\(", re.M)
_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "with", "else", "do", "try", "await",
             "typeof", "new", "super", "constructor"}
_DEEPLINK_FN = re.compile(r"(?i)^(?:handle|on|process|parse|receive|route)_?(?:deep_?link|open_?ur[li]|incoming_?(?:ur[li]|link)"
                          r"|universal_?link|initial_?ur[li]|ur[li])s?$")
_URLISH_NAME = re.compile(r"(?i)ur[li]|link|href|query|param|path")

_LISTENER = re.compile(r"\b[\w$]*Linking\s*\.\s*add(?:Event)?Listener\s*\(")
_INITIAL = re.compile(r"\b[\w$]*Linking\s*\.\s*(?:getInitialURL|parseInitialURLAsync)\s*\(\s*\)")
_USE_URL = re.compile(r"(?<![\w$])(?:[\w$]*Linking\s*\.\s*)?use(?:Linking)?URL\s*\(\s*\)")
_SEARCH_PARAMS = re.compile(r"(?<![\w$.])use(?:Local|Global)SearchParams\s*(?:<[^<>()]{0,200}>)?\s*\(\s*\)")
_DECL_BEFORE = re.compile(r"(?:const|let|var)\s+(\{[^{}=;]{0,400}\}|\[[^\[\]=;]{0,200}\]|[A-Za-z_$][\w$]*)"
                          r"\s*(?::[^=;\n]{0,200})?=\s*(?:await\s+)?$")
_DECL = re.compile(r"\b(?:const|let|var)\s+(\{[^{}=;]{0,400}\}|\[[^\[\]=;]{0,200}\]|[A-Za-z_$][\w$]*)"
                   r"\s*(?::[^=;\n]{0,200})?=(?![=>])")
_SETTER = re.compile(r"(?<![\w$.])(set[A-Z][\w$]*)\s*\(")
_USE_STATE = re.compile(r"\[\s*([A-Za-z_$][\w$]*)\s*,\s*(set[A-Z][\w$]*)\s*\]\s*=\s*(?:React\s*\.\s*)?useState\b")
_CALL = re.compile(r"(?<![\w$.])(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(")

_SINK_OPEN = re.compile(r"\b[\w$]*Linking\s*\.\s*openURL\s*\(")
_SINK_FETCH = re.compile(r"(?<![\w$.])(?:fetch|axios)\s*\(|(?<![\w$.])axios\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(")
_SINK_NAV = re.compile(r"(?<![\w$.])navigate\s*\(|(?:[Nn]avigation|[Nn]avigator|[Rr]outer|[Nn]av|Ref|current)\s*\??\.\s*"
                       r"(?:navigate|push|replace)\s*\(")
_URL_KEY = re.compile(r"(?i)^(?:\w*(?:url|uri|link|href)|redirect\w*|next|return(?:to|url|path)\w*|callback\w*|target)$")
_VALIDATED = re.compile(r"(?i)\.\s*(?:hostname|host|origin|protocol)\b|allow_?list|whitelist|allowed|trusted|isValid\w*"
                        r"|validat\w*|sanitiz\w*|isSafe\w*|\.\s*test\s*\("
                        r"|startsWith\s*\(\s*['\"`](?:https?:|[a-z][\w+.-]*://)")


class _Fn:
    __slots__ = ("params", "start", "end")

    def __init__(self, params: List[str], start: int, end: int):
        self.params, self.start, self.end = params, start, end


def _pattern_names(text: str) -> List[str]:
    """Names a parameter or declaration binds: `url`, `{ url, query: q }`, `[a, b]`, `{ url }: Event`."""
    t = text.strip()
    if t.startswith("..."):
        t = t[3:]
    if t and t[0] in "{[":
        close = bracket_match(t, 0, t[0], "}" if t[0] == "{" else "]")
        inner = t[1:close]
        names = []
        for part in _split_commas(inner):
            part = part.split("=", 1)[0]
            if ":" in part:
                part = part.split(":", 1)[1]
            names.extend(_pattern_names(part))
        return names
    m = _IDENT.match(t)
    return [m.group(0)] if m else []


def _params(text: str) -> List[str]:
    """Each parameter's name. A destructured parameter keeps only its URL-like names (`{ url, origin }` -> url)."""
    out = []
    for part in _split_commas(text):
        names = _pattern_names(part)
        if len(names) > 1:
            names = [n for n in names if _URLISH_NAME.search(n)]
        out.append(",".join(names))
    return out


def _parse_fn(blank: str, i: int, limit: int) -> Optional[_Fn]:
    """A function expression or declaration tail starting at i: `async (a, b) => …`, `x => …`, `(a) {…}`."""
    n = min(len(blank), limit)
    while i < n and blank[i] in " \t\r\n":
        i += 1
    if blank.startswith("async", i):
        i += 5
        while i < n and blank[i] in " \t\r\n":
            i += 1
    if blank.startswith("function", i):
        p = blank.find("(", i, min(n, i + 200))
        if p < 0:
            return None
        i = p
    if i >= n:
        return None
    if blank[i] == "(":
        close = bracket_match(blank, i, "(", ")")
        if close >= n:
            return None
        params = _params(blank[i + 1:close])
        k = close + 1
    else:
        m = _IDENT.match(blank, i)
        if not m:
            return None
        params = [m.group(0)]
        k = m.end()
    stop = min(n, k + 300)
    while k < stop and blank[k] not in "{=;":
        k += 1
    if k >= stop or blank[k] == ";":
        return None
    if blank.startswith("=>", k):
        k += 2
        while k < n and blank[k] in " \t\r\n":
            k += 1
        if k < n and blank[k] == "{":
            end = bracket_match(blank, k, "{", "}")
            return _Fn(params, k, min(end, n))
        return _Fn(params, k, _statement_end(blank, k, min(n, k + _REGION)))
    if blank[k] == "{":
        end = bracket_match(blank, k, "{", "}")
        return _Fn(params, k, min(end, n))
    return None


def _function_index(blank: str) -> Dict[str, _Fn]:
    index: Dict[str, _Fn] = {}
    for rx in (_FN_DECL, _FN_ASSIGN, _FN_METHOD):
        for m in rx.finditer(blank):
            name = m.group(1)
            if name in index or name in _KEYWORDS:
                continue
            start = m.end() - 1 if rx is _FN_DECL else (m.end(1) if rx is _FN_METHOD else m.end())
            if rx is _FN_METHOD:
                start = blank.find("(", start)
            fn = _parse_fn(blank, start, start + 300 + _REGION)
            if fn is not None and fn.end - fn.start <= _REGION * 2:
                index[name] = fn
            if len(index) >= 2000:
                return index
    return index


def _block_end(blank: str, i: int) -> int:
    """The end of the block that contains i: the first `}` that closes something opened before i."""
    depth = 0
    limit = min(len(blank), i + _REGION)
    k = i
    while k < limit:
        c = blank[k]
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 0:
                return k
            depth -= 1
        k += 1
    return limit


def _fixed_prefix(code_arg: str) -> bool:
    """The argument starts with a constant scheme or path: `'tel:' + n`, `` `https://api.example.com/${id}` ``."""
    t = code_arg.strip()
    if not t or t[0] not in "'\"`":
        return False
    head = re.match(r"[`'\"]([^`'\"$]*)", t)
    return bool(head and re.match(r"(?:[a-z][\w+.-]*:|/)", head.group(1), re.I))


class _FileFlow:
    """One file's code, function index, and state setters, built once."""

    def __init__(self, ctx: Context, path: str):
        self.path = path
        self.code = ctx.code(path) or ""
        self.blank = ctx.code(path, keep_strings=False) or ""
        self._index: Optional[Dict[str, _Fn]] = None
        self.setters = {m.group(2): m.group(1) for m in _USE_STATE.finditer(self.blank)}
        self._imports: Optional[Dict[str, Tuple[str, str]]] = None

    @property
    def index(self) -> Dict[str, _Fn]:
        if self._index is None:
            self._index = _function_index(self.blank)
        return self._index

    @property
    def imports(self) -> Dict[str, Tuple[str, str]]:
        if self._imports is None:
            self._imports = imports(self.code)
        return self._imports


class _DeepLinks:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.flows: Dict[str, _FileFlow] = {}
        self.files = set(js_files(ctx))
        self.hits: Dict[Tuple[str, int], Hit] = {}

    def flow(self, path: str) -> _FileFlow:
        f = self.flows.get(path)
        if f is None:
            f = self.flows[path] = _FileFlow(self.ctx, path)
        return f

    def resolve(self, frm: str, module: str) -> Optional[str]:
        if not module.startswith("."):
            return None
        base = os.path.normpath(os.path.join(os.path.dirname(frm), module)).replace(os.sep, "/")
        for ext in ("", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"):
            if base + ext in self.files:
                return base + ext
        return None

    # -- sources

    def seeds(self, f: _FileFlow) -> Iterator[Tuple[int, int, Set[str], str, int]]:
        """(region start, region end, tainted names, source label, source offset)."""
        blank, code = f.blank, f.code
        count = 0
        for m in _LISTENER.finditer(blank):
            spans = call_args(blank, m.end() - 1)
            if len(spans) < 2 or code[spans[0][0]:spans[0][1]].strip().strip("'\"`") != "url":
                continue
            fn = self.handler(f, spans[1])
            if fn is not None and fn.params:
                count += 1
                yield fn.start, fn.end, set(fn.params[0].split(",")), "`Linking.addEventListener('url')`", m.start()
        for rx, label in ((_INITIAL, "`Linking.getInitialURL()`"), (_USE_URL, "`Linking.useURL()`"),
                          (_SEARCH_PARAMS, "expo-router search parameters")):
            if rx is _SEARCH_PARAMS and not any(mod == "expo-router" for mod, _ in f.imports.values()):
                continue
            for m in rx.finditer(blank):
                if count >= _MAX_SOURCES:
                    return
                k = m.end()
                while k < len(blank) and blank[k] in " \t\r\n":
                    k += 1
                if blank.startswith(".then", k):
                    p = blank.find("(", k)
                    spans = call_args(blank, p) if p >= 0 else []
                    fn = self.handler(f, spans[0]) if spans else None
                    if fn is not None and fn.params:
                        count += 1
                        yield fn.start, fn.end, set(fn.params[0].split(",")), label, m.start()
                    continue
                d = _DECL_BEFORE.search(blank, max(0, m.start() - 600), m.start())
                if d is None:
                    continue
                names = set(_pattern_names(d.group(1)))
                if names:
                    count += 1
                    yield m.end(), _block_end(blank, m.end()), names, label, m.start()
        for name, fn in f.index.items():
            if count >= _MAX_SOURCES:
                return
            if _DEEPLINK_FN.search(name) and fn.params and fn.params[0]:
                count += 1
                yield fn.start, fn.end, set(fn.params[0].split(",")), f"the deep-link handler `{name}`", fn.start

    def handler(self, f: _FileFlow, span: Tuple[int, int]) -> Optional[_Fn]:
        text = f.blank[span[0]:span[1]].strip()
        ref = re.fullmatch(r"(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)(?:\s*\.\s*bind\s*\(\s*this\s*\))?", text)
        if ref:
            return f.index.get(ref.group(1))
        return _parse_fn(f.blank, span[0], span[1])

    # -- flow

    def run(self) -> Iterable[Hit]:
        for path in sorted(self.files):
            if scope_of(path) in _SKIP_SCOPES or _VENDORED.search(path):
                continue
            raw = self.ctx.text(path) or ""
            if "Linking" not in raw and "SearchParams" not in raw and not re.search(r"(?i)deep_?link|openurl|incoming", raw):
                continue
            if _minified(raw):
                continue
            f = self.flow(path)
            state: Set[str] = set()
            for s, e, names, label, src in self.seeds(f):
                line = self.ctx.line_of(f.blank, src)
                self.follow(f, s, e, names, f"Data from {label} (line {line})", 0, state)
            if state:
                self.sinks(f, 0, len(f.blank), state, "Deep-link data kept in component state")
        return list(self.hits.values())

    def follow(self, f: _FileFlow, s: int, e: int, names: Set[str], label: str, depth: int, state: Set[str]) -> None:
        names = {n for n in names if n}
        if not names or _VALIDATED.search(f.code[s:e]):
            return
        blank = f.blank
        for _ in range(2):
            for m in _DECL.finditer(blank, s, e):
                rhs_end = _statement_end(blank, m.end(), min(e, m.end() + 4000))
                if _mentions(blank[m.end():rhs_end], names):
                    names.update(_pattern_names(m.group(1)))
                if len(names) > 60:
                    break
        for m in _SETTER.finditer(blank, s, e):
            var = f.setters.get(m.group(1))
            if var and _mentions(blank[m.end():_statement_end(blank, m.end(), min(e, m.end() + 2000))], names):
                state.add(var)
        self.sinks(f, s, e, names, label)
        if depth >= _MAX_DEPTH:
            return
        for m in _CALL.finditer(blank, s, e):
            name = m.group(1)
            if name in _KEYWORDS:
                continue
            target_flow, fn = f, f.index.get(name)
            if fn is None:
                imp = f.imports.get(name)
                other = self.resolve(f.path, imp[0]) if imp else None
                if other is None:
                    continue
                target_flow = self.flow(other)
                fn = target_flow.index.get(imp[1] if imp[1] not in ("default", "*") else name)
                if fn is None:
                    continue
            if target_flow is f and fn.start <= m.start() < fn.end and s >= fn.start:
                continue                                  # a recursive call
            for k, (a, b) in enumerate(call_args(blank, m.end() - 1)):
                if k < len(fn.params) and _mentions(blank[a:b], names):
                    self.follow(target_flow, fn.start, fn.end, set(fn.params[k].split(",")), label, depth + 1,
                                state if target_flow is f else set())

    def sinks(self, f: _FileFlow, s: int, e: int, names: Set[str], label: str) -> None:
        blank, code = f.blank, f.code
        for rx, kind in ((_SINK_OPEN, "open"), (_SINK_FETCH, "fetch")):
            for m in rx.finditer(blank, s, e):
                arg = _first_arg(blank, m.end() - 1)
                if arg and _mentions(blank[arg[0]:arg[1]], names) and not _fixed_prefix(code[arg[0]:arg[1]]):
                    self.add(f, m.start(), kind, label)
        for m in _SINK_NAV.finditer(blank, s, e):
            spans = call_args(blank, m.end() - 1)
            if spans and _nav_url_param(blank, spans[0][0], spans[-1][1], names):
                self.add(f, m.start(), "navigate", label)
        if "WebView" in blank[s:e] or (s == 0 and "WebView" in blank):
            for el in jsx_elements(code, blank, ["WebView"]):
                if not s <= el.start < e:
                    continue
                prop = el.props.get("source")
                if prop is None or prop.kind != "expr":
                    continue
                uri = re.search(r"\buri\s*:", blank[prop.start:prop.end])
                vs = prop.start + uri.end() if uri else prop.start
                ve = _statement_end(blank, vs, prop.end) if uri else prop.end
                if _mentions(blank[vs:ve], names) and not _fixed_prefix(code[vs:ve]):
                    self.add(f, el.start, "webview", label)

    def add(self, f: _FileFlow, at: int, kind: str, label: str) -> None:
        line = self.ctx.line_of(f.blank, at)
        key = (f.path, line)
        if key in self.hits:
            return
        what = {
            "open": "`Linking.openURL` opens it. A crafted link can launch another app's screen (on Android an "
                    "`intent://` URL starts any exported activity) or send the user to a phishing page.",
            "fetch": "the app sends a request to it. A crafted link points the request, and any token the app adds, "
                     "at a server the attacker runs.",
            "navigate": "it is passed on as a URL parameter to another screen, which can load it or open it.",
            "webview": "a WebView loads it. A crafted link opens the attacker's page inside the app, with the "
                       "WebView's bridge and cookies.",
        }[kind]
        self.hits[key] = Hit(f.path, line, self.ctx.snippet(f.path, line),
                             f"{label} reaches this line with no allowlist check, and {what}",
                             scope="debug" if rn.in_dev(f.code, f.blank, at) else "")


def _nav_url_param(blank: str, s: int, e: int, names: Set[str]) -> bool:
    """A navigation call passes a tainted value under a URL-like key: `navigate('Web', { url })`."""
    text = blank[s:e]
    for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*:\s*", text):
        if _URL_KEY.match(m.group(1)):
            end = _statement_end(text, m.end(), len(text))
            if _mentions(text[m.end():end], names):
                return True
    for m in re.finditer(r"[{,]\s*([A-Za-z_$][\w$]*)\s*(?=[,}])", text):
        if _URL_KEY.match(m.group(1)) and m.group(1) in names:
            return True
    return False


@detector("rn_deeplink_sink")
def rn_deeplink_sink(ctx: Context, rule: Rule) -> Iterable[Hit]:
    yield from _DeepLinks(ctx).run()
