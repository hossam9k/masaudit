# SPDX-License-Identifier: Apache-2.0
"""React Native detectors: storage, secrets, and the clipboard. Shared helpers are in reactnative.py.

RN-001: a token or password written to AsyncStorage, to an MMKV instance created without `encryptionKey`,
or to a redux-persist store that saves an auth slice in plain storage (book §6.4).
RN-002: a secret that build-time configuration copies into the app: react-native-config, `EXPO_PUBLIC_*`,
react-native-dotenv's `@env`, app.json `extra` and plugin options, eas.json `env`, and `.env` files that
react-native-config or Expo bundle (book §15.2).

Every scan here is bounded: key and value texts are cut, look-backs have fixed windows, and each file is
read once per rule.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from masaudit import safety
from masaudit.detect import scope_of
from masaudit.detectors.reactnative import as_list, call_args, imports, js_files, memo, package_deps
from masaudit.engine import Context, Hit, detector
from masaudit.model import Rule
from masaudit.textscan import bracket_match, text_memo

# ---------------------------------------------------------------------------- names

_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def words(name: str) -> List[str]:
    """`accessToken`, `ACCESS_TOKEN`, `@auth-token` -> ['access', 'token']."""
    return [w.lower() for w in _WORD.findall(name[:200])]


def _mask_in(snippet: str, value: str) -> str:
    if value and value in snippet:
        return snippet.replace(value, (value[:4] if len(value) > 8 else "") + "…[masked]")
    return snippet


# ---------------------------------------------------------------------------- RN-001: what a stored key holds

# A word that makes a storage key a credential wherever it appears.
_CREDENTIAL_WORDS = {"password", "passwords", "passwd", "passphrase", "passcode", "secret", "secrets", "jwt",
                     "credential", "credentials", "mnemonic"}
# `token` and `session` are credentials only as the key's last word, alone or after one of these: in a wallet,
# `tokenList` or `selectedToken` is an asset, and `pushToken` is a push registration ID.
_AUTH_QUALIFIERS = {"access", "refresh", "auth", "authentication", "authorization", "id", "session", "bearer",
                    "user", "api", "jwt", "csrf", "xsrf", "login", "oauth", "sso", "identity", "app", "client",
                    "security", "secret", "private", "personal", "master", "my", "current", "saved", "stored"}
_PAIRS = {("api", "key"), ("private", "key"), ("secret", "key"), ("seed", "phrase"), ("session", "id"),
          ("auth", "key"), ("access", "key")}
# Words that make a key about a credential without holding one: an expiry, a flag, a counter, a push ID.
_NOT_A_CREDENTIAL = {
    "push", "fcm", "apns", "device", "notification", "notifications", "expire", "expires", "expiry", "expiration",
    "expired", "exp", "ttl", "time", "timestamp", "date", "at", "count", "attempt", "attempts", "seen", "tip",
    "hint", "shown", "show", "enabled", "disabled", "enable", "flag", "has", "is", "should", "did", "was",
    "prompt", "reminder", "policy", "length", "type", "version", "migrated", "migration", "status", "changed",
    "reset", "strength", "hash", "hashed", "last", "visible", "visibility", "required", "rule", "rules", "error",
    "label", "placeholder", "field", "hidden", "pinned", "list", "balance", "balances", "price", "prices",
    "address", "symbol", "metadata", "icon", "decimals", "contract", "chain", "network", "manager", "salt",
    "iv", "encrypted", "cipher", "sealed", "nonce", "lock", "locked", "biometric", "biometrics", "fingerprint",
}
# A key named by an identifier: `TOKEN_STORAGE_KEY` names the key, so its last words describe the name.
_NAME_SUFFIXES = {"key", "keys", "storage", "item", "name", "prefix", "const", "constant"}


def credential_key(name: str, from_identifier: bool = False) -> bool:
    """Does a storage key (or the identifier that names it) hold a token, password, or secret?"""
    ws = words(name)
    if from_identifier:
        while len(ws) > 1 and ws[-1] in _NAME_SUFFIXES:
            ws = ws[:-1]
    if not ws or set(ws) & _NOT_A_CREDENTIAL:
        return False
    if set(ws) & _CREDENTIAL_WORDS:
        return True
    if any((a, b) in _PAIRS for a, b in zip(ws, ws[1:])):
        return True
    last = ws[-1]
    if last in ("token", "session", "cookie"):
        return len(ws) == 1 or ws[-2] in _AUTH_QUALIFIERS
    return False


_ENCRYPTED_VALUE = re.compile(r"(?i)encrypt|cipher|seal|\bhash|sha\d|\bhmac|keychain|securestore")
_VALUE_CHAIN = re.compile(r"\s*(?:await\s+)?(?:JSON\s*\.\s*stringify\s*\(\s*)?((?:this\s*\.\s*)?[A-Za-z_$][\w$]*"
                          r"(?:\s*\??\.\s*[A-Za-z_$][\w$]*){0,6})\s*\)?\s*$")


def _value_name(value: str) -> str:
    """The last name of a value that is a plain variable or property chain: `res.data.accessToken` ->
    `accessToken`. '' for anything else (a call, a literal, an expression)."""
    m = _VALUE_CHAIN.fullmatch(value[:300])
    if not m:
        return ""
    return re.split(r"\s*\??\.\s*", m.group(1))[-1]


_STRING_LIT = re.compile(r"\s*(['\"`])([^'\"`\n]{0,200})\1\s*")
_TEMPLATE = re.compile(r"\s*`([^`\n]{0,200})`\s*")
_IDENT = re.compile(r"\s*((?:this\s*\.\s*)?[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*){0,4})\s*")


_CONST = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?[:=]\s*(['\"`])([^'\"`\n]{0,200})\2")


def _const_value(code: str, name: str) -> Optional[str]:
    """`const NAME = 'x'` or `NAME: 'x'` (an enum or object of keys) in the same file. The file's constants
    are indexed once, so a file with many writes isn't searched once per write."""
    def build() -> Dict[str, str]:
        table: Dict[str, str] = {}
        for m in _CONST.finditer(code):
            table.setdefault(m.group(1), m.group(3))
        return table
    return text_memo(code, ("rn001:consts",), build).get(name)


def key_text(code: str, expr: str) -> Tuple[str, bool]:
    """(text, from_identifier) for a storage key expression: a literal, a constant resolved in the file,
    or the constant's own name. ('', False) when the key is computed."""
    s = _STRING_LIT.fullmatch(expr)
    if s:
        return s.group(2), False
    t = _TEMPLATE.fullmatch(expr)
    if t:
        return re.sub(r"\$\{[^}]{0,100}\}", " ", t.group(1)), False
    i = _IDENT.fullmatch(expr)
    if i:
        name = re.split(r"\s*\??\.\s*", i.group(1))[-1]
        value = _const_value(code, name)
        if value is not None:
            return value, False
        return name, True
    return "", False


def _stored_secret(code: str, blank: str, key_span: Tuple[int, int],
                   value_span: Optional[Tuple[int, int]]) -> str:
    """What makes this write a credential (the key, or the value's name), or ''."""
    key, from_ident = key_text(code, code[key_span[0]:key_span[1]])
    if not key:
        return ""
    key_words = set(words(key))
    if key_words & _NOT_A_CREDENTIAL:
        return ""
    value = code[value_span[0]:value_span[1]] if value_span else ""
    if _ENCRYPTED_VALUE.search(value[:300]):
        return ""
    if credential_key(key, from_ident):
        return key
    name = _value_name(blank[value_span[0]:value_span[1]]) if value_span else ""
    if name and credential_key(name):
        return name
    return ""


# ---------------------------------------------------------------------------- RN-001 detector

ASYNC_STORAGE = ("@react-native-async-storage/async-storage", "@react-native-community/async-storage")
_WRITE = re.compile(r"\.\s*(setItem|mergeItem|multiSet|multiMerge)\s*\(")
_PAIR_KEY = re.compile(r"\[\s*((?:['\"`][^'\"`\n]{0,200}['\"`])|[A-Za-z_$][\w$.]{0,200})\s*,")


def _async_names(code: str) -> Set[str]:
    names = set()
    for local, (module, imported) in imports(code).items():
        if module in ASYNC_STORAGE and imported in ("default", "*", "AsyncStorage"):
            names.add(local)
        elif module == "react-native" and imported == "AsyncStorage":
            names.add(local)
    return names


def _receiver(blank: str, dot: int) -> str:
    """The name just before `.setItem(`: `AsyncStorage`, `this.storage` -> `storage`."""
    j = dot
    while j > 0 and blank[j - 1] in " \t\n":
        j -= 1
    k = j
    while k > 0 and k > j - 100 and (blank[k - 1].isalnum() or blank[k - 1] in "_$"):
        k -= 1
    return blank[k:j]


def _writes(code: str, blank: str, receivers: Set[str]) -> Iterator[Tuple[int, str, str]]:
    """(offset, method, what) for each write of a credential through one of these receivers."""
    for m in _WRITE.finditer(blank):
        if _receiver(blank, m.start()) not in receivers:
            continue
        args = call_args(blank, m.end() - 1)
        if not args:
            continue
        method = m.group(1)
        if method in ("multiSet", "multiMerge"):
            a, b = args[0]
            for p in _PAIR_KEY.finditer(code, a, b):
                what = _stored_secret(code, blank, (p.start(1), p.end(1)), None)
                if what:
                    yield m.start(), method, what
                    break
        else:
            what = _stored_secret(code, blank, args[0], args[1] if len(args) > 1 else None)
            if what:
                yield m.start(), method, what


# MMKV: `new MMKV(...)` (v2-v3) and `createMMKV(...)` (v4). The instance is unencrypted when the call has no
# argument, or an object literal without `encryptionKey`; anything else (a variable, a call) is left alone.
_ASSIGNED = re.compile(r"(?:(?<![\w$.])(?:const|let|var)\s+|\bthis\s*\.\s*|(?<![\w$.]))([A-Za-z_$#][\w$]*)\s*"
                       r"(?::\s*[\w$<>.| ]{1,60})?=\s*$")


def _plain_mmkv(code: str, blank: str, paren: int) -> bool:
    args = call_args(blank, paren)
    if not args:
        return True
    if len(args) > 1:
        return False
    a, b = args[0]
    text = blank[a:b].strip()
    if not (text.startswith("{") and text.endswith("}")):
        return False
    inner = text[1:-1]
    if "..." in inner:
        return False
    return not re.search(r"(?<![\w$])encryptionKey\b", inner)


def _mmkv_instances(code: str, blank: str) -> Iterator[Tuple[str, int, bool]]:
    """(variable, offset, exported) for each unencrypted MMKV instance assigned to a variable or field."""
    names = imports(code)
    ctors = [local for local, (module, imported) in names.items()
             if module == "react-native-mmkv" and imported in ("MMKV", "createMMKV")]
    if not ctors:
        return
    alts = [r"\bnew\s+" + re.escape(c) for c in ctors if names[c][1] == "MMKV"]
    alts += [r"(?<![\w$.])" + re.escape(c) for c in ctors if names[c][1] == "createMMKV"]
    rx = re.compile(r"(?:" + "|".join(alts) + r")\s*\(")
    for m in rx.finditer(blank):
        if not _plain_mmkv(code, blank, m.end() - 1):
            continue
        target = _ASSIGNED.search(blank[max(0, m.start() - 160):m.start()])
        if not target:
            continue
        # The start of the line, looked for only in the 200 characters before: a minified line with many
        # instances would otherwise be scanned again for each one.
        lo = max(0, m.start() - 200)
        line_start = blank.rfind("\n", lo, m.start()) + 1
        exported = (line_start > 0 or lo == 0) and bool(re.match(r"\s*export\b", blank[line_start:m.start()]))
        yield target.group(1), m.start(), exported


def _module_key(path: str) -> str:
    base = re.sub(r"\.(?:js|jsx|ts|tsx|mjs|cjs)$", "", path)
    return base[:-6] if base.endswith("/index") else base


def _exported_mmkv(ctx: Context) -> Dict[str, Set[str]]:
    """module path (no extension) -> names of unencrypted MMKV instances it exports."""
    def build() -> Dict[str, Set[str]]:
        out: Dict[str, Set[str]] = {}
        for path in js_files(ctx):
            raw = ctx.text(path) or ""
            if "react-native-mmkv" not in raw or scope_of(path) == "test":
                continue
            code = ctx.code(path) or ""
            blank = ctx.code(path, False) or ""
            for name, _off, exported in _mmkv_instances(code, blank):
                if exported:
                    out.setdefault(_module_key(path), set()).add(name)
        return out
    return memo(ctx, "rn001:mmkv-exports", build)


def _imported_mmkv(path: str, code: str, exported: Dict[str, Set[str]]) -> Set[str]:
    if not exported:
        return set()
    out = set()
    here = path.rsplit("/", 1)[0] if "/" in path else ""
    for local, (module, imported) in imports(code).items():
        if not module.startswith("."):
            continue
        target = _module_key(os.path.normpath(os.path.join(here, module)).replace(os.sep, "/"))
        if imported in exported.get(target, ()):
            out.add(local)
    return out


# redux-persist: persistReducer(config, reducer) whose config saves an auth slice to plain storage.
_PERSIST_SLICE_WORDS = {"auth", "authentication", "session", "token", "credential", "credentials", "password",
                        "secret", "jwt", "login"}
_PLAIN_PERSIST_MODULES = set(ASYNC_STORAGE) | {"redux-persist/lib/storage", "redux-persist-filesystem-storage",
                                               "redux-persist/es/storage"}
_SECURE_STORAGE_NAME = re.compile(r"(?i)secure|encrypt|keychain|sensitive|vault")


def _object_at(blank: str, i: int) -> Optional[Tuple[int, int]]:
    """Span of the object literal whose `{` is at i (after spaces)."""
    while i < len(blank) and blank[i] in " \t\n":
        i += 1
    if i >= len(blank) or blank[i] != "{":
        return None
    close = bracket_match(blank, i, "{", "}")
    return (i, close + 1) if close < len(blank) else None


def _persist_config(code: str, blank: str, expr: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    a, b = expr
    obj = _object_at(blank, a)
    if obj:
        return obj
    name = blank[a:b].strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return None
    def build() -> Dict[str, int]:
        decls: Dict[str, int] = {}
        for d in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=\n]{1,80})?=\s*", blank):
            decls.setdefault(d.group(1), d.end())
        return decls
    at = text_memo(blank, ("rn001:decls",), build).get(name)
    return _object_at(blank, at) if at is not None else None


def _prop(code: str, blank: str, span: Tuple[int, int], name: str) -> Optional[Tuple[int, int]]:
    """Value span of a top-level property in an object literal span, or (k, k) for a shorthand property."""
    a, b = span
    depth = 0
    i = a + 1
    rx = re.compile(r"(?<![\w$])" + re.escape(name) + r"\s*(:|,|\})")
    while i < b - 1:
        c = blank[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == name[0]:
            m = rx.match(blank, i)
            if m and (i == 0 or not (blank[i - 1].isalnum() or blank[i - 1] in "_$")):
                if m.group(1) != ":":
                    return (i, i + len(name))
                start = m.end()
                j, d = start, 0
                while j < b - 1:
                    cj = blank[j]
                    if cj in "([{":
                        d += 1
                    elif cj in ")]}":
                        if d == 0:
                            break
                        d -= 1
                    elif cj == "," and d == 0:
                        break
                    j += 1
                return (start, j)
        i += 1
    return None


def _redux_persist_hits(code: str, blank: str) -> Iterator[Tuple[int, str]]:
    names = imports(code)
    persist = [local for local, (module, imported) in names.items()
               if module.startswith("redux-persist") and imported == "persistReducer"]
    if not persist:
        return
    rx = re.compile(r"(?<![\w$.])(?:" + "|".join(re.escape(p) for p in persist) + r")\s*\(")
    for m in rx.finditer(blank):
        args = call_args(blank, m.end() - 1)
        if not args:
            continue
        cfg = _persist_config(code, blank, args[0])
        if not cfg:
            continue
        if _prop(code, blank, cfg, "transforms"):
            continue                        # a transform may encrypt; we can't tell
        storage = _prop(code, blank, cfg, "storage")
        if not storage:
            continue
        storage_text = code[storage[0]:storage[1]].strip()
        if _SECURE_STORAGE_NAME.search(storage_text):
            continue
        ident = re.fullmatch(r"[A-Za-z_$][\w$]*", storage_text)
        if not ident or names.get(storage_text, ("", ""))[0] not in _PLAIN_PERSIST_MODULES:
            continue
        what = ""
        white = _prop(code, blank, cfg, "whitelist") or _prop(code, blank, cfg, "allowlist")
        if white:
            for item in re.findall(r"['\"`]([^'\"`\n]{1,100})['\"`]", code[white[0]:white[1]][:2000]):
                if set(words(item)) & _PERSIST_SLICE_WORDS and not set(words(item)) & _NOT_A_CREDENTIAL:
                    what = item
                    break
        else:
            key = _prop(code, blank, cfg, "key")
            if key:
                k = _STRING_LIT.fullmatch(code[key[0]:key[1]])
                if k and set(words(k.group(2))) & _PERSIST_SLICE_WORDS:
                    what = k.group(2)
        if what:
            yield m.start(), what


def _token_writes(ctx: Context, path: str, raw: str, code: str, blank: str) -> Iterator[Tuple[int, str]]:
    """(offset, message) for each credential this file writes to plain storage."""
    if "async-storage" in raw or "AsyncStorage" in raw:
        for off, method, what in _writes(code, blank, _async_names(code)):
            yield off, (f"`{what}` looks like a token or password and is written to AsyncStorage with `{method}`, "
                        "which saves it unencrypted on the device.")
        for local, (module, imported) in imports(code).items():
            if module not in ASYNC_STORAGE or imported != "useAsyncStorage" or \
                    not re.search(r"\b(?:setItem|mergeItem)\b", blank):
                continue
            for u in re.finditer(r"(?<![\w$.])" + re.escape(local) + r"\s*\(", blank):
                args = call_args(blank, u.end() - 1)
                key, from_ident = key_text(code, code[args[0][0]:args[0][1]]) if args else ("", False)
                if key and credential_key(key, from_ident):
                    yield u.start(), (f"`{key}` looks like a token or password and is saved through "
                                      "useAsyncStorage, which stores it unencrypted.")
    if "mmkv" in raw.lower():
        receivers = {name for name, _o, _e in _mmkv_instances(code, blank)}
        receivers |= _imported_mmkv(path, code, _exported_mmkv(ctx))
        if receivers:
            for m in re.finditer(r"\.\s*set\s*\(", blank):
                if _receiver(blank, m.start()) not in receivers:
                    continue
                args = call_args(blank, m.end() - 1)
                what = _stored_secret(code, blank, args[0], args[1]) if len(args) >= 2 else ""
                if what:
                    yield m.start(), (f"`{what}` looks like a token or password and is written to an MMKV instance "
                                      "created without `encryptionKey`, so it is saved unencrypted.")
    if "redux-persist" in raw:
        for off, what in _redux_persist_hits(code, blank):
            yield off, (f"redux-persist saves the `{what}` state to plain storage with no encrypting transform, "
                        "so any token it holds is written unencrypted.")


@detector("rn_plain_token_storage")
def plain_token_storage(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in js_files(ctx):
        if scope_of(path) == "test":
            continue
        raw = ctx.text(path) or ""
        if not ("async-storage" in raw or "AsyncStorage" in raw or "mmkv" in raw.lower() or "redux-persist" in raw):
            continue
        code = ctx.code(path) or ""
        blank = ctx.code(path, False) or ""
        seen: Set[int] = set()
        for offset, message in _token_writes(ctx, path, raw, code, blank):
            line = ctx.line_of(code, offset)
            if line not in seen:
                seen.add(line)
                yield Hit(path, line, ctx.snippet(path, line), message)


# ---------------------------------------------------------------------------- RN-002: names and values

# Names that say the value is a secret wherever it appears.
_SECRET_NAME_WORDS = {"secret", "secrets", "password", "passwd", "passphrase", "pwd"}
_SECRET_NAME_PAIRS = {("private", "key"), ("service", "role"), ("service", "account"), ("master", "key"),
                      ("signing", "key"), ("access", "secret")}
# Names that mark a public identifier or a setting, not a secret.
_PUBLIC_NAME_WORDS = {"public", "publishable", "pub", "anon", "anonymous", "dsn", "url", "uri", "host", "hostname",
                      "endpoint", "domain", "env", "environment", "name", "version", "min", "max", "length",
                      "policy", "regex", "pattern", "reset", "field", "label", "hint", "placeholder", "enabled",
                      "required", "path", "file", "dir", "header", "id", "site", "measurement", "example", "sample"}
# Names that may hold a secret: report them only when the value has a known secret format.
_MAYBE_SECRET_WORDS = {"token", "key", "auth", "apikey", "credential", "credentials"}

# Known formats of restricted or server-only credentials (book §15.2). Public ones are left out on purpose:
# Google `AIza…` keys (Firebase and Maps keys ship by design, XPL-002), Stripe `pk_…`, Sentry DSNs, Mapbox `pk.…`.
KNOWN_SECRET = re.compile(
    r"^(?:[sr]k_live_[0-9A-Za-z]{16,}|sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_\-]{20,}"
    r"|sntry[su]_[A-Za-z0-9+/=_\-]{20,}|npm_[A-Za-z0-9]{36}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"
    r"|shp(?:at|ss|ca)_[a-fA-F0-9]{32}|-----BEGIN [A-Z ]*PRIVATE KEY-----.*)$"
)
_PLACEHOLDER = re.compile(r"(?i)^(?:your|my|fake|dummy|test|mock|sample|example|changeme|change_me|replace|todo|"
                          r"insert|placeholder|xxx|none|null|undefined|redacted|secret$|password$|<)|example|xxxx")


def looks_secret(value: str) -> bool:
    """A value that could be a real credential: not empty, a placeholder, a word, a number, or a URL."""
    v = value.strip().strip("'\"")
    if KNOWN_SECRET.match(v):
        return True
    if len(v) < 8 or len(v) > 4000 or any(s in v for s in ("${", "$(", "{{", "%(", "<", " ")):
        return False
    if _PLACEHOLDER.search(v) or re.search(r"(.)\1{7,}", v):
        return False
    if re.fullmatch(r"[A-Za-z_.\-]+", v) or re.fullmatch(r"[\d.]+", v):
        return False                    # a word, a key name, or a number
    if "://" in v or v.startswith(("/", "./", "~")):
        return False
    return True


def secret_name(name: str) -> bool:
    ws = words(name)
    if ws[:2] == ["expo", "public"]:
        ws = ws[2:]
    s = set(ws)
    if not ws or s & _PUBLIC_NAME_WORDS:
        return False
    return bool(s & _SECRET_NAME_WORDS) or any((a, b) in _SECRET_NAME_PAIRS for a, b in zip(ws, ws[1:]))


def secret_entry(name: str, value: str) -> bool:
    """A name-value pair from configuration that holds a real secret."""
    v = value.strip().strip("'\"")
    if KNOWN_SECRET.match(v):
        return True
    return secret_name(name) and looks_secret(v)


# ---------------------------------------------------------------------------- RN-002 detector

_RN_CONFIG = ("react-native-config",)
_DOTENV = ("@env", "react-native-dotenv")
_EXPO_PUBLIC = re.compile(r"\bprocess\s*\.\s*env\s*(?:\.\s*(EXPO_PUBLIC_\w+)|\[\s*['\"](EXPO_PUBLIC_\w+)['\"]\s*\])")
_APP_CONFIG = re.compile(r"(?:^|/)app\.config\.(?:js|ts|mjs|cjs)$")
_ENV_FILE = re.compile(r"^\.env(?:\.[\w.\-]{1,60})?$")
_ENV_NOT_SHIPPED = re.compile(r"(?i)example|sample|template|dist|defaults?\b|schema")
_ENV_LINE = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,120})[ \t]*=[ \t]*(.*)$", re.MULTILINE)


def _env_scope(name: str) -> str:
    low = name.lower()
    if re.search(r"\b(?:test|e2e|ci)\b", low.replace(".", " ")):
        return "test"
    if re.search(r"\b(?:dev|development|local|debug)\b", low.replace(".", " ")):
        return "debug"
    return ""


def _env_value(raw: str) -> str:
    v = raw.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    return re.split(r"[ \t]+#", v, maxsplit=1)[0].strip()


def package_dirs(ctx: Context) -> List[str]:
    """Folders of the project's package.json files (outside tests), plus the scan root."""
    def build() -> List[str]:
        dirs = {""}
        for p in ctx.files(name="package.json"):
            if scope_of(p) != "test":
                dirs.add(p.rsplit("/", 1)[0] if "/" in p else "")
        return sorted(dirs)
    return memo(ctx, "rn:package-dirs", build)


def dotfiles(ctx: Context, dir_: str, pattern: "re.Pattern[str]") -> List[str]:
    """Dotfiles (`.env`, `.env.production`, `.npmrc`) directly in one project folder, from the walked files."""
    def build() -> Dict[str, List[str]]:
        by_dir: Dict[str, List[str]] = {}
        for f in ctx.project.files:
            folder, _, base = f.rpartition("/")
            if base.startswith("."):
                by_dir.setdefault(folder, []).append(f)
        return by_dir
    in_dir = memo(ctx, "rn:dotfiles", build).get(dir_, [])
    return sorted(f for f in in_dir if pattern.match(f.rpartition("/")[2]))


_MAX_JSON_HITS = 50


def _line_of_key(ctx: Context, text: str, key: str, value: str) -> int:
    m = re.search(r"[\"']?" + re.escape(key) + r"[\"']?\s*[:=]\s*[\"']?" + re.escape(value[:200]), text)
    if not m:
        m = re.search(r"[\"']" + re.escape(key) + r"[\"']", text)
    return ctx.line_of(text, m.start()) if m else 1


def _json_pairs(node, depth: int = 0) -> Iterator[Tuple[str, str]]:
    """(key, string value) pairs in a JSON tree, a few levels deep."""
    if depth > 6:
        return
    if isinstance(node, dict):
        for k, v in list(node.items())[:500]:
            if isinstance(v, str) and isinstance(k, str):
                yield k, v
            elif isinstance(v, (dict, list)):
                yield from _json_pairs(v, depth + 1)
    elif isinstance(node, list):
        for item in node[:500]:
            yield from _json_pairs(item, depth + 1)


def _load_json(text: Optional[str]):
    if not text or len(text) > safety.MAX_FILE_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _code_hits(ctx: Context, path: str) -> Iterator[Hit]:
    raw = ctx.text(path) or ""
    if not ("react-native-config" in raw or "EXPO_PUBLIC_" in raw or "@env" in raw or "react-native-dotenv" in raw):
        return
    code = ctx.code(path) or ""
    blank = ctx.code(path, False) or ""
    seen: Set[int] = set()

    def hit(offset: int, message: str) -> Iterator[Hit]:
        line = ctx.line_of(code, offset)
        if line not in seen:
            seen.add(line)
            yield Hit(path, line, ctx.snippet(path, line), message)

    names = imports(code)
    config = [local for local, (module, imported) in names.items()
              if module in _RN_CONFIG and imported in ("default", "Config", "*")]
    if config:
        alt = "|".join(re.escape(c) for c in config)
        member = re.compile(r"(?<![\w$.])(?:" + alt + r")\s*(?:\?\.\s*|\.\s*)(?:([A-Za-z_$][\w$]*)|\[\s*['\"]"
                            r"([A-Za-z_$][\w$]*)['\"]\s*\])|(?<![\w$.])(?:" + alt + r")\s*\[\s*['\"]([A-Za-z_$][\w$]*)"
                            r"['\"]\s*\]")
        for m in member.finditer(code):
            name = m.group(1) or m.group(2) or m.group(3)
            if blank[m.start()] == code[m.start()] and secret_name(name):
                yield from hit(m.start(), f"`{name}` comes from react-native-config, which copies the .env file "
                                          "into the app at build time, so this secret ships inside the app.")
        for m in re.finditer(r"\{([^{}]{1,600})\}\s*=\s*(?:" + alt + r")\b", blank):
            for part in m.group(1).split(","):
                name = part.split(":")[0].strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", name) and secret_name(name):
                    yield from hit(m.start(), f"`{name}` comes from react-native-config, which copies the .env "
                                              "file into the app at build time, so this secret ships inside the app.")
    module_at: Dict[str, int] = {}

    def import_offset(module: str) -> int:
        if module not in module_at:
            m = re.search(r"['\"]" + re.escape(module) + r"['\"]", code)
            module_at[module] = m.start() if m else 0
        return module_at[module]

    for module, imported in names.values():
        if module in _RN_CONFIG and imported not in ("default", "Config", "*") and secret_name(imported):
            yield from hit(import_offset(module), f"`{imported}` comes from react-native-config, so this secret "
                                                  "ships inside the app.")
        if module in _DOTENV and imported not in ("default", "*") and secret_name(imported):
            yield from hit(import_offset(module), f"`{imported}` is imported from `{module}`, whose Babel plugin "
                                                  "writes its value into the JavaScript bundle.")
    if "EXPO_PUBLIC_" in raw and not _APP_CONFIG.search(path):
        for m in _EXPO_PUBLIC.finditer(code):
            if blank[m.start()] != code[m.start()]:
                continue
            name = m.group(1) or m.group(2)
            if secret_name(name):
                yield from hit(m.start(), f"`{name}` is an EXPO_PUBLIC_ variable: Expo writes its value into the "
                                          "JavaScript bundle, so this secret ships inside the app.")


_PROP_LITERAL = re.compile(r"(?<![\w$])['\"]?([A-Za-z_$][\w$\-]{0,80})['\"]?\s*:\s*(['\"`])([^'\"`\n]{1,4000})\2")


def _app_config_hits(ctx: Context, path: str) -> Iterator[Hit]:
    """app.config.js/ts is code: report literal secret values written into it (`extra`, plugin options)."""
    code = ctx.code(path) or ""
    blank = ctx.code(path, False) or ""
    for m in _PROP_LITERAL.finditer(code):
        if blank[m.start(2)] != code[m.start(2)]:
            continue                            # inside a string or comment
        name, value = m.group(1), m.group(3)
        if "${" in value or not secret_entry(name, value):
            continue
        line = ctx.line_of(code, m.start())
        yield Hit(path, line, _mask_in(ctx.snippet(path, line), value),
                  f"`{name}` is set to a literal secret in the Expo app config. Values in `extra` and plugin "
                  "options are copied into the app or the build output.")


def _app_json_hits(ctx: Context, path: str) -> Iterator[Hit]:
    text = ctx.text(path) or ""
    data = _load_json(text)
    if not isinstance(data, dict):
        return
    expo = data.get("expo", data)
    if not isinstance(expo, dict):
        return
    places = []
    if isinstance(expo.get("extra"), dict):
        extra = dict(expo["extra"])
        extra.pop("eas", None)
        places.append(("extra", extra))
    for platform in ("ios", "android"):
        p = expo.get(platform)
        if isinstance(p, dict) and isinstance(p.get("config"), dict):
            places.append((f"{platform}.config", p["config"]))
    for plugin in as_list(expo.get("plugins")):
        if isinstance(plugin, list) and len(plugin) > 1 and isinstance(plugin[1], (dict, list)):
            places.append((f"the {plugin[0]} plugin options", plugin[1]))
    seen: Set[int] = set()
    tries = 0
    for where, node in places:
        for key, value in _json_pairs(node):
            if not secret_entry(key, value):
                continue
            tries += 1
            if tries > _MAX_JSON_HITS:
                return                          # each line lookup searches the file; the report lists 50
            line = _line_of_key(ctx, text, key, value)
            if line in seen:
                continue
            seen.add(line)
            yield Hit(path, line, _mask_in(ctx.snippet(path, line), value),
                      f"`{key}` in {where} is a literal secret. Expo copies `extra` into the app, and plugin "
                      "options end up in the native build, so anyone with the app or the repository can read it.")


def _eas_hits(ctx: Context, path: str) -> Iterator[Hit]:
    text = ctx.text(path) or ""
    data = _load_json(text)
    build = data.get("build") if isinstance(data, dict) else None
    if not isinstance(build, dict):
        return
    seen: Set[int] = set()
    tries = 0
    for profile, conf in list(build.items())[:100]:
        env = conf.get("env") if isinstance(conf, dict) else None
        if not isinstance(env, dict):
            continue
        for key, value in list(env.items())[:500]:
            if not isinstance(value, str) or not secret_entry(key, value):
                continue
            tries += 1
            if tries > _MAX_JSON_HITS:
                return
            line = _line_of_key(ctx, text, key, value)
            if line in seen:
                continue
            seen.add(line)
            if key.startswith("EXPO_PUBLIC_"):
                msg = (f"`{key}` in eas.json's `{profile}` profile is a literal secret with the EXPO_PUBLIC_ prefix, "
                       "so Expo writes it into the app's JavaScript bundle.")
            else:
                msg = (f"`{key}` in eas.json's `{profile}` profile is a literal secret committed to the repository. "
                       "Store it as an EAS environment variable of secret visibility instead.")
            yield Hit(path, line, _mask_in(ctx.snippet(path, line), value), msg)


def _env_file_hits(ctx: Context) -> Iterator[Hit]:
    deps = package_deps(ctx)
    rn_config = "react-native-config" in deps
    expo = "expo" in deps
    if not (rn_config or expo):
        return
    for dir_ in package_dirs(ctx):
        for path in dotfiles(ctx, dir_, _ENV_FILE):
            base = path.rsplit("/", 1)[-1]
            if _ENV_NOT_SHIPPED.search(base[4:]):
                continue
            text = ctx.text(path) or ""
            for m in _ENV_LINE.finditer(text[:safety.MAX_FILE_BYTES]):
                key, value = m.group(1), _env_value(m.group(2))
                public = key.startswith("EXPO_PUBLIC_")
                if not (rn_config or (expo and public)) or not secret_entry(key, value):
                    continue
                line = ctx.line_of(text, m.start())
                how = ("react-native-config copies every value in this file into the app at build time"
                       if rn_config else "Expo writes EXPO_PUBLIC_ values into the JavaScript bundle")
                yield Hit(path, line, _mask_in(ctx.snippet(path, line), value),
                          f"`{key}` holds a secret, and {how}.", scope=_env_scope(base))


@detector("rn_bundled_secret")
def bundled_secret(ctx: Context, rule: Rule) -> Iterable[Hit]:
    for path in js_files(ctx):
        if scope_of(path) == "test":
            continue
        if _APP_CONFIG.search(path):
            yield from _app_config_hits(ctx, path)
        yield from _code_hits(ctx, path)
    for path in ctx.files(name="app.json"):
        if scope_of(path) != "test":
            yield from _app_json_hits(ctx, path)
    for path in ctx.files(name="eas.json"):
        if scope_of(path) != "test":
            yield from _eas_hits(ctx, path)
    yield from _env_file_hits(ctx)

