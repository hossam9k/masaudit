# SPDX-License-Identifier: Apache-2.0
"""Fast text search shared by the detectors: bracket matching, literal-anchored regex search, a
per-scan needle index, and a small memo keyed by text.

These exist because the obvious versions were slow on large apps or quadratic on crafted files.
Each gives exactly the answer of the obvious version; the tests compare them.
"""

from __future__ import annotations

import bisect
import re
from typing import TYPE_CHECKING, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

if TYPE_CHECKING:
    from masaudit.engine import Context


def match(text: str, i: int, opener: str, closer: str) -> int:
    """Index of the bracket closing the one at `i`, or len(text) if it never closes."""
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return j
    return len(text)


_TEXT_MEMO: List[list] = []


def text_memo(text: str, key: tuple, compute: Callable[[], object]):
    """compute(), remembered for this text object and key (the most recently used texts are kept)."""
    for k, entry in enumerate(_TEXT_MEMO):
        if entry[0] is text:
            memo = entry[1]
            if k:
                _TEXT_MEMO.insert(0, _TEXT_MEMO.pop(k))
            break
    else:
        memo = {}
        _TEXT_MEMO.insert(0, [text, memo])
        del _TEXT_MEMO[4:]
    if key not in memo:
        memo[key] = compute()
    return memo[key]


def first_in_span(text: str, rx: "re.Pattern[str]", start: int, end: int) -> Optional["re.Match[str]"]:
    """The match rx.search(text[start:end]) finds, as a match on `text` (offsets into `text`), answered from
    one memoized pass over `text`: a bisect per question instead of a scan of the slice. Exact when no match
    of `rx` can begin before `start` and overlap it, or run past `end`: the callers' spans start and end at
    brackets their patterns can't contain, such as an argument list `(...)` or a block `{...}`."""
    def build() -> Tuple[List[int], List["re.Match[str]"]]:
        found = list(rx.finditer(text))
        return [m.start() for m in found], found
    starts, found = text_memo(text, ("matches", rx.pattern, rx.flags), build)  # type: ignore[misc]
    k = bisect.bisect_left(starts, start)
    return found[k] if k < len(starts) and starts[k] < end else None


def found_in_span(text: str, rx: "re.Pattern[str]", start: int, end: int) -> bool:
    """rx.search(text[start:end]) is not None; see first_in_span."""
    return first_in_span(text, rx, start, end) is not None


# Recent texts bracket_match was asked about: [text, opener, closer, {open: close} once asked twice].
_PAIRINGS: List[list] = []
_PAIR_MIN = 4096                              # texts shorter than this are walked without the cache


def name_index(text: str, tail: str) -> Dict[str, "re.Match[str]"]:
    """{identifier: its first match of `\\bIDENTIFIER` + `tail`} for every identifier in `text`, in one pass.

    Replaces re.search(r"\\b" + re.escape(name) + tail, text) called once per name, which rescanned the
    whole file for every call site. The scan is a lookahead at each position, so matches may overlap as
    separate searches would; groups of `tail` are numbered from 2 (group 1 is the identifier)."""
    def build() -> Dict[str, "re.Match[str]"]:
        out: Dict[str, "re.Match[str]"] = {}
        for m in re.finditer(r"(?=\b([A-Za-z_]\w*)" + tail + r")", text):
            out.setdefault(m.group(1), m)
        return out
    return text_memo(text, ("name_index", tail), build)  # type: ignore[return-value]


def bracket_match(text: str, i: int, opener: str, closer: str) -> int:
    """guards.match(text, i, opener, closer): the index of the bracket closing the one at `i`, or len(text).
    guards.match walks forward from `i`, a pass over the rest of the file per question, which made files
    with thousands of unclosed blocks quadratic. From the second question about the same text, all its
    brackets are paired in one walk instead (pairing forwards with a stack gives the bracket at `i` the
    same partner as counting depth from `i`; a closer with nothing open never pairs with it)."""
    # Short texts (an argument list, a signature) are walked directly: cached, they would push a large
    # file's pairing out of the cache before it is reused.
    if (len(opener) == 1 and len(closer) == 1 and opener != closer and len(text) >= _PAIR_MIN
            and 0 <= i < len(text) and text[i] == opener):
        for k, entry in enumerate(_PAIRINGS):
            if entry[0] is text and entry[1] == opener and entry[2] == closer:
                if k:
                    _PAIRINGS.insert(0, _PAIRINGS.pop(k))     # most recently used first
                if entry[3] is None:
                    pairs: dict = {}
                    stack: List[int] = []
                    for m in re.finditer(re.escape(opener) + "|" + re.escape(closer), text):
                        if m.group() == opener:
                            stack.append(m.start())
                        elif stack:
                            pairs[stack.pop()] = m.start()
                    entry[3] = pairs
                return entry[3].get(i, len(text))
        _PAIRINGS.insert(0, [text, opener, closer, None])
        del _PAIRINGS[6:]
    return match(text, i, opener, closer)


def finditer_lit(rx: "re.Pattern[str]", text: str, literals: Tuple[str, ...]) -> Iterator["re.Match[str]"]:
    """The matches of rx.finditer(text), for a pattern each of whose matches starts with one of `literals`
    (such as `\\b(?:class|object)\\s+...`). A leading `\\b` keeps the regex engine from skipping ahead to
    the literal, so it tries every offset; str.find jumps to the only offsets where a match can start, and
    rx.match there (which still sees the character before, for `\\b`) picks the same leftmost match."""
    pos, n = 0, len(text)
    # Next offset of each literal at or after `pos`; each is searched forward only, so a file costs one
    # pass per literal however many candidates it has.
    nxt = {lit: text.find(lit) for lit in literals}
    while pos <= n:
        at = -1
        for lit, i in nxt.items():
            if 0 <= i < pos:
                i = nxt[lit] = text.find(lit, pos)
            if i >= 0 and (at < 0 or i < at):
                at = i
        if at < 0:
            return
        m = rx.match(text, at)
        if m is None:
            pos = at + 1
            continue
        yield m
        pos = m.end() if m.end() > at else at + 1


# Every ASCII character that isn't a letter, digit, or underscore, mapped to a space.
_NOT_WORD = {c: " " for c in range(128) if not (chr(c).isalnum() or chr(c) == "_")}


class _NeedleIndex:
    """Which of a list of texts contain a substring: `needle in text`, or with lower=True `needle in
    text.lower()`. Detectors prefilter files by hundreds of literal needles; testing each needle against
    every file costs a pass over all the code per needle. Instead each text is split once into words (runs
    left when whitespace and every ASCII character other than a letter, digit, or `_` separate them), and
    a needle is looked up in the much shorter list of distinct words: a text holds the needle only if each
    of the needle's own word pieces lies inside one of the text's words. When the needle is a single word
    piece that is exact; otherwise the texts that pass are confirmed with a substring test. Answers are
    cached, so rules sharing a needle pay once."""

    def __init__(self, texts: List[str]):
        self.texts = texts
        self._by_word: Optional[dict] = None      # word -> indices of the texts holding it; built on first use
        self._words = ""                          # the distinct words, one per line
        self._by_lower: Optional[dict] = None     # the same keyed by lower-cased word
        self._lower_words = ""
        self._cache: dict = {}
        self._sets: dict = {}
        self._unions: dict = {}
        self._ci: dict = {}

    def holding_any(self, needles: Sequence[str]) -> Set[int]:
        """Texts that contain at least one of `needles`."""
        key = tuple(needles)
        found = self._unions.get(key)
        if found is None:
            found = set()
            for n in key:
                found |= self.holding(n)
            self._unions[key] = found
        return found

    def candidates_lower(self, needle: str) -> Set[int]:
        """A superset of the texts whose lower-cased form contains `needle` (lower-case ASCII): the texts
        that have, for each word piece of the needle, a word whose lower-cased form contains the piece.
        Lower-casing never turns a separator into a word character or back, and maps each character on
        its own (but for the Greek final sigma, which no ASCII piece can touch), so a piece found in a
        lower-cased text lies inside one lower-cased word."""
        found = self._ci.get(needle)
        if found is None:
            pieces = needle.translate(_NOT_WORD).split()
            if not pieces or not needle.isascii():
                found = set(range(len(self.texts)))
            else:
                if self._by_lower is None:
                    if self._by_word is None:
                        self._build()
                    assert self._by_word is not None
                    by_lower: dict = {}
                    for w, held in self._by_word.items():
                        by_lower.setdefault(w.lower(), []).extend(held)
                    self._by_lower = by_lower
                    self._lower_words = "\n".join(by_lower)
                for piece in pieces:
                    held_set = _texts_with_piece(self._lower_words, self._by_lower, piece)
                    found = held_set if found is None else found & held_set
                    if not found:
                        break
            self._ci[needle] = found
        return found

    def files_holding(self, needle: str) -> List[int]:
        """Indices, ascending, of the texts that contain `needle`."""
        if needle not in self._cache:
            self._cache[needle] = self._scan(needle)
        return self._cache[needle]

    def holding(self, needle: str) -> Set[int]:
        """files_holding(needle) as a set."""
        found = self._sets.get(needle)
        if found is None:
            found = self._sets[needle] = set(self.files_holding(needle))
        return found

    def _build(self) -> None:
        by_word: dict = {}
        for k, text in enumerate(self.texts):
            for w in set(text.translate(_NOT_WORD).split()):
                held = by_word.get(w)
                if held is None:
                    by_word[w] = [k]
                else:
                    held.append(k)
        self._by_word = by_word
        self._words = "\n".join(by_word)

    def _scan(self, needle: str) -> List[int]:
        if not needle:
            return list(range(len(self.texts)))
        pieces = needle.translate(_NOT_WORD).split()
        if not pieces:                            # all punctuation: test every text
            return [k for k, text in enumerate(self.texts) if needle in text]
        if self._by_word is None:
            self._build()
        # A text holding the needle holds each piece inside one of its words (translation maps characters
        # one to one, and a piece has no separator in it), so it is among the candidates.
        candidates: Optional[Set[int]] = None
        for piece in pieces:
            held = _texts_with_piece(self._words, self._by_word, piece)
            candidates = held if candidates is None else candidates & held
            if not candidates:
                return []
        assert candidates is not None
        if pieces == [needle]:
            # A word is unchanged text (separators are the only characters translated), so a text with a
            # word containing the needle contains the needle.
            return sorted(candidates)
        return sorted(k for k in candidates if needle in self.texts[k])


def _texts_with_piece(words: str, by_word: dict, piece: str) -> Set[int]:
    """Union of by_word[w] over the words w (one per line of `words`) that contain `piece`."""
    out: Set[int] = set()
    i = words.find(piece)
    while i >= 0:
        start = words.rfind("\n", 0, i) + 1
        end = words.find("\n", i)
        end = len(words) if end < 0 else end
        out.update(by_word[words[start:end]])
        i = words.find(piece, end)                # the next word holding it
    return out


# Files the raw-text needle index covers: every source file a detector prefilters by literal.
_INDEXED = (".kt", ".java", ".swift", ".m", ".mm", ".h", ".dart", ".kts")


def _raw_index(ctx: Context) -> Tuple[_NeedleIndex, dict]:
    """(case-sensitive _NeedleIndex over the raw text of every readable _INDEXED file, path -> its index
    there); built once per scan."""
    cached = getattr(ctx, "_xpl_raw_index", None)
    if cached is None:
        paths, texts = [], []
        for path in ctx.files(*_INDEXED):
            raw = ctx.text(path)
            if raw is not None:
                paths.append(path)
                texts.append(raw)
        cached = (_NeedleIndex(texts), {p: i for i, p in enumerate(paths)})
        ctx._xpl_raw_index = cached  # type: ignore[attr-defined]
    return cached


def holds_any(ctx: Context, path: str, needles: Sequence[str]) -> bool:
    """`any(n in ctx.text(path) for n in needles)` (False for an unreadable file), from the index."""
    index, pos = _raw_index(ctx)
    k = pos.get(path)
    if k is None:
        raw = ctx.text(path)
        return raw is not None and any(map(raw.__contains__, needles))
    return k in index.holding_any(needles)


def holds_all(ctx: Context, path: str, needles: Sequence[str]) -> bool:
    """`all(n in ctx.text(path) for n in needles)` (False for an unreadable file), from the index."""
    index, pos = _raw_index(ctx)
    k = pos.get(path)
    if k is None or not needles:
        raw = ctx.text(path)
        return raw is not None and all(n in raw for n in needles)
    if k not in index.holding(needles[0]):
        return False
    # Few files get past the first needle; test the rest in this file rather than over every file.
    raw = ctx.text(path) or ""
    return all(n in raw for n in needles[1:])


MAX_TAG = 4000


def xml_tags(text: str, start: "re.Pattern[str]") -> Iterator[Tuple[int, str]]:
    """(offset, whole tag) for each tag `start` finds, up to its `>`; a tag with no `>` within MAX_TAG
    characters is skipped. The `>` is found with str.find, and a stretch already known to have none is not
    searched again, so a crafted file of unclosed tags stays linear."""
    clear_until = 0                           # no `>` in text[...:clear_until] past the last failed search
    for m in start.finditer(text):
        limit = m.end() + MAX_TAG
        end = text.find(">", max(m.end(), clear_until), limit)
        if end < 0:
            clear_until = limit
            continue
        yield m.start(), text[m.start():end + 1]
