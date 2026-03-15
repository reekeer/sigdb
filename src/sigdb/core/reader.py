from __future__ import annotations

from pathlib import Path
from typing import Any, overload

from sigdb.format.trie import load_sigdb, read_sigdb_metadata, validate_sigdb
from sigdb.groups import (
    SIGDB_GROUPS,
    SIGDB_GROUPS_MAP,
    format_list_pattern,
    format_map_pattern,
    html_heads,
    parse_group_list,
    parse_string_map,
)
from sigdb.types import (
    SigDBDatabase,
    SigDBFormatError,
    SigDBGroupName,
    SigDBMatchResult,
    SigDBSearchDefinition,
    SigDBValidationResult,
)


def _normalize_head(head: str) -> str:
    s = head.strip()
    i = s.find(":")
    if i == -1:
        return s.lower()
    name = s[:i].strip().lower()
    value = s[i + 1 :].strip().lower()
    return f"{name}:{value}"


def _iter_search_heads(search: SigDBSearchDefinition) -> list[str]:
    heads: list[str] = []
    headers = parse_string_map(search.get("headers"), "headers")
    for header_name, header_value in headers.items():
        heads.append(format_map_pattern("headers", header_name, header_value))

    for group in SIGDB_GROUPS:
        if group == "headers":
            continue
        if group in SIGDB_GROUPS_MAP:
            group_map = parse_string_map(search.get(group), group)
            for name, value in group_map.items():
                heads.append(format_map_pattern(group, name, value))
        else:
            group_values = parse_group_list(search.get(group), group)
            for value in group_values:
                heads.append(format_list_pattern(group, value))
    return heads


class SigDBMatcher:
    __slots__ = ("_automaton", "_items")

    def __init__(self, db: SigDBDatabase) -> None:
        self._automaton = db.automaton
        self._items = db.items

    def match(self, head: str) -> SigDBMatchResult:
        normalized = _normalize_head(head)
        data = normalized.encode("utf-8")

        a = self._automaton
        labels = a.labels
        children_start = a.children_start
        children_count = a.children_count
        next_state = a.next_state
        fail = a.fail
        out_start = a.out_start
        out_count = a.out_count
        outputs = a.outputs

        state = 0
        for b in data:
            while True:
                start = children_start[state]
                count = children_count[state]
                nxt = -1
                if count:
                    lo = 0
                    hi = count
                    while lo < hi:
                        mid = (lo + hi) >> 1
                        lb = labels[start + mid]
                        if lb < b:
                            lo = mid + 1
                        elif lb > b:
                            hi = mid
                        else:
                            nxt = next_state[start + mid]
                            break

                if nxt != -1:
                    state = nxt
                    break
                if state == 0:
                    break
                state = fail[state]

            oc = out_count[state]
            if oc:
                ostart = out_start[state]
                item_id = outputs[ostart]
                item = self._items[item_id]
                return SigDBMatchResult(
                    result=True, item_id=item_id, item=item, head=normalized
                )

        return SigDBMatchResult(result=False, item_id=None, item=None, head=normalized)

    def match_group(
        self,
        group: SigDBGroupName,
        value: str,
        *,
        name: str | None = None,
    ) -> SigDBMatchResult:
        if group not in SIGDB_GROUPS:
            raise SigDBFormatError(f"unknown group: {group}")
        if name is None:
            if group in SIGDB_GROUPS_MAP:
                raise SigDBFormatError(f"group {group} requires a name")
            head = format_list_pattern(group, value)
        else:
            if group not in SIGDB_GROUPS_MAP:
                raise SigDBFormatError(f"group {group} does not accept a name")
            head = format_map_pattern(group, name, value)
        return self.match(head)

    def match_search(self, search: SigDBSearchDefinition) -> SigDBMatchResult:
        for head in _iter_search_heads(search):
            result = self.match(head)
            if result.result:
                return result
        return SigDBMatchResult(result=False, item_id=None, item=None, head="")

    def match_html(self, html: str) -> SigDBMatchResult:
        for head in html_heads(html):
            result = self.match(head)
            if result.result:
                return result
        return SigDBMatchResult(result=False, item_id=None, item=None, head="")


@overload
def match(head: str, src: SigDBMatcher) -> SigDBMatchResult: ...


@overload
def match(head: str, src: SigDBDatabase) -> SigDBMatchResult: ...


@overload
def match(head: str, src: SigDBReader) -> SigDBMatchResult: ...


def match(head: str, src: object) -> SigDBMatchResult:
    if isinstance(src, SigDBMatcher):
        return src.match(head)
    if isinstance(src, SigDBDatabase):
        return SigDBMatcher(src).match(head)
    if isinstance(src, SigDBReader):
        return src.matcher().match(head)
    raise TypeError("src must be SigDBReader, SigDBDatabase, or SigDBMatcher")


@overload
def match_group(
    group: SigDBGroupName,
    value: str,
    src: SigDBMatcher,
    *,
    name: str | None = None,
) -> SigDBMatchResult: ...


@overload
def match_group(
    group: SigDBGroupName,
    value: str,
    src: SigDBDatabase,
    *,
    name: str | None = None,
) -> SigDBMatchResult: ...


@overload
def match_group(
    group: SigDBGroupName,
    value: str,
    src: SigDBReader,
    *,
    name: str | None = None,
) -> SigDBMatchResult: ...


def match_group(
    group: SigDBGroupName,
    value: str,
    src: object,
    *,
    name: str | None = None,
) -> SigDBMatchResult:
    if isinstance(src, SigDBMatcher):
        return src.match_group(group, value, name=name)
    if isinstance(src, SigDBDatabase):
        return SigDBMatcher(src).match_group(group, value, name=name)
    if isinstance(src, SigDBReader):
        return src.matcher().match_group(group, value, name=name)
    raise TypeError("src must be SigDBReader, SigDBDatabase, or SigDBMatcher")


@overload
def match_search(
    search: SigDBSearchDefinition,
    src: SigDBMatcher,
) -> SigDBMatchResult: ...


@overload
def match_search(
    search: SigDBSearchDefinition,
    src: SigDBDatabase,
) -> SigDBMatchResult: ...


@overload
def match_search(
    search: SigDBSearchDefinition,
    src: SigDBReader,
) -> SigDBMatchResult: ...


def match_search(search: SigDBSearchDefinition, src: object) -> SigDBMatchResult:
    if isinstance(src, SigDBMatcher):
        return src.match_search(search)
    if isinstance(src, SigDBDatabase):
        return SigDBMatcher(src).match_search(search)
    if isinstance(src, SigDBReader):
        return src.matcher().match_search(search)
    raise TypeError("src must be SigDBReader, SigDBDatabase, or SigDBMatcher")


@overload
def match_html(html: str, src: SigDBMatcher) -> SigDBMatchResult: ...


@overload
def match_html(html: str, src: SigDBDatabase) -> SigDBMatchResult: ...


@overload
def match_html(html: str, src: SigDBReader) -> SigDBMatchResult: ...


def match_html(html: str, src: object) -> SigDBMatchResult:
    if isinstance(src, SigDBMatcher):
        return src.match_html(html)
    if isinstance(src, SigDBDatabase):
        return SigDBMatcher(src).match_html(html)
    if isinstance(src, SigDBReader):
        return src.matcher().match_html(html)
    raise TypeError("src must be SigDBReader, SigDBDatabase, or SigDBMatcher")


class SigDBReader:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._cache_db: SigDBDatabase | None = None
        self._cache_params: tuple[str | None, bool, bool] | None = None

    @property
    def path(self) -> Path:
        return self._path

    def metadata(self) -> dict[str, Any]:
        return read_sigdb_metadata(self._path)

    def validate(
        self,
        *,
        public_key_hex: str | None = None,
        verify_hash: bool = True,
        verify_signature: bool = True,
    ) -> SigDBValidationResult:
        return validate_sigdb(
            self._path,
            public_key_hex=public_key_hex,
            verify_hash=verify_hash,
            verify_signature=verify_signature,
        )

    def load(
        self,
        *,
        public_key_hex: str | None = None,
        verify_hash: bool = True,
        verify_signature: bool = True,
    ) -> SigDBDatabase:
        return load_sigdb(
            self._path,
            public_key_hex=public_key_hex,
            verify_hash=verify_hash,
            verify_signature=verify_signature,
        )

    def load_cached(
        self,
        *,
        public_key_hex: str | None = None,
        verify_hash: bool = True,
        verify_signature: bool = True,
    ) -> SigDBDatabase:
        params = (public_key_hex, verify_hash, verify_signature)
        if self._cache_db is not None and self._cache_params == params:
            return self._cache_db
        self._cache_db = self.load(
            public_key_hex=public_key_hex,
            verify_hash=verify_hash,
            verify_signature=verify_signature,
        )
        self._cache_params = params
        return self._cache_db

    def matcher(
        self,
        *,
        public_key_hex: str | None = None,
        verify_hash: bool = True,
        verify_signature: bool = True,
    ) -> SigDBMatcher:
        return SigDBMatcher(
            self.load_cached(
                public_key_hex=public_key_hex,
                verify_hash=verify_hash,
                verify_signature=verify_signature,
            )
        )

    def match(self, head: str) -> SigDBMatchResult:
        return self.matcher().match(head)

    def match_group(
        self,
        group: SigDBGroupName,
        value: str,
        *,
        name: str | None = None,
    ) -> SigDBMatchResult:
        return self.matcher().match_group(group, value, name=name)

    def match_search(self, search: SigDBSearchDefinition) -> SigDBMatchResult:
        return self.matcher().match_search(search)

    def match_html(self, html: str) -> SigDBMatchResult:
        return self.matcher().match_html(html)
