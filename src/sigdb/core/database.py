from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from sigdb.core.compiler import DEFAULT_INDEX, automaton_section, index_section
from sigdb.core.index import Index
from sigdb.format.automaton import deserialize_automaton
from sigdb.format.container import (
    DEFAULT_MAX_SECTION_SIZE,
    Container,
    parse_container,
    parse_json,
    read_header_file,
)
from sigdb.types import (
    Automaton,
    FormatError,
    Hit,
    Item,
    MatchResult,
    Occurrence,
    SearchDefinition,
    ValidationResult,
)
from sigdb.utils.hashing import sha256


class _RawSections:
    __slots__ = ("_raw",)

    def __init__(self, raw: Mapping[str, bytes]) -> None:
        self._raw = dict(raw)

    @property
    def names(self) -> list[str]:
        return list(self._raw)

    def digests(self) -> dict[str, str]:
        return {name: sha256(raw).hex() for name, raw in self._raw.items()}

    def __contains__(self, name: str) -> bool:
        return name in self._raw

    def raw(self, name: str) -> bytes:
        raw = self._raw.get(name)
        if raw is None:
            raise FormatError(f"missing section: {name}")
        return raw


class Database:
    __slots__ = ("_indexes", "_sections", "_store", "metadata")

    def __init__(self, metadata: dict[str, Any], store: Container | _RawSections) -> None:
        self.metadata = metadata
        self._store = store
        self._indexes: dict[str, Index] = {}
        self._sections: dict[str, Any] = {}
        for name in store.names:
            kind, _, rest = name.partition("/")
            if kind not in ("index", "automaton", "json", "blob") or not rest:
                raise FormatError(f"unknown section: {name}")
        if not self.index_names:
            raise FormatError("database has no indexes")

    @classmethod
    def from_raw(cls, metadata: Mapping[str, Any], sections: Mapping[str, bytes]) -> Database:
        return cls(dict(metadata), _RawSections(sections))

    def raw_sections(self) -> dict[str, bytes]:
        return {name: self._store.raw(name) for name in self._store.names}

    def section_digests(self) -> dict[str, str]:
        return self._store.digests()

    @property
    def index_names(self) -> list[str]:
        return [n.partition("/")[2] for n in self._store.names if n.startswith("index/")]

    @property
    def section_names(self) -> list[str]:
        return [
            n.partition("/")[2]
            for n in self._store.names
            if n.startswith("json/") or n.startswith("blob/")
        ]

    def section(self, name: str) -> Any:
        if name in self._sections:
            return self._sections[name]
        if f"json/{name}" in self._store:
            value = parse_json(self._store.raw(f"json/{name}"), f"section {name}")
        elif f"blob/{name}" in self._store:
            value = self._store.raw(f"blob/{name}")
        else:
            raise FormatError(f"missing section: {name}")
        self._sections[name] = value
        return value

    def index(self, name: str = DEFAULT_INDEX) -> Index:
        index = self._indexes.get(name)
        if index is not None:
            return index
        section = index_section(name)
        if section not in self._store:
            raise FormatError(f"missing index: {name}")
        payload = parse_json(self._store.raw(section), f"index {name}")

        def load_automaton(group: str, pattern_count: int) -> Automaton | None:
            sec = automaton_section(name, group)
            if sec not in self._store:
                return None
            return deserialize_automaton(self._store.raw(sec), pattern_count=pattern_count)

        index = Index(name, payload, load_automaton)
        self._indexes[name] = index
        return index

    @property
    def items(self) -> list[Item]:
        return self.index().items

    def item(self, key: str) -> Item | None:
        return self.index().item(key)

    def items_with_prefix(self, prefix: str) -> list[Item]:
        return self.index().items_with_prefix(prefix)

    def match(self, head: str) -> MatchResult:
        return self.index().match(head)

    def match_group(self, group: str, value: str, *, name: str | None = None) -> MatchResult:
        return self.index().match_group(group, value, name=name)

    def match_search(self, search: SearchDefinition) -> MatchResult:
        return self.index().match_search(search)

    def match_html(self, html: str) -> MatchResult:
        return self.index().match_html(html)

    def match_all(self, group: str, values: str | Iterable[str] | Mapping[str, str]) -> list[Hit]:
        return self.index().match_all(group, values)

    def match_tokens(self, group: str, tokens: Iterable[str]) -> dict[int, int]:
        return self.index().match_tokens(group, tokens)

    def scan(self, text: str, group: str) -> list[Occurrence]:
        return self.index().scan(text, group)


def load_bytes(
    data: bytes,
    *,
    verify_hash: bool = True,
    max_section_size: int = DEFAULT_MAX_SECTION_SIZE,
) -> Database:
    container = parse_container(data, verify_hash=verify_hash, max_section_size=max_section_size)
    return Database(container.header, container)


def load(
    path: str | Path,
    *,
    verify_hash: bool = True,
    lazy: bool = True,
    max_section_size: int = DEFAULT_MAX_SECTION_SIZE,
) -> Database:
    db = load_bytes(
        Path(path).read_bytes(), verify_hash=verify_hash, max_section_size=max_section_size
    )
    if not lazy:
        _load_all(db)
    return db


def _load_all(db: Database) -> None:
    for name in db.index_names:
        db.index(name).preload()
    for name in db.section_names:
        db.section(name)


def read_metadata(path: str | Path) -> dict[str, Any]:
    return read_header_file(path)


def validate(
    path: str | Path,
    *,
    verify_hash: bool = True,
    max_section_size: int = DEFAULT_MAX_SECTION_SIZE,
) -> ValidationResult:
    errors: list[str] = []
    metadata: dict[str, Any] | None = None
    digests: dict[str, str] | None = None
    try:
        db = load_bytes(
            Path(path).read_bytes(), verify_hash=verify_hash, max_section_size=max_section_size
        )
        metadata = db.metadata
        digests = db.section_digests()
        db.raw_sections()
        _load_all(db)
        for section in digests:
            kind, _, rest = section.partition("/")
            if kind != "automaton":
                continue
            index_name, _, group = rest.partition("/")
            if index_name not in db.index_names:
                errors.append(f"automaton section for unknown index: {section}")
                continue
            spec = db.index(index_name).groups.get(group)
            if spec is None or spec.match == "exact":
                errors.append(f"unexpected automaton section: {section}")
    except Exception as e:
        errors.append(str(e))
    return ValidationResult(ok=not errors, errors=errors, metadata=metadata, sections=digests)
