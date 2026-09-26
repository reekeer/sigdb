from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from sigdb.core.compiler import DEFAULT_INDEX
from sigdb.core.database import Database, load, read_metadata, validate
from sigdb.core.index import Index
from sigdb.types import (
    Hit,
    Item,
    MatchResult,
    Occurrence,
    SearchDefinition,
    ValidationResult,
)


class Reader:
    __slots__ = ("_db", "_path", "_verify_hash")

    def __init__(self, path: str | Path, *, verify_hash: bool = True) -> None:
        self._path = Path(path)
        self._verify_hash = verify_hash
        self._db: Database | None = None

    @property
    def path(self) -> Path:
        return self._path

    def metadata(self) -> dict[str, Any]:
        return read_metadata(self._path)

    def validate(self) -> ValidationResult:
        return validate(self._path, verify_hash=self._verify_hash)

    def load(self) -> Database:
        return load(self._path, verify_hash=self._verify_hash)

    def database(self) -> Database:
        if self._db is None:
            self._db = self.load()
        return self._db

    def index(self, name: str = DEFAULT_INDEX) -> Index:
        return self.database().index(name)

    def section(self, name: str) -> Any:
        return self.database().section(name)

    def item(self, key: str) -> Item | None:
        return self.database().item(key)

    def items_with_prefix(self, prefix: str) -> list[Item]:
        return self.database().items_with_prefix(prefix)

    def match(self, head: str) -> MatchResult:
        return self.database().match(head)

    def match_group(self, group: str, value: str, *, name: str | None = None) -> MatchResult:
        return self.database().match_group(group, value, name=name)

    def match_search(self, search: SearchDefinition) -> MatchResult:
        return self.database().match_search(search)

    def match_html(self, html: str) -> MatchResult:
        return self.database().match_html(html)

    def match_all(self, group: str, values: str | Iterable[str] | Mapping[str, str]) -> list[Hit]:
        return self.database().match_all(group, values)

    def match_tokens(self, group: str, tokens: Iterable[str]) -> dict[int, int]:
        return self.database().match_tokens(group, tokens)

    def scan(self, text: str, group: str) -> list[Occurrence]:
        return self.database().scan(text, group)
