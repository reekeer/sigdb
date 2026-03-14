from __future__ import annotations

from pathlib import Path
from typing import Any

from sigdb.format.trie import load_sigdb, read_sigdb_metadata, validate_sigdb
from sigdb.types import SigDBDatabase, SigDBValidationResult


class SigDBReader:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

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
