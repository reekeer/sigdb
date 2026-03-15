from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sigdb.types import SigDBBuildResult, SigDBDatabase, SigDBValidationResult


def build_sigdb(
    *,
    rules: object,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    signing_key_hex: str | None = None,
    zstd_level: int = 19,
) -> SigDBBuildResult:
    from sigdb.format.trie import build_sigdb as _build

    return _build(
        rules=rules,
        output_path=output_path,
        metadata=metadata,
        signing_key_hex=signing_key_hex,
        zstd_level=zstd_level,
    )


def load_sigdb(
    path: str | Path,
    *,
    public_key_hex: str | None = None,
    verify_hash: bool = True,
    verify_signature: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> SigDBDatabase:
    from sigdb.format.trie import load_sigdb as _load

    return _load(
        path,
        public_key_hex=public_key_hex,
        verify_hash=verify_hash,
        verify_signature=verify_signature,
        max_items_json_size=max_items_json_size,
        max_automaton_size=max_automaton_size,
    )


def read_sigdb_metadata(path: str | Path) -> dict[str, Any]:
    from sigdb.format.trie import read_sigdb_metadata as _read

    return _read(path)


def validate_sigdb(
    path: str | Path,
    *,
    public_key_hex: str | None = None,
    verify_hash: bool = True,
    verify_signature: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> SigDBValidationResult:
    from sigdb.format.trie import validate_sigdb as _validate

    return _validate(
        path,
        public_key_hex=public_key_hex,
        verify_hash=verify_hash,
        verify_signature=verify_signature,
        max_items_json_size=max_items_json_size,
        max_automaton_size=max_automaton_size,
    )


def compile_sigdb_json(
    *,
    json_path: str | Path,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    signing_key_hex: str | None = None,
    zstd_level: int = 19,
) -> SigDBBuildResult:
    from sigdb.core.compiler import compile_sigdb_json as _compile

    return _compile(
        json_path=json_path,
        output_path=output_path,
        metadata=metadata,
        signing_key_hex=signing_key_hex,
        zstd_level=zstd_level,
    )
