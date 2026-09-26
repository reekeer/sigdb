from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sigdb.types import (
    BuildResult,
    Database,
    Rules,
    ValidationResult,
)


def build_sigdb(
    *,
    rules: Rules,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    zstd_level: int = 19,
) -> BuildResult:
    from sigdb.format.trie import build_sigdb as _build

    return _build(
        rules=rules,
        output_path=output_path,
        metadata=metadata,
        zstd_level=zstd_level,
    )


def load_sigdb(
    path: str | Path,
    *,
    verify_hash: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> Database:
    from sigdb.format.trie import load_sigdb as _load

    return _load(
        path,
        verify_hash=verify_hash,
        max_items_json_size=max_items_json_size,
        max_automaton_size=max_automaton_size,
    )


def read_sigdb_metadata(path: str | Path) -> dict[str, Any]:
    from sigdb.format.trie import read_sigdb_metadata as _read

    return _read(path)


def validate_sigdb(
    path: str | Path,
    *,
    verify_hash: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> ValidationResult:
    from sigdb.format.trie import validate_sigdb as _validate

    return _validate(
        path,
        verify_hash=verify_hash,
        max_items_json_size=max_items_json_size,
        max_automaton_size=max_automaton_size,
    )


def compile_sigdb_json(
    *,
    json_path: str | Path,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    zstd_level: int = 19,
) -> BuildResult:
    from sigdb.core.compiler import compile_sigdb_json as _compile

    return _compile(
        json_path=json_path,
        output_path=output_path,
        metadata=metadata,
        zstd_level=zstd_level,
    )
