from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from sigdb.types import BuildResult, FormatError, Rules


def compile_sigdb_json(
    *,
    json_path: str | Path,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    zstd_level: int = 19,
) -> BuildResult:
    p = Path(json_path)
    try:
        rules_any = json.loads(p.read_bytes())
    except json.JSONDecodeError as e:
        raise FormatError("invalid rules json") from e

    from sigdb.format.trie import build_sigdb

    return build_sigdb(
        rules=cast(Rules, rules_any),
        output_path=output_path,
        metadata=metadata,
        zstd_level=zstd_level,
    )
