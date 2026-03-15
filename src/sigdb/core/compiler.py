from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from sigdb.types import SigDBBuildResult, SigDBFormatError, SigDBRules


def compile_sigdb_json(
    *,
    json_path: str | Path,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    signing_key_hex: str | None = None,
    zstd_level: int = 19,
) -> SigDBBuildResult:
    p = Path(json_path)
    try:
        rules_any = json.loads(p.read_bytes())
    except json.JSONDecodeError as e:
        raise SigDBFormatError("invalid rules json") from e

    from sigdb.format.trie import build_sigdb

    return build_sigdb(
        rules=cast(SigDBRules, rules_any),
        output_path=output_path,
        metadata=metadata,
        signing_key_hex=signing_key_hex,
        zstd_level=zstd_level,
    )
