from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).parent))

from test_golden import GOLDEN_DIR, _check_item_keys, _run  # noqa: E402

from sigdb.core import compile_sigdb_json, load_sigdb, read_sigdb_metadata  # noqa: E402

FIXTURES_DIR = Path(__file__).with_name("fixtures") / "ts"


def main() -> None:
    fixtures = sorted(FIXTURES_DIR.glob("*.sigdb"))
    if not fixtures:
        raise AssertionError("no sigdb-ts fixtures found")

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        for fixture in fixtures:
            case_dir = GOLDEN_DIR / fixture.stem
            db = load_sigdb(fixture)
            _check_item_keys(case_dir, db)

            vectors = cast(list[dict[str, Any]], json.loads((case_dir / "vectors.json").read_bytes()))
            for i, vector in enumerate(vectors):
                actual = _run(db, vector)
                if vector.get("expect") != actual:
                    failures.append(f"{fixture.name}[{i}] expected {vector.get('expect')} got {actual}")

            rebuilt = compile_sigdb_json(
                json_path=case_dir / "rules.json",
                output_path=tmp / fixture.name,
                metadata=read_sigdb_metadata(fixture),
            )
            stored = fixture.read_bytes()[-32:].hex()
            if rebuilt.data_hash_hex != stored:
                failures.append(f"{fixture.name}: data hash {rebuilt.data_hash_hex} != {stored}")

    if failures:
        raise AssertionError("sigdb-ts fixture mismatch:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
