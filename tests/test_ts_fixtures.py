from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from test_golden import GOLDEN_DIR, _run

from sigdb import load

FIXTURES_DIR = Path(__file__).with_name("fixtures") / "ts"


def main() -> None:
    fixtures = sorted(FIXTURES_DIR.glob("*.sigdb"))
    if not fixtures:
        raise AssertionError("no sigdb-ts fixtures found")

    failures: list[str] = []
    for fixture in fixtures:
        case_dir = GOLDEN_DIR / fixture.stem
        db = load(fixture, lazy=False)

        expected = json.loads((case_dir / "sections.json").read_bytes())
        if db.section_digests() != expected:
            failures.append(f"{fixture.name}: section digests differ: {db.section_digests()}")

        vectors = cast(list[dict[str, Any]], json.loads((case_dir / "vectors.json").read_bytes()))
        for i, vector in enumerate(vectors):
            actual = _run(db, vector)
            if vector.get("expect") != actual:
                failures.append(f"{fixture.name}[{i}] expected {vector.get('expect')} got {actual}")

    if failures:
        raise AssertionError("sigdb-ts fixture mismatch:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
