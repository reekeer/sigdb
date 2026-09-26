from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

from sigdb.core import Matcher, compile_sigdb_json, load_sigdb
from sigdb.types import Database, Error, MatchResult

GOLDEN_DIR = Path(__file__).with_name("golden")


def _all_ids(db: Database, head: str) -> list[int]:
    # Every item id reported while scanning `head`, in order of first appearance.
    # `head` must already be normalized (MatchResult.head).
    a = db.automaton
    seen: list[int] = []
    state = 0
    for b in head.encode("utf-8"):
        while True:
            nxt = a.transition(state, b)
            if nxt != -1:
                state = nxt
                break
            if state == 0:
                break
            state = a.fail[state]
        start = a.out_start[state]
        for item_id in a.outputs[start : start + a.out_count[state]]:
            if item_id not in seen:
                seen.append(item_id)
    return seen


def _result(db: Database, r: MatchResult, *, with_all_ids: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "result": r.result,
        "item_id": r.item_id,
        "key": r.item.key if r.item is not None else None,
        "head": r.head,
    }
    if with_all_ids:
        out["all_ids"] = _all_ids(db, r.head)
    return out


def _run(db: Database, vector: dict[str, Any]) -> dict[str, Any]:
    m = Matcher(db)
    call = vector["call"]
    try:
        if call == "match":
            return _result(db, m.match(vector["head"]), with_all_ids=True)
        if call == "match_group":
            r = m.match_group(vector["group"], vector["value"], name=vector.get("name"))
            return _result(db, r, with_all_ids=True)
        if call == "match_html":
            return _result(db, m.match_html(vector["html"]), with_all_ids=False)
        if call == "match_search":
            return _result(db, m.match_search(vector["search"]), with_all_ids=False)
    except Error as e:
        return {"error": type(e).__name__, "message": str(e)}
    raise AssertionError(f"unknown call: {call}")


def _compile(case_dir: Path, tmp: Path) -> Database:
    out = tmp / f"{case_dir.name}.sigdb"
    compile_sigdb_json(json_path=case_dir / "rules.json", output_path=out)
    return load_sigdb(out)


def _check_item_keys(case_dir: Path, db: Database) -> None:
    # Item ids are assigned in rule-definition order.
    rules = cast(dict[str, Any], json.loads((case_dir / "rules.json").read_bytes()))
    keys = [item.key for item in db.items]
    if keys != list(rules):
        raise AssertionError(f"{case_dir.name}: item order mismatch: {keys} != {list(rules)}")


def main(argv: list[str]) -> None:
    regen = "--regen" in argv
    case_dirs = sorted(p for p in GOLDEN_DIR.iterdir() if (p / "rules.json").is_file())
    if not case_dirs:
        raise AssertionError("no golden cases found")

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)
        for case_dir in case_dirs:
            db = _compile(case_dir, tmp)
            _check_item_keys(case_dir, db)

            vectors_path = case_dir / "vectors.json"
            vectors = cast(list[dict[str, Any]], json.loads(vectors_path.read_bytes()))
            for i, vector in enumerate(vectors):
                actual = _run(db, vector)
                if regen:
                    vector["expect"] = actual
                elif vector.get("expect") != actual:
                    inputs = {k: v for k, v in vector.items() if k != "expect"}
                    failures.append(
                        f"{case_dir.name}[{i}] {json.dumps(inputs)}\n"
                        f"  expected: {json.dumps(vector.get('expect'))}\n"
                        f"  actual:   {json.dumps(actual)}"
                    )

            if regen:
                text = json.dumps(vectors, indent=2, ensure_ascii=False) + "\n"
                vectors_path.write_text(text, encoding="utf-8")

    if failures:
        raise AssertionError("golden vector mismatch:\n" + "\n".join(failures))


if __name__ == "__main__":
    main(sys.argv[1:])
