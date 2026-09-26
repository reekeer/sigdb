from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

from sigdb import Database, Error, build_bytes, load_bytes
from sigdb.types import Hit, MatchResult

GOLDEN_DIR = Path(__file__).with_name("golden")


def _result(r: MatchResult) -> dict[str, Any]:
    return {
        "result": r.result,
        "item_id": r.item_id,
        "key": r.item.key if r.item is not None else None,
        "head": r.head,
        "pattern_id": r.pattern_id,
    }


def _hits(hits: list[Hit]) -> list[list[Any]]:
    return [[h.item_id, h.item.key, h.hits, list(h.pattern_ids)] for h in hits]


def _run(db: Database, vector: dict[str, Any]) -> Any:
    call = vector["call"]
    try:
        index = db.index(vector.get("index", "main"))
        if call == "match":
            out = _result(index.match(vector["head"]))
            out["all"] = _hits(index.match_all("headers", vector["head"]))
            return out
        if call == "match_group":
            group, value, name = vector["group"], vector["value"], vector.get("name")
            out = _result(index.match_group(group, value, name=name))
            out["all"] = _hits(index.match_all(group, {name: value} if name else [value]))
            return out
        if call == "match_html":
            return _result(index.match_html(vector["html"]))
        if call == "match_search":
            return _result(index.match_search(vector["search"]))
        if call == "match_all":
            return _hits(index.match_all(vector["group"], vector["values"]))
        if call == "match_tokens":
            counts = index.match_tokens(vector["group"], vector["tokens"])
            return [[item_id, count] for item_id, count in counts.items()]
        if call == "scan":
            return [
                [o.pattern_id, o.start, o.end, index.pattern(o.pattern_id).text]
                for o in index.scan(vector["text"], vector["group"])
            ]
        if call == "item":
            item = index.item(vector["key"])
            return None if item is None else [index.item_id(vector["key"]), item.data]
        if call == "items_with_prefix":
            return [item.key for item in index.items_with_prefix(vector["prefix"])]
        if call == "pattern_count":
            return index.pattern_count(vector["item_id"], vector.get("group"))
        if call == "section":
            value = db.section(vector["name"])
            return {"hex": value.hex()} if isinstance(value, bytes) else value
    except Error as e:
        return {"error": type(e).__name__, "message": str(e)}
    raise AssertionError(f"unknown call: {call}")


def _build_args(case_dir: Path) -> dict[str, Any]:
    build_path = case_dir / "build.json"
    if build_path.is_file():
        args = cast(dict[str, Any], json.loads(build_path.read_bytes()))
    else:
        args = {"rules": json.loads((case_dir / "rules.json").read_bytes())}
    sections = args.get("sections")
    if isinstance(sections, dict):
        for name, value in list(cast(dict[str, Any], sections).items()):
            if isinstance(value, dict) and set(cast(dict[str, Any], value)) == {"hex"}:
                sections[name] = bytes.fromhex(cast(dict[str, str], value)["hex"])
    return args


def _build_error(args: dict[str, Any]) -> dict[str, str] | None:
    try:
        build_bytes(**args)
    except Error as e:
        return {"error": type(e).__name__, "message": str(e)}
    return None


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str]) -> None:
    regen = "--regen" in argv
    case_dirs = sorted(
        p
        for p in GOLDEN_DIR.iterdir()
        if (p / "rules.json").is_file() or (p / "build.json").is_file()
    )
    if not case_dirs:
        raise AssertionError("no golden cases found")

    failures: list[str] = []
    for case_dir in case_dirs:
        data = build_bytes(**_build_args(case_dir))
        if data != build_bytes(**_build_args(case_dir)):
            failures.append(f"{case_dir.name}: build is not reproducible")
        db = load_bytes(data)

        digests_path = case_dir / "sections.json"
        digests = db.section_digests()
        if regen:
            _write_json(digests_path, digests)
        elif json.loads(digests_path.read_bytes()) != digests:
            failures.append(f"{case_dir.name}: section digests changed: {json.dumps(digests)}")

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
            _write_json(vectors_path, vectors)

    errors_path = GOLDEN_DIR / "build_errors.json"
    cases = cast(list[dict[str, Any]], json.loads(errors_path.read_bytes()))
    for i, case in enumerate(cases):
        actual = _build_error(case["build"])
        if regen:
            case["expect"] = actual
        elif case.get("expect") != actual:
            expected = json.dumps(case.get("expect"))
            failures.append(f"build_errors[{i}] expected {expected} got {json.dumps(actual)}")
    if regen:
        _write_json(errors_path, cases)

    if failures:
        raise AssertionError("golden vector mismatch:\n" + "\n".join(failures))


if __name__ == "__main__":
    main(sys.argv[1:])
