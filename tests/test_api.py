from __future__ import annotations

import json
import tempfile
from pathlib import Path

from helpers import assert_eq, assert_raises, assert_true

from sigdb import (
    Database,
    FormatError,
    Reader,
    build,
    build_bytes,
    compile_dir,
    compile_json,
    load,
    load_bytes,
    read_metadata,
    read_rules,
    validate,
)
from sigdb.core.compiler import compile_index
from sigdb.format.automaton import deserialize_automaton
from sigdb.format.container import dump_json, write_container

RULES = {
    "react@18/index.js": {
        "data": {"package": "react", "entry": True},
        "features": ["P:useState", "K:setState"],
    },
    "zustand@4/index.js": {"data": {"package": "zustand"}, "features": ["P:useState"]},
    "nginx": {"headers": {"Server": "nginx"}},
}
GROUPS = {"features": {}}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)

        out = tmp / "a.sigdb"
        result = build(RULES, out, groups=GROUPS, metadata={"dataset": "x"})
        assert_eq(result.size, out.stat().st_size, "size")
        assert_eq(result.metadata, {"dataset": "x", "format": "SIGDB"}, "no timestamps by default")
        assert_eq(read_metadata(out), result.metadata, "read_metadata")
        assert_eq(sorted(result.sections), sorted(load(out).section_digests()), "digests")

        first = out.read_bytes()
        build(RULES, out, groups=GROUPS, metadata={"dataset": "x"})
        assert_eq(out.read_bytes(), first, "rebuild is byte-identical")

        stamped = build_bytes(RULES, groups=GROUPS, timestamp=86_400)
        meta = load_bytes(stamped).metadata
        assert_eq((meta["created"], meta["build"]), (86_400, "1970-01-02"), "timestamp")
        assert_raises(FormatError, lambda: build_bytes(RULES, groups=GROUPS, timestamp=-1))

        v = validate(out)
        assert_true(v.ok, f"validate failed: {v.errors}")
        assert_eq(v.sections, result.sections, "validate digests")

        reader = Reader(out)
        assert_eq(reader.match_tokens("features", ["P:useState"]), {0: 1, 1: 1}, "reader tokens")
        assert_true(reader.database() is reader.database(), "reader caches database")
        assert_eq(reader.item("nginx"), reader.index().items[2], "reader item")

        eager = load(out, lazy=False)
        assert_eq(eager.match("Server: nginx").item_id, 2, "eager load")

        db = load(out)
        clone = Database.from_raw(db.metadata, db.raw_sections())
        assert_eq(clone.match_tokens("features", ["K:setState"]), {0: 1}, "from_raw")
        assert_eq(clone.section_digests(), db.section_digests(), "from_raw digests")

        rules_dir = tmp / "rules"
        (rules_dir / "b").mkdir(parents=True)
        (rules_dir / "a.json").write_text(json.dumps({"x": {"js": "x"}}))
        (rules_dir / "b" / "c.json").write_text(json.dumps({"y": {"js": "y"}}))
        (rules_dir / "b" / "ignored.txt").write_text("{")
        assert_eq(list(read_rules(rules_dir)), ["x", "y"], "read_rules dir order")
        compiled = compile_dir(rules_dir, tmp / "dir.sigdb", timestamp=0)
        assert_eq(compiled.metadata["build"], "1970-01-01", "compile_dir options")
        assert_eq([i.key for i in load(tmp / "dir.sigdb").items], ["x", "y"], "compile_dir items")
        compile_json(rules_dir / "a.json", tmp / "file.sigdb")
        assert_raises(
            FormatError, lambda: compile_json(rules_dir, tmp / "x.sigdb"), msg_contains="not found"
        )
        assert_raises(
            FormatError,
            lambda: compile_dir(rules_dir / "a.json", tmp / "x.sigdb"),
            msg_contains="not found",
        )

        (rules_dir / "b" / "dup.json").write_text(json.dumps({"x": {}}))
        assert_raises(
            FormatError,
            lambda: read_rules(rules_dir),
            msg_contains="duplicate rule key 'x' in a.json and b/dup.json",
        )
        (rules_dir / "b" / "dup.json").write_text("{")
        assert_raises(FormatError, lambda: read_rules(rules_dir), msg_contains="invalid rules json")

        assert_raises(
            FormatError,
            lambda: build_bytes({"a": {"data": float("nan")}}),
            msg_contains="data is not serializable",
        )
        assert_raises(
            FormatError,
            lambda: build_bytes({"a": {"data": {"x": object()}}}),
            msg_contains="data is not serializable",
        )
        assert_raises(FormatError, lambda: build(RULES), msg_contains="output_path is required")

        sections = compile_index("main", {"a": {"js": "abc"}}, None)
        automaton = dict(sections)["automaton/main/js"]
        assert_raises(
            FormatError,
            lambda: deserialize_automaton(automaton, pattern_count=0),
            msg_contains="unknown pattern",
        )
        assert_raises(
            FormatError,
            lambda: deserialize_automaton(b"\xff\xff\xff\x01\x00\x00", pattern_count=1),
            msg_contains="exceed",
        )

        payload = json.loads(dict(sections)["index/main"])
        for mutate, text in (
            (lambda p: p.update(pattern_items=[[5]]), "unknown item"),
            (lambda p: p.update(pattern_items=[[]]), "non-empty array"),
            (lambda p: p.update(patterns=[["nope", "x"]]), "unknown group"),
            (lambda p: p.update(items=[["a"]]), "[key, data]"),
            (lambda p: p["groups"]["js"].update(match="regex"), "match must be"),
        ):
            bad = json.loads(json.dumps(payload))
            mutate(bad)
            data, _ = write_container({}, [("index/main", dump_json(bad))], zstd_level=1)
            assert_raises(FormatError, lambda d=data: load_bytes(d).index(), msg_contains=text)

        stray, _ = write_container(
            {},
            [("index/main", dict(sections)["index/main"]), ("automaton/other/js", automaton)],
            zstd_level=1,
        )
        (tmp / "stray.sigdb").write_bytes(stray)
        v = validate(tmp / "stray.sigdb")
        assert_true(not v.ok and "unknown index" in v.errors[0], f"stray automaton: {v.errors}")

        unknown, _ = write_container({}, [("weird/x", b"")], zstd_level=1)
        assert_raises(FormatError, lambda: load_bytes(unknown), msg_contains="unknown section")


if __name__ == "__main__":
    main()
