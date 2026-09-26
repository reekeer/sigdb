from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sigdb.format.automaton import build_automaton, serialize_automaton
from sigdb.format.container import dump_json, write_container
from sigdb.internal.groups import (
    RESERVED_RULE_KEYS,
    check_name,
    normalize,
    parse_values,
    resolve_groups,
)
from sigdb.types import BuildResult, FormatError, GroupConfig, IndexSpec, RulesInput

DEFAULT_INDEX = "main"
FORMAT_NAME = "SIGDB"


def index_section(index: str) -> str:
    return f"index/{index}"


def automaton_section(index: str, group: str) -> str:
    return f"automaton/{index}/{group}"


def json_section(name: str) -> str:
    return f"json/{name}"


def blob_section(name: str) -> str:
    return f"blob/{name}"


def merge_rules(rules: object) -> dict[str, Mapping[str, Any]]:
    parts: list[object]
    if isinstance(rules, Mapping):
        parts = [rules]
    elif isinstance(rules, Sequence) and not isinstance(rules, (str, bytes, bytearray)):
        parts = list(cast(Sequence[object], rules))
    else:
        raise FormatError("rules must be a JSON object")

    merged: dict[str, Mapping[str, Any]] = {}
    for part in parts:
        if not isinstance(part, Mapping):
            raise FormatError("rules must be a JSON object")
        for key, value in cast(Mapping[object, object], part).items():
            if not isinstance(key, str) or not key:
                raise FormatError("rule keys must be non-empty strings")
            if key in merged:
                raise FormatError(f"duplicate rule key: {key!r}")
            if not isinstance(value, Mapping):
                raise FormatError(f"rule {key!r} must be an object")
            merged[key] = cast(Mapping[str, Any], value)
    return merged


def compile_index(
    name: str,
    rules: RulesInput,
    groups: Mapping[str, GroupConfig] | None,
) -> list[tuple[str, bytes]]:
    specs = resolve_groups(groups)
    merged = merge_rules(rules)

    items: list[list[Any]] = []
    pattern_ids: dict[tuple[str, str], int] = {}
    patterns: list[list[str]] = []
    pattern_items: list[list[int]] = []

    for key, rule in merged.items():
        item_id = len(items)
        data = rule.get("data")
        try:
            dump_json(data)
        except FormatError as e:
            raise FormatError(f"rule {key!r}: data is not serializable as JSON") from e
        for group, raw in rule.items():
            if group in RESERVED_RULE_KEYS:
                continue
            spec = specs.get(group)
            if spec is None:
                raise FormatError(f"rule {key!r}: unknown group: {group}")
            for value in parse_values(spec, raw):
                text = normalize(spec, value)
                if not text:
                    raise FormatError(f"rule {key!r}: empty pattern in group {group}")
                if spec.kind == "map" and text.startswith(":"):
                    raise FormatError(f"rule {key!r}: empty name in group {group}")
                pid = pattern_ids.get((group, text))
                if pid is None:
                    pid = len(patterns)
                    pattern_ids[(group, text)] = pid
                    patterns.append([group, text])
                    pattern_items.append([])
                ids = pattern_items[pid]
                if not ids or ids[-1] != item_id:
                    ids.append(item_id)
        items.append([key, data])

    payload = {
        "groups": {g: spec.to_json() for g, spec in specs.items()},
        "items": items,
        "patterns": patterns,
        "pattern_items": pattern_items,
    }
    sections: list[tuple[str, bytes]] = [(index_section(name), dump_json(payload))]

    for group, spec in specs.items():
        if spec.match == "exact":
            continue
        entries = [
            (text.encode("utf-8"), pid) for pid, (g, text) in enumerate(patterns) if g == group
        ]
        if entries:
            automaton = serialize_automaton(build_automaton(entries))
            sections.append((automaton_section(name, group), automaton))
    return sections


def _header(metadata: Mapping[str, Any] | None, timestamp: int | None) -> dict[str, Any]:
    if metadata is not None and not isinstance(cast(object, metadata), Mapping):
        raise FormatError("metadata must be an object")
    header: dict[str, Any] = dict(metadata or {})
    header.setdefault("format", FORMAT_NAME)
    if timestamp is not None:
        if (
            isinstance(timestamp, bool)
            or not isinstance(cast(object, timestamp), int)
            or timestamp < 0
        ):
            raise FormatError("timestamp must be a non-negative integer")
        header.setdefault("created", timestamp)
        header.setdefault("build", datetime.fromtimestamp(timestamp, UTC).date().isoformat())
    return header


def _collect_sections(
    rules: RulesInput | None,
    groups: Mapping[str, GroupConfig] | None,
    indexes: Mapping[str, IndexSpec] | None,
    sections: Mapping[str, Any] | None,
) -> list[tuple[str, bytes]]:
    specs: dict[str, IndexSpec] = {}
    if rules is not None:
        specs[DEFAULT_INDEX] = {"rules": rules, "groups": groups or {}}
    elif groups is not None:
        raise FormatError("groups requires rules")
    for name, spec in (indexes or {}).items():
        check_name(name, "index")
        if name in specs:
            raise FormatError(f"duplicate index: {name}")
        if not isinstance(cast(object, spec), Mapping) or spec.get("rules") is None:
            raise FormatError(f"index {name} must have rules")
        specs[name] = spec
    if not specs:
        raise FormatError("at least one index is required")

    out: list[tuple[str, bytes]] = []
    for name, spec in specs.items():
        out.extend(compile_index(name, cast(RulesInput, spec.get("rules")), spec.get("groups")))
    for name, value in sections.items() if sections else ():
        check_name(name, "section")
        if isinstance(value, (bytes, bytearray, memoryview)):
            out.append((blob_section(name), bytes(cast(bytes, value))))
        else:
            out.append((json_section(name), dump_json(value)))
    return out


def _build(
    rules: RulesInput | None,
    groups: Mapping[str, GroupConfig] | None,
    indexes: Mapping[str, IndexSpec] | None,
    sections: Mapping[str, Any] | None,
    metadata: Mapping[str, Any] | None,
    timestamp: int | None,
    zstd_level: int,
) -> tuple[bytes, dict[str, Any], dict[str, str]]:
    header = _header(metadata, timestamp)
    collected = _collect_sections(rules, groups, indexes, sections)
    data, hashes = write_container(header, collected, zstd_level=zstd_level)
    return data, header, hashes


def build_bytes(
    rules: RulesInput | None = None,
    *,
    groups: Mapping[str, GroupConfig] | None = None,
    indexes: Mapping[str, IndexSpec] | None = None,
    sections: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    timestamp: int | None = None,
    zstd_level: int = 19,
) -> bytes:
    data, _, _ = _build(rules, groups, indexes, sections, metadata, timestamp, zstd_level)
    return data


def build(
    rules: RulesInput | None = None,
    output_path: str | Path | None = None,
    *,
    groups: Mapping[str, GroupConfig] | None = None,
    indexes: Mapping[str, IndexSpec] | None = None,
    sections: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    timestamp: int | None = None,
    zstd_level: int = 19,
) -> BuildResult:
    if output_path is None:
        raise FormatError("output_path is required")
    data, header, hashes = _build(rules, groups, indexes, sections, metadata, timestamp, zstd_level)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return BuildResult(output_path=output, size=len(data), metadata=header, sections=hashes)


def _read_json_rules(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise FormatError(f"invalid rules json: {path}") from e


def read_rules(path: str | Path) -> dict[str, Mapping[str, Any]]:
    p = Path(path)
    if p.is_file():
        return merge_rules(_read_json_rules(p))
    if not p.is_dir():
        raise FormatError(f"rules path not found: {p}")

    merged: dict[str, Mapping[str, Any]] = {}
    origin: dict[str, str] = {}
    files = sorted(p.rglob("*.json"), key=lambda f: f.relative_to(p).as_posix())
    for f in files:
        rel = f.relative_to(p).as_posix()
        for key, value in merge_rules(_read_json_rules(f)).items():
            if key in merged:
                raise FormatError(f"duplicate rule key {key!r} in {origin[key]} and {rel}")
            merged[key] = value
            origin[key] = rel
    return merged


def compile_json(json_path: str | Path, output_path: str | Path, **options: Any) -> BuildResult:
    p = Path(json_path)
    if not p.is_file():
        raise FormatError(f"rules file not found: {p}")
    return build(read_rules(p), output_path, **options)


def compile_dir(dir_path: str | Path, output_path: str | Path, **options: Any) -> BuildResult:
    p = Path(dir_path)
    if not p.is_dir():
        raise FormatError(f"rules directory not found: {p}")
    return build(read_rules(p), output_path, **options)
