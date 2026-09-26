from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Iterable, Mapping
from typing import cast

from sigdb.format.automaton import find_contains, find_prefix
from sigdb.internal.groups import (
    format_map_value,
    html_heads,
    normalize,
    parse_values,
    spec_from_json,
)
from sigdb.types import (
    Automaton,
    FormatError,
    GroupSpec,
    Hit,
    Item,
    MatchResult,
    Occurrence,
    Pattern,
    SearchDefinition,
)

AutomatonLoader = Callable[[str, int], Automaton | None]


def _no_match(head: str = "") -> MatchResult:
    return MatchResult(result=False, item_id=None, item=None, head=head, pattern_id=None)


class Index:
    __slots__ = (
        "_automata",
        "_exact",
        "_group_counts",
        "_key_ids",
        "_lengths",
        "_load_automaton",
        "_pattern_items",
        "_patterns",
        "_sorted_keys",
        "groups",
        "items",
        "name",
    )

    def __init__(self, name: str, payload: object, load_automaton: AutomatonLoader) -> None:
        if not isinstance(payload, Mapping):
            raise FormatError(f"index {name}: payload must be an object")
        data = cast(Mapping[str, object], payload)

        groups_raw = data.get("groups")
        if not isinstance(groups_raw, Mapping):
            raise FormatError(f"index {name}: groups must be an object")
        self.groups: dict[str, GroupSpec] = {
            str(g): spec_from_json(str(g), cfg)
            for g, cfg in cast(Mapping[object, object], groups_raw).items()
        }

        items_raw = data.get("items")
        if not isinstance(items_raw, list):
            raise FormatError(f"index {name}: items must be an array")
        self.items: list[Item] = []
        for entry in cast(list[object], items_raw):
            if not isinstance(entry, list) or len(cast(list[object], entry)) != 2:
                raise FormatError(f"index {name}: item must be [key, data]")
            key, value = cast(list[object], entry)
            if not isinstance(key, str) or not key:
                raise FormatError(f"index {name}: item key must be a non-empty string")
            self.items.append(Item(key=key, data=value))

        patterns_raw = data.get("patterns")
        pattern_items_raw = data.get("pattern_items")
        if not isinstance(patterns_raw, list) or not isinstance(pattern_items_raw, list):
            raise FormatError(f"index {name}: patterns and pattern_items must be arrays")
        patterns_list = cast(list[object], patterns_raw)
        pattern_items_list = cast(list[object], pattern_items_raw)
        if len(patterns_list) != len(pattern_items_list):
            raise FormatError(f"index {name}: patterns and pattern_items differ in length")

        item_count = len(self.items)
        self._patterns: list[tuple[str, str]] = []
        self._pattern_items: list[tuple[int, ...]] = []
        for p, ids in zip(patterns_list, pattern_items_list, strict=True):
            if (
                not isinstance(p, list)
                or len(cast(list[object], p)) != 2
                or not all(isinstance(x, str) for x in cast(list[object], p))
            ):
                raise FormatError(f"index {name}: pattern must be [group, text]")
            group, text = cast(list[str], p)
            if group not in self.groups:
                raise FormatError(f"index {name}: pattern references unknown group: {group}")
            if not isinstance(ids, list) or not ids:
                raise FormatError(f"index {name}: pattern_items entry must be a non-empty array")
            id_list = cast(list[object], ids)
            if not all(
                isinstance(i, int) and not isinstance(i, bool) and 0 <= i < item_count
                for i in id_list
            ):
                raise FormatError(f"index {name}: pattern_items references unknown item")
            id_tuple = cast(tuple[int, ...], tuple(id_list))
            if list(id_tuple) != sorted(set(id_tuple)):
                raise FormatError(f"index {name}: pattern_items entry must be sorted and unique")
            self._patterns.append((group, text))
            self._pattern_items.append(id_tuple)

        self.name = name
        self._load_automaton = load_automaton
        self._automata: dict[str, Automaton | None] = {}
        self._exact: dict[str, dict[str, int]] = {}
        self._lengths: list[int] | None = None
        self._key_ids: dict[str, int] | None = None
        self._sorted_keys: list[tuple[str, int]] | None = None
        self._group_counts: dict[str | None, list[int]] = {}

    @property
    def pattern_total(self) -> int:
        return len(self._patterns)

    def pattern(self, pattern_id: int) -> Pattern:
        group, text = self._patterns[pattern_id]
        return Pattern(
            id=pattern_id, group=group, text=text, item_ids=self._pattern_items[pattern_id]
        )

    def item(self, key: str) -> Item | None:
        item_id = self.item_id(key)
        return None if item_id is None else self.items[item_id]

    def item_id(self, key: str) -> int | None:
        if self._key_ids is None:
            self._key_ids = {item.key: i for i, item in enumerate(self.items)}
        return self._key_ids.get(key)

    def items_with_prefix(self, prefix: str) -> list[Item]:
        if self._sorted_keys is None:
            self._sorted_keys = sorted((item.key, i) for i, item in enumerate(self.items))
        keys = self._sorted_keys
        out: list[Item] = []
        for key, item_id in keys[bisect_left(keys, (prefix, -1)) :]:
            if not key.startswith(prefix):
                break
            out.append(self.items[item_id])
        return out

    def pattern_count(self, item_id: int, group: str | None = None) -> int:
        counts = self._group_counts.get(group)
        if counts is None:
            counts = [0] * len(self.items)
            for (g, _), ids in zip(self._patterns, self._pattern_items, strict=True):
                if group is None or g == group:
                    for i in ids:
                        counts[i] += 1
            self._group_counts[group] = counts
        return counts[item_id]

    def preload(self) -> None:
        for group, spec in self.groups.items():
            if spec.match == "exact":
                self._exact_map(group)
            else:
                self._automaton(group)
        self._pattern_lengths()

    def spec(self, group: str) -> GroupSpec:
        spec = self.groups.get(group)
        if spec is None:
            raise FormatError(f"unknown group: {group}")
        return spec

    def _automaton(self, group: str) -> Automaton | None:
        if group not in self._automata:
            self._automata[group] = self._load_automaton(group, len(self._patterns))
        return self._automata[group]

    def _pattern_lengths(self) -> list[int]:
        if self._lengths is None:
            self._lengths = [len(text.encode("utf-8")) for _, text in self._patterns]
        return self._lengths

    def _exact_map(self, group: str) -> dict[str, int]:
        table = self._exact.get(group)
        if table is None:
            table = {text: pid for pid, (g, text) in enumerate(self._patterns) if g == group}
            self._exact[group] = table
        return table

    def _find(self, spec: GroupSpec, head: str) -> list[tuple[int, int]]:
        if spec.match == "exact":
            pid = self._exact_map(spec.name).get(head)
            return [] if pid is None else [(len(head.encode("utf-8")), pid)]
        automaton = self._automaton(spec.name)
        if automaton is None:
            return []
        data = head.encode("utf-8")
        if spec.match == "prefix":
            return find_prefix(automaton, data, self._pattern_lengths())
        return find_contains(automaton, data)

    def _first(self, spec: GroupSpec, head: str) -> MatchResult:
        found = self._find(spec, head)
        if not found:
            return _no_match(head)
        end = min(e for e, _ in found)
        best: tuple[int, int] | None = None
        for e, pid in found:
            if e != end:
                continue
            candidate = (self._pattern_items[pid][0], pid)
            if best is None or candidate < best:
                best = candidate
        assert best is not None
        item_id, pid = best
        return MatchResult(
            result=True, item_id=item_id, item=self.items[item_id], head=head, pattern_id=pid
        )

    def _heads(self, spec: GroupSpec, values: object, name: str | None = None) -> list[str]:
        if isinstance(values, str):
            if spec.kind == "map":
                if name is None:
                    raise FormatError(f"group {spec.name} requires a name")
                values = format_map_value(name, values)
            elif name is not None:
                raise FormatError(f"group {spec.name} does not accept a name")
            return [normalize(spec, values)]
        if name is not None:
            raise FormatError("name is only accepted with a single value")
        raw: list[str] = []
        if isinstance(values, Mapping):
            if spec.kind != "map":
                raise FormatError(f"group {spec.name} does not accept a name")
            raw = parse_values(spec, cast(object, values))
        elif isinstance(values, Iterable):
            for v in cast(Iterable[object], values):
                if not isinstance(v, str):
                    raise FormatError(f"{spec.name} values must be strings")
                raw.append(v)
        else:
            raise FormatError(f"{spec.name} values must be a string, list, or object")
        return [normalize(spec, v) for v in raw]

    def match(self, head: str) -> MatchResult:
        spec = self.spec("headers")
        return self._first(spec, normalize(spec, head))

    def match_group(self, group: str, value: str, *, name: str | None = None) -> MatchResult:
        spec = self.spec(group)
        return self._first(spec, self._heads(spec, value, name)[0])

    def match_search(self, search: SearchDefinition) -> MatchResult:
        if not isinstance(cast(object, search), Mapping):
            raise FormatError("search must be an object")
        for group, values in search.items():
            spec = self.spec(group)
            for head in (normalize(spec, v) for v in parse_values(spec, values)):
                result = self._first(spec, head)
                if result.result:
                    return result
        return _no_match()

    def match_html(self, html: str) -> MatchResult:
        spec = self.spec("html")
        for head in html_heads(html):
            result = self._first(spec, normalize(spec, head))
            if result.result:
                return result
        return _no_match()

    def match_all(self, group: str, values: str | Iterable[str] | Mapping[str, str]) -> list[Hit]:
        spec = self.spec(group)
        heads = [normalize(spec, values)] if isinstance(values, str) else self._heads(spec, values)
        pattern_ids: set[int] = set()
        for head in heads:
            pattern_ids.update(pid for _, pid in self._find(spec, head))
        return self.hits_for(pattern_ids)

    def match_tokens(self, group: str, tokens: Iterable[str]) -> dict[int, int]:
        if isinstance(tokens, str):
            raise FormatError("tokens must be a list of strings")
        return {hit.item_id: hit.hits for hit in self.match_all(group, tokens)}

    def scan(self, text: str, group: str) -> list[Occurrence]:
        spec = self.spec(group)
        if spec.match == "exact":
            raise FormatError(f"group {group} uses exact match and cannot be scanned")
        automaton = self._automaton(group)
        if automaton is None:
            return []
        data = (text.lower() if spec.ignore_case else text).encode("utf-8")
        lengths = self._pattern_lengths()
        return [
            Occurrence(pattern_id=pid, start=end - lengths[pid], end=end)
            for end, pid in find_contains(automaton, data)
        ]

    def hits_for(self, pattern_ids: Iterable[int]) -> list[Hit]:
        per_item: dict[int, list[int]] = {}
        for pid in sorted(set(pattern_ids)):
            if not 0 <= pid < len(self._patterns):
                raise FormatError(f"unknown pattern id: {pid}")
            for item_id in self._pattern_items[pid]:
                per_item.setdefault(item_id, []).append(pid)
        hits = [
            Hit(item_id=i, item=self.items[i], hits=len(pids), pattern_ids=tuple(pids))
            for i, pids in per_item.items()
        ]
        hits.sort(key=lambda h: (-h.hits, h.item_id))
        return hits
