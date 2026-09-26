from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

MatchMode = Literal["prefix", "contains", "exact"]
GroupKind = Literal["list", "map"]


@dataclass(frozen=True, slots=True)
class DecodeResult:
    value: int
    offset: int


@dataclass(frozen=True, slots=True)
class Item:
    key: str
    data: Any = None


@dataclass(frozen=True, slots=True)
class GroupSpec:
    name: str
    kind: GroupKind
    match: MatchMode
    ignore_case: bool
    trim: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "match": self.match,
            "ignore_case": self.ignore_case,
            "trim": self.trim,
        }


@dataclass(frozen=True, slots=True)
class Pattern:
    id: int
    group: str
    text: str
    item_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Automaton:
    children_start: list[int]
    children_count: list[int]
    fail: list[int]
    out_start: list[int]
    out_count: list[int]
    labels: bytes
    next_state: list[int]
    outputs: list[int]

    def transition(self, state: int, b: int) -> int:
        start = self.children_start[state]
        count = self.children_count[state]
        if count == 0:
            return -1

        lo = 0
        hi = count
        labels = self.labels
        while lo < hi:
            mid = (lo + hi) >> 1
            lb = labels[start + mid]
            if lb < b:
                lo = mid + 1
            elif lb > b:
                hi = mid
            else:
                return self.next_state[start + mid]
        return -1

    def outputs_of(self, state: int) -> list[int]:
        start = self.out_start[state]
        return self.outputs[start : start + self.out_count[state]]


@dataclass(frozen=True, slots=True)
class MatchResult:
    result: bool
    item_id: int | None
    item: Item | None
    head: str
    pattern_id: int | None = None


@dataclass(frozen=True, slots=True)
class Hit:
    item_id: int
    item: Item
    hits: int
    pattern_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Occurrence:
    pattern_id: int
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class BuildResult:
    output_path: Path
    size: int
    metadata: dict[str, Any]
    sections: dict[str, str]


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    errors: list[str]
    metadata: dict[str, Any] | None
    sections: dict[str, str] | None
