from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class DecodeResult:
    value: int
    offset: int


@dataclass(frozen=True, slots=True)
class SigDBItem:
    key: str
    headers: dict[str, str]

    def to_compact(self) -> list[object]:
        # Compact JSON representation: [key, headers]
        return [self.key, self.headers]


@dataclass(frozen=True, slots=True)
class SigDBBuildResult:
    output_path: Path
    public_key_hex: str
    signing_key_hex: str | None
    data_hash_hex: str
    signature_hex: str
    metadata: dict[str, Any]


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


@dataclass(frozen=True, slots=True)
class SigDBDatabase:
    metadata: dict[str, Any]
    items: list[SigDBItem]
    automaton: Automaton


@dataclass(frozen=True, slots=True)
class SigDBValidationResult:
    ok: bool
    errors: list[str]
    metadata: dict[str, Any] | None
    public_key_hex: str | None
    stored_hash_hex: str | None
    computed_hash_hex: str | None
    signature_ok: bool | None
