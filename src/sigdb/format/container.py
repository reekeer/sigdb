from __future__ import annotations

import json
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, cast

from sigdb.compression import compress_zstd, decompress_zstd
from sigdb.storage import read_exact
from sigdb.types import FormatError, IntegrityError
from sigdb.utils.hashing import sha256

MAGIC: bytes = b"SIGT"
VERSION: int = 3

MAX_HEADER_BYTES: int = 65_536
MAX_SECTIONS: int = 65_535
MAX_SECTION_NAME_BYTES: int = 255
SHA256_SIZE: int = 32
DEFAULT_MAX_SECTION_SIZE: int = 512 * 1024 * 1024

_LEGACY_VERSIONS: dict[int, str] = {
    1: "legacy signed format",
    2: "single-automaton format",
}


def check_version(version: int) -> None:
    if version in _LEGACY_VERSIONS:
        raise FormatError(
            f"unsupported sigdb version: {version} ({_LEGACY_VERSIONS[version]}); "
            "rebuild the database from rules"
        )
    if version != VERSION:
        raise FormatError(f"unsupported sigdb version: {version}")


def dump_json(value: Any) -> bytes:
    try:
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        return text.encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as e:
        raise FormatError(f"value is not serializable as JSON: {e}") from e


def parse_json(data: bytes, what: str) -> Any:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise FormatError(f"invalid {what} json") from e


def _parse_header(raw: bytes) -> dict[str, Any]:
    header = parse_json(raw, "HEADER_DATA")
    if not isinstance(header, dict):
        raise FormatError("HEADER_DATA must be an object")
    return cast(dict[str, Any], header)


def write_container(
    header: Mapping[str, Any],
    sections: Sequence[tuple[str, bytes]],
    *,
    zstd_level: int,
) -> tuple[bytes, dict[str, str]]:
    header_raw = dump_json(dict(header))
    if len(header_raw) > MAX_HEADER_BYTES:
        raise FormatError("HEADER_DATA too large")
    if len(sections) > MAX_SECTIONS:
        raise FormatError("too many sections")

    table = bytearray()
    bodies: list[bytes] = []
    hashes: dict[str, str] = {}
    for name, raw in sections:
        name_raw = name.encode("utf-8")
        if not name_raw or len(name_raw) > MAX_SECTION_NAME_BYTES:
            raise FormatError(f"invalid section name: {name!r}")
        if name in hashes:
            raise FormatError(f"duplicate section: {name}")
        body = compress_zstd(raw, level=zstd_level)
        if len(raw) > 0xFFFFFFFF or len(body) > 0xFFFFFFFF:
            raise FormatError(f"section {name} too large for 32-bit length")
        digest = sha256(raw)
        hashes[name] = digest.hex()
        table += bytes([len(name_raw)]) + name_raw
        table += struct.pack(">II", len(raw), len(body)) + digest
        bodies.append(body)

    out = bytearray(MAGIC)
    out.append(VERSION)
    out += struct.pack(">I", len(header_raw)) + header_raw
    out += struct.pack(">H", len(sections)) + table
    for body in bodies:
        out += body
    return bytes(out), hashes


@dataclass(frozen=True, slots=True)
class SectionEntry:
    name: str
    raw_size: int
    digest: bytes
    body: memoryview


class Container:
    __slots__ = ("_cache", "_entries", "_max_section_size", "_verify_hash", "header")

    def __init__(
        self,
        header: dict[str, Any],
        entries: dict[str, SectionEntry],
        *,
        verify_hash: bool,
        max_section_size: int,
    ) -> None:
        self.header = header
        self._entries = entries
        self._verify_hash = verify_hash
        self._max_section_size = max_section_size
        self._cache: dict[str, bytes] = {}

    @property
    def names(self) -> list[str]:
        return list(self._entries)

    def digests(self) -> dict[str, str]:
        return {name: e.digest.hex() for name, e in self._entries.items()}

    def __contains__(self, name: str) -> bool:
        return name in self._entries

    def raw(self, name: str) -> bytes:
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        entry = self._entries.get(name)
        if entry is None:
            raise FormatError(f"missing section: {name}")
        if entry.raw_size > self._max_section_size:
            raise FormatError(f"section {name} exceeds max_section_size")
        try:
            raw = decompress_zstd(bytes(entry.body), expected_size=entry.raw_size)
        except FormatError as e:
            raise FormatError(f"section {name}: {e}") from e
        if self._verify_hash and sha256(raw) != entry.digest:
            raise IntegrityError(f"corrupted database (hash mismatch in section {name})")
        self._cache[name] = raw
        return raw


def parse_container(
    data: bytes,
    *,
    verify_hash: bool = True,
    max_section_size: int = DEFAULT_MAX_SECTION_SIZE,
) -> Container:
    view = memoryview(data)
    pos = 0

    def take(n: int) -> memoryview:
        nonlocal pos
        if pos + n > len(view):
            raise FormatError("unexpected EOF")
        chunk = view[pos : pos + n]
        pos += n
        return chunk

    if bytes(take(4)) != MAGIC:
        raise FormatError("invalid magic")
    check_version(take(1)[0])
    header_len = struct.unpack(">I", take(4))[0]
    if header_len > MAX_HEADER_BYTES:
        raise FormatError("HEADER_DATA too large")
    header = _parse_header(bytes(take(header_len)))

    count = struct.unpack(">H", take(2))[0]
    table: list[tuple[str, int, int, bytes]] = []
    seen: set[str] = set()
    for _ in range(count):
        name_len = take(1)[0]
        try:
            name = bytes(take(name_len)).decode("utf-8")
        except UnicodeDecodeError as e:
            raise FormatError("invalid section name") from e
        if not name or name in seen:
            raise FormatError(f"invalid or duplicate section name: {name!r}")
        seen.add(name)
        raw_size, body_size = struct.unpack(">II", take(8))
        table.append((name, raw_size, body_size, bytes(take(SHA256_SIZE))))

    entries: dict[str, SectionEntry] = {}
    for name, raw_size, body_size, digest in table:
        entries[name] = SectionEntry(name, raw_size, digest, take(body_size))

    if pos != len(view):
        raise FormatError("trailing data after last section")

    return Container(
        header,
        entries,
        verify_hash=verify_hash,
        max_section_size=max_section_size,
    )


def read_header(f: BinaryIO) -> dict[str, Any]:
    if read_exact(f, 4) != MAGIC:
        raise FormatError("invalid magic")
    check_version(read_exact(f, 1)[0])
    header_len = struct.unpack(">I", read_exact(f, 4))[0]
    if header_len > MAX_HEADER_BYTES:
        raise FormatError("HEADER_DATA too large")
    return _parse_header(read_exact(f, header_len))


def read_header_file(path: str | Path) -> dict[str, Any]:
    with Path(path).open("rb") as f:
        return read_header(f)
