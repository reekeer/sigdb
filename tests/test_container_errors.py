from __future__ import annotations

import struct

from helpers import assert_eq, assert_raises, assert_true

from sigdb import FormatError, IntegrityError, build_bytes, load_bytes
from sigdb.compression import compress_zstd
from sigdb.format.container import parse_container

RULES = {"nginx": {"headers": {"Server": "nginx"}}, "jquery": {"js": "jquery"}}


def _sections_offset(data: bytes) -> int:
    header_len = struct.unpack(">I", data[5:9])[0]
    return 9 + header_len


def _table(data: bytes) -> list[tuple[str, int, int, int]]:
    pos = _sections_offset(data)
    count = struct.unpack(">H", data[pos : pos + 2])[0]
    pos += 2
    out: list[tuple[str, int, int, int]] = []
    for _ in range(count):
        name_len = data[pos]
        name = data[pos + 1 : pos + 1 + name_len].decode()
        pos += 1 + name_len
        raw_size, body_size = struct.unpack(">II", data[pos : pos + 8])
        out.append((name, raw_size, body_size, pos))
        pos += 8 + 32
    return out


def main() -> None:
    data = build_bytes(RULES)
    assert_eq(data[:4], b"SIGT", "magic")
    assert_eq(data[4], 3, "version byte")
    names = [t[0] for t in _table(data)]
    assert_eq(
        names,
        ["index/main", "automaton/main/headers", "automaton/main/js"],
        "section order",
    )

    assert_raises(
        FormatError, lambda: load_bytes(b"NOPE" + b"\x00" * 16), msg_contains="invalid magic"
    )
    for version, text in ((1, "legacy signed format"), (2, "single-automaton format")):
        assert_raises(
            FormatError,
            lambda v=version: load_bytes(b"SIGT" + bytes([v]) + b"\x00" * 16),
            msg_contains=text,
        )
    assert_raises(
        FormatError,
        lambda: load_bytes(b"SIGT\x04" + b"\x00" * 16),
        msg_contains="unsupported sigdb version: 4",
    )
    assert_raises(FormatError, lambda: load_bytes(data + b"\x00"), msg_contains="trailing data")
    assert_raises(FormatError, lambda: load_bytes(data[:-1]), msg_contains="unexpected EOF")
    assert_raises(FormatError, lambda: load_bytes(data[:7]), msg_contains="unexpected EOF")

    name, _, _, pos = _table(data)[0]
    corrupted = bytearray(data)
    corrupted[pos + 8] ^= 0x01
    db = load_bytes(bytes(corrupted))
    assert_raises(
        IntegrityError, lambda: db.index(), msg_contains=f"hash mismatch in section {name}"
    )
    assert_true(
        load_bytes(bytes(corrupted), verify_hash=False).index().items[0].key == "nginx", "no verify"
    )

    lazy = load_bytes(bytes(corrupted))
    assert_eq(lazy.metadata["format"], "SIGDB", "header is readable without touching sections")

    wrong_size = bytearray(data)
    struct.pack_into(">I", wrong_size, pos, _table(data)[0][1] + 1)
    assert_raises(
        FormatError,
        lambda: load_bytes(bytes(wrong_size)).index(),
        msg_contains="zstd frame size does not match section size",
    )

    bomb = compress_zstd(b"a" * 10_000_000, level=1)
    head = bytearray(b"SIGT\x03")
    head += struct.pack(">I", 2) + b"{}"
    head += struct.pack(">H", 1)
    head += bytes([10]) + b"index/main" + struct.pack(">II", 100, len(bomb)) + b"\x00" * 32
    container = parse_container(bytes(head) + bomb)
    assert_raises(FormatError, lambda: container.raw("index/main"), msg_contains="zstd frame size")

    assert_raises(
        FormatError,
        lambda: parse_container(bytes(head) + bomb, max_section_size=10).raw("index/main"),
        msg_contains="exceeds max_section_size",
    )

    garbage = bytearray(b"SIGT\x03") + struct.pack(">I", 2) + b"{}" + struct.pack(">H", 1)
    body = compress_zstd(b"\xff\xff", level=1)
    garbage += bytes([10]) + b"index/main" + struct.pack(">II", 2, len(body)) + b"\x00" * 32 + body
    assert_raises(
        FormatError,
        lambda: load_bytes(bytes(garbage), verify_hash=False).index(),
        msg_contains="invalid index main json",
    )

    only_json = bytearray(b"SIGT\x03") + struct.pack(">I", 2) + b"{}" + struct.pack(">H", 0)
    assert_raises(FormatError, lambda: load_bytes(bytes(only_json)), msg_contains="no indexes")


if __name__ == "__main__":
    main()
