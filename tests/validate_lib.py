from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from sigdb.core import (
    SigDBReader,
    build_sigdb,
    load_sigdb,
    read_sigdb_metadata,
    validate_sigdb,
)
from sigdb.types import (
    SigDBFormatError,
    SigDBIntegrityError,
    SigDBItem,
)

TExc = TypeVar("TExc", bound=BaseException)


def assert_true(value: bool, msg: str) -> None:
    if not value:
        raise AssertionError(msg)


def assert_eq(left: object, right: object, msg: str) -> None:
    if left != right:
        raise AssertionError(f"{msg}: {left!r} != {right!r}")


def assert_in(needle: str, haystack: str, msg: str) -> None:
    if needle not in haystack:
        raise AssertionError(f"{msg}: {needle!r} not in {haystack!r}")


def assert_raises(
    exc_type: type[TExc],
    fn: Callable[[], object],
    *,
    msg_contains: str | None = None,
) -> TExc:
    try:
        fn()
    except exc_type as e:
        if msg_contains is not None:
            assert_in(msg_contains, str(e), "exception message mismatch")
        return e
    except Exception as e:  # pragma: no cover
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}: {e}") from e
    raise AssertionError(f"expected {exc_type.__name__}, got no exception")


def _read_container_offsets(path: Path) -> tuple[int, int]:
    with path.open("rb") as f:
        magic = f.read(4)
        if magic != b"SIGT":
            raise AssertionError("unexpected magic in test file")
        version = f.read(1)
        if version != b"\x02":
            raise AssertionError("unexpected version in test file")

        header_len = struct.unpack(">I", f.read(4))[0]
        f.seek(header_len, 1)

        items_len = struct.unpack(">I", f.read(4))[0]
        f.seek(items_len, 1)

        auto_len = struct.unpack(">I", f.read(4))[0]
        f.seek(auto_len, 1)

        return f.tell(), 32


def main() -> None:
    out = Path(__file__).with_name("test_validity.sigdb")
    out_corrupt = Path(__file__).with_name("test_validity_corrupt.sigdb")

    rules: dict[str, Any] = {
        "nginx": {"headers": {"Server": "nginx"}},
        "cloudflare": {"headers": {"Server": "cloudflare"}},
    }

    metadata: dict[str, Any] = {
        "dataset": "Example",
        "version": "1.0.0",
        "author": "Validity Checker",
        "contact": "validity@reekeer.hidden",
        "license": "MIT",
        "repository": "https://github.com/reekeer/sigdb",
        "homepage": "https://reekeer.com",
        "description": "Example .sigdb dataset to test validity",
    }

    result = build_sigdb(rules=rules, output_path=out, metadata=metadata)
    assert_eq(len(result.data_hash_hex), 64, "data hash length mismatch")

    meta = read_sigdb_metadata(out)
    for k, v in metadata.items():
        assert_eq(meta.get(k), v, f"metadata mismatch for {k}")
    assert_eq(meta.get("format"), "SIGDB-TRIE", "missing default format")
    for k in ("certificate", "signature_algorithm", "public_key"):
        assert_true(k not in meta, f"unexpected signing metadata key {k}")

    v = validate_sigdb(out)
    assert_true(v.ok, f"validate_sigdb failed: {v.errors}")
    assert_eq(v.errors, [], "validate_sigdb errors not empty")
    assert_true(
        v.stored_hash_hex is not None and v.computed_hash_hex is not None,
        "hash hex values missing",
    )
    assert_eq(v.stored_hash_hex, v.computed_hash_hex, "hash mismatch in validator")

    reader = SigDBReader(out)
    db = reader.load()
    expected_items = [
        SigDBItem(key="nginx", headers={"Server": "nginx"}),
        SigDBItem(key="cloudflare", headers={"Server": "cloudflare"}),
    ]
    assert_eq(db.items, expected_items, "loaded items mismatch")

    assert_raises(
        SigDBFormatError,
        lambda: build_sigdb(rules=123, output_path=out),
        msg_contains="rules must be a JSON object",
    )

    bad_file = Path(__file__).with_name("test_invalid_magic.sigdb")
    bad_file.write_bytes(b"NOPE" + b"\x00" * 16)
    assert_raises(
        SigDBFormatError,
        lambda: read_sigdb_metadata(bad_file),
        msg_contains="invalid magic",
    )
    bad_file.write_bytes(b"SIGT\x01" + b"\x00" * 16)
    assert_raises(
        SigDBFormatError,
        lambda: read_sigdb_metadata(bad_file),
        msg_contains="legacy signed format",
    )
    assert_raises(
        SigDBFormatError,
        lambda: load_sigdb(bad_file),
        msg_contains="legacy signed format",
    )
    bad_file.write_bytes(b"SIGT\x03" + b"\x00" * 16)
    assert_raises(
        SigDBFormatError,
        lambda: load_sigdb(bad_file),
        msg_contains="unsupported sigdb version: 3",
    )
    bad_file.unlink()

    raw = out.read_bytes()
    data_hash_off, data_hash_len = _read_container_offsets(out)
    if data_hash_off + data_hash_len != len(raw):
        raise AssertionError("unexpected container layout in test file")
    corrupted = bytearray(raw)
    corrupted[data_hash_off] ^= 0x01
    assert_eq(
        len(corrupted[data_hash_off : data_hash_off + data_hash_len]),
        32,
        "bad hash size",
    )
    out_corrupt.write_bytes(bytes(corrupted))
    assert_raises(
        SigDBIntegrityError,
        lambda: load_sigdb(out_corrupt),
        msg_contains="hash mismatch",
    )
    load_sigdb(out_corrupt, verify_hash=False)

    out.unlink()
    out_corrupt.unlink()


if __name__ == "__main__":
    main()
