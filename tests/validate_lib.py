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
from sigdb.crypto import derive_public_key_hex, generate_signing_key_hex
from sigdb.types import (
    SigDBFormatError,
    SigDBIntegrityError,
    SigDBItem,
    SigDBSignatureError,
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
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(e).__name__}: {e}"
        ) from e
    raise AssertionError(f"expected {exc_type.__name__}, got no exception")


def _read_container_offsets(path: Path) -> tuple[int, int, int]:
    with path.open("rb") as f:
        magic = f.read(4)
        if magic != b"SIGT":
            raise AssertionError("unexpected magic in test file")
        version = f.read(1)
        if version != b"\x01":
            raise AssertionError("unexpected version in test file")

        header_len = struct.unpack(">I", f.read(4))[0]
        f.seek(header_len, 1)

        items_len = struct.unpack(">I", f.read(4))[0]
        f.seek(items_len, 1)

        auto_len = struct.unpack(">I", f.read(4))[0]
        f.seek(auto_len, 1)

        data_hash_off = f.tell()
        data_hash_len = 32
        sig_off = data_hash_off + data_hash_len
        return data_hash_off, data_hash_len, sig_off


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

    signing_key_hex = generate_signing_key_hex()
    public_key_hex = derive_public_key_hex(signing_key_hex)
    metadata["public_key"] = public_key_hex

    result = build_sigdb(
        rules=rules,
        output_path=out,
        metadata=metadata,
        signing_key_hex=signing_key_hex,
    )
    assert_eq(result.public_key_hex, public_key_hex, "public key mismatch")

    meta = read_sigdb_metadata(out)
    for k, v in metadata.items():
        assert_eq(meta.get(k), v, f"metadata mismatch for {k}")
    assert_eq(meta.get("format"), "SIGDB-TRIE", "missing default format")
    assert_eq(meta.get("certificate"), "ed25519", "missing default certificate")
    assert_eq(meta.get("signature_algorithm"), "ed25519", "missing signature algorithm")

    v = validate_sigdb(out)
    assert_true(v.ok, f"validate_sigdb failed: {v.errors}")
    assert_eq(v.errors, [], "validate_sigdb errors not empty")
    assert_eq(v.signature_ok, True, "signature_ok must be True")
    assert_true(
        v.stored_hash_hex is not None and v.computed_hash_hex is not None,
        "hash hex values missing",
    )
    assert_eq(v.stored_hash_hex, v.computed_hash_hex, "hash mismatch in validator")

    reader = SigDBReader(out)
    db = reader.load(public_key_hex=public_key_hex)
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

    bad_meta = dict(metadata)
    bad_meta["public_key"] = "00" * 32
    assert_raises(
        SigDBFormatError,
        lambda: build_sigdb(
            rules=rules,
            output_path=out,
            metadata=bad_meta,
            signing_key_hex=signing_key_hex,
        ),
        msg_contains="metadata.public_key does not match signing key",
    )

    bad_file = Path(__file__).with_name("test_invalid_magic.sigdb")
    bad_file.write_bytes(b"NOPE" + b"\x00" * 16)
    assert_raises(
        SigDBFormatError,
        lambda: read_sigdb_metadata(bad_file),
        msg_contains="invalid magic",
    )
    bad_file.unlink()

    raw = out.read_bytes()
    data_hash_off, data_hash_len, sig_off = _read_container_offsets(out)
    if sig_off + 64 != len(raw):
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
        lambda: load_sigdb(out_corrupt, public_key_hex=public_key_hex),
        msg_contains="hash mismatch",
    )

    assert_raises(
        SigDBSignatureError,
        lambda: load_sigdb(out, public_key_hex="00" * 32, verify_hash=False),
        msg_contains="invalid signature",
    )

    out.unlink()
    out_corrupt.unlink()


if __name__ == "__main__":
    main()
