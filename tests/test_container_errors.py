from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from sigdb.core import build_sigdb, load_sigdb, validate_sigdb
from sigdb.crypto import derive_public_key_hex, generate_signing_key_hex
from sigdb.types import SigDBFormatError

TExc = TypeVar("TExc", bound=BaseException)


def assert_true(value: bool, msg: str) -> None:
    if not value:
        raise AssertionError(msg)


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
    except Exception as e:
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}: {e}") from e
    raise AssertionError(f"expected {exc_type.__name__}, got no exception")


def main() -> None:
    out = Path(__file__).with_name("test_trailing_data.sigdb")
    out_bad = Path(__file__).with_name("test_trailing_data_extra.sigdb")

    rules: dict[str, Any] = {
        "nginx": {"headers": {"Server": "nginx"}},
    }

    metadata: dict[str, Any] = {
        "dataset": "Example",
        "version": "1.0.0",
        "author": "Container Checker",
        "contact": "container@reekeer.hidden",
        "license": "MIT",
        "repository": "https://github.com/reekeer/sigdb",
        "homepage": "https://reekeer.com",
        "description": "Container layout tests",
    }

    signing_key_hex = generate_signing_key_hex()
    public_key_hex = derive_public_key_hex(signing_key_hex)
    metadata["public_key"] = public_key_hex

    build_sigdb(
        rules=rules,
        output_path=out,
        metadata=metadata,
        signing_key_hex=signing_key_hex,
    )

    out_bad.write_bytes(out.read_bytes() + b"\x00")

    assert_raises(
        SigDBFormatError,
        lambda: load_sigdb(out_bad),
        msg_contains="trailing data after signature",
    )

    v = validate_sigdb(out_bad)
    assert_true(not v.ok, "validate_sigdb must fail for trailing data")
    assert_true(len(v.errors) > 0, "validate_sigdb must report errors")
    assert_true(
        any("trailing data after signature" in e for e in v.errors),
        "missing expected error",
    )


if __name__ == "__main__":
    main()
