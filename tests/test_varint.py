from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from sigdb.types import SigDBFormatError
from sigdb.utils.varint import decode_varint, encode_varint

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
    except Exception as e:
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(e).__name__}: {e}"
        ) from e
    raise AssertionError(f"expected {exc_type.__name__}, got no exception")


def main() -> None:
    for value in [0, 1, 2, 10, 127, 128, 255, 300, 16_384, 2**32, 2**63 - 1]:
        encoded = encode_varint(value)
        decoded = decode_varint(encoded, 0)
        assert_eq(decoded.value, value, "varint roundtrip mismatch")
        assert_eq(decoded.offset, len(encoded), "varint decode offset mismatch")

    assert_raises(
        ValueError,
        lambda: encode_varint(-1),
        msg_contains="negative",
    )
    assert_raises(
        SigDBFormatError,
        lambda: decode_varint(b"", 0),
        msg_contains="truncated varint",
    )
    assert_raises(
        SigDBFormatError,
        lambda: decode_varint(b"\x80", 0),
        msg_contains="truncated varint",
    )
    assert_raises(
        SigDBFormatError,
        lambda: decode_varint(b"\x80" * 10, 0),
        msg_contains="varint too long",
    )
    assert_raises(
        SigDBFormatError,
        lambda: decode_varint(b"\x00", -1),
        msg_contains="negative offset",
    )

    encoded = encode_varint(300)
    decoded = decode_varint(encoded, 1)
    assert_true(decoded.value != 300, "decode must respect offset")


if __name__ == "__main__":
    main()

