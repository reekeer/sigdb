from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

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
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}: {e}") from e
    raise AssertionError(f"expected {exc_type.__name__}, got no exception")
