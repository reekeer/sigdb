from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import TypeVar

from sigdb.crypto import (
    derive_public_key_hex,
    generate_signing_key_hex,
    sign_hash,
    verify_hash_signature,
)
from sigdb.types import SigDBSignatureError

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


def main() -> None:
    signing_key_hex = generate_signing_key_hex()
    assert_eq(len(signing_key_hex), 64, "signing_key_hex length mismatch")
    assert_eq(len(bytes.fromhex(signing_key_hex)), 32, "signing_key_hex bytes mismatch")

    public_key_hex = derive_public_key_hex(signing_key_hex)
    assert_eq(len(public_key_hex), 64, "public_key_hex length mismatch")
    assert_eq(len(bytes.fromhex(public_key_hex)), 32, "public_key_hex bytes mismatch")

    data_hash = hashlib.sha256(b"sigdb").digest()
    signature = sign_hash(data_hash, signing_key_hex=signing_key_hex)
    assert_eq(len(signature), 64, "signature length mismatch")

    verify_hash_signature(data_hash, signature, public_key_hex=public_key_hex)

    assert_raises(
        SigDBSignatureError,
        lambda: verify_hash_signature(data_hash, signature, public_key_hex="0"),
        msg_contains="invalid public key hex",
    )

    other_pk = derive_public_key_hex(generate_signing_key_hex())
    assert_true(other_pk != public_key_hex, "generated public keys must differ")
    assert_raises(
        SigDBSignatureError,
        lambda: verify_hash_signature(data_hash, signature, public_key_hex=other_pk),
        msg_contains="invalid signature",
    )


if __name__ == "__main__":
    main()
