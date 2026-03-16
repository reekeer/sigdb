from __future__ import annotations

from sigdb.types import SigDBError, SigDBSignatureError


def _import_nacl():
    try:
        from nacl.exceptions import BadSignatureError  # type: ignore[import-not-found]
        from nacl.signing import SigningKey, VerifyKey  # type: ignore[import-not-found]
    except ModuleNotFoundError as e:  # pragma: no cover
        raise SigDBError("missing dependency: pynacl") from e
    return SigningKey, VerifyKey, BadSignatureError


def generate_signing_key_hex() -> str:
    SigningKey, _VerifyKey, _BadSignatureError = _import_nacl()
    return SigningKey.generate().encode().hex()


def _parse_signing_key_hex(signing_key_hex: str):
    SigningKey, _VerifyKey, _BadSignatureError = _import_nacl()
    raw = bytes.fromhex(signing_key_hex)
    if len(raw) == 32:
        return SigningKey(raw)
    if len(raw) == 64:
        return SigningKey(raw[:32])
    raise ValueError("signing key must be 32-byte seed or 64-byte private key")


def derive_public_key_hex(signing_key_hex: str) -> str:
    return _parse_signing_key_hex(signing_key_hex).verify_key.encode().hex()


def sign_hash(data_hash: bytes, *, signing_key_hex: str) -> bytes:
    key = _parse_signing_key_hex(signing_key_hex)
    return key.sign(data_hash).signature


def verify_hash_signature(
    data_hash: bytes, signature: bytes, *, public_key_hex: str
) -> None:
    _SigningKey, VerifyKey, BadSignatureError = _import_nacl()
    try:
        verify = VerifyKey(bytes.fromhex(public_key_hex))
    except ValueError as e:
        raise SigDBSignatureError("invalid public key hex") from e

    try:
        verify.verify(data_hash, signature)
    except BadSignatureError as e:
        raise SigDBSignatureError("invalid signature") from e
