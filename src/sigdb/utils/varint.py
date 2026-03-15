from __future__ import annotations

from sigdb.types import DecodeResult, SigDBFormatError


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")

    out = bytearray()
    n = value

    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break

    return bytes(out)


def decode_varint(data: bytes, offset: int, *, max_bytes: int = 10) -> DecodeResult:
    if offset < 0:
        raise SigDBFormatError("negative offset")

    shift = 0
    result = 0
    start = offset

    while True:
        if offset >= len(data):
            raise SigDBFormatError("truncated varint")

        b = data[offset]
        offset += 1

        result |= (b & 0x7F) << shift

        if not (b & 0x80):
            return DecodeResult(result, offset)

        shift += 7
        if offset - start >= max_bytes:
            raise SigDBFormatError("varint too long")
