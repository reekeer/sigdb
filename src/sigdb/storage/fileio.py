from __future__ import annotations

from typing import BinaryIO

from sigdb.types import FormatError


def read_exact(f: BinaryIO, size: int) -> bytes:
    data = f.read(size)
    if len(data) != size:
        raise FormatError("unexpected EOF")
    return data
