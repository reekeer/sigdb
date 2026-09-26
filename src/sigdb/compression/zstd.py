from __future__ import annotations

from typing import Any

from sigdb.types import Error, FormatError


def _import_zstd() -> Any:
    try:
        import zstandard as zstd  # type: ignore[import-not-found]
    except ModuleNotFoundError as e:  # pragma: no cover
        raise Error("missing dependency: zstandard") from e
    return zstd


def compress_zstd(data: bytes, *, level: int = 19) -> bytes:
    zstd = _import_zstd()
    cctx = zstd.ZstdCompressor(level=level, write_content_size=True)
    return cctx.compress(data)


def decompress_zstd(data: bytes, *, expected_size: int) -> bytes:
    zstd = _import_zstd()
    try:
        declared: int = zstd.frame_content_size(data)
    except zstd.ZstdError as e:
        raise FormatError("invalid zstd frame") from e
    if declared not in (-1, expected_size):
        raise FormatError("zstd frame size does not match section size")
    try:
        out: bytes = zstd.ZstdDecompressor().decompress(data, max_output_size=max(expected_size, 1))
    except zstd.ZstdError as e:
        raise FormatError("zstd decompression failed") from e
    if len(out) != expected_size:
        raise FormatError("zstd frame size does not match section size")
    return out
