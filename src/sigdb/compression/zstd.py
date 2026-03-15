from __future__ import annotations

from sigdb.types import SigDBError


def _import_zstd():
    try:
        import zstandard as zstd  # type: ignore[import-not-found]
    except ModuleNotFoundError as e:  # pragma: no cover
        raise SigDBError("missing dependency: zstandard") from e
    return zstd


def compress_zstd(data: bytes, *, level: int = 19) -> bytes:
    zstd = _import_zstd()
    cctx = zstd.ZstdCompressor(level=level, write_content_size=True)
    return cctx.compress(data)


def decompress_zstd(data: bytes, *, max_output_size: int) -> bytes:
    zstd = _import_zstd()
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data, max_output_size=max_output_size)
