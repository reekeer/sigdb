from __future__ import annotations

import json
import struct
import time
from collections import deque
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any, cast

from sigdb.compression import compress_zstd, decompress_zstd
from sigdb.crypto import (
    derive_public_key_hex,
    generate_signing_key_hex,
    sign_hash,
    verify_hash_signature,
)
from sigdb.storage import read_exact
from sigdb.types import (
    Automaton,
    SigDBBuildResult,
    SigDBDatabase,
    SigDBFormatError,
    SigDBIntegrityError,
    SigDBItem,
    SigDBSignatureError,
    SigDBValidationResult,
)
from sigdb.utils.hashing import sha256
from sigdb.utils.varint import decode_varint, encode_varint

MAGIC: bytes = b"SIGT"
VERSION: int = 1

MAX_HEADER_BYTES: int = 65_536
SHA256_SIZE: int = 32
ED25519_SIGNATURE_SIZE: int = 64


def read_sigdb_metadata(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open("rb") as f:
        magic = read_exact(f, 4)
        if magic != MAGIC:
            raise SigDBFormatError("invalid magic")

        version = read_exact(f, 1)[0]
        if version != VERSION:
            raise SigDBFormatError(f"unsupported sigdb version: {version}")

        header_len = struct.unpack(">I", read_exact(f, 4))[0]
        if header_len > MAX_HEADER_BYTES:
            raise SigDBFormatError("HEADER_DATA too large")

        header_raw = read_exact(f, header_len)
        try:
            header_any = json.loads(header_raw)
        except json.JSONDecodeError as e:
            raise SigDBFormatError("invalid HEADER_DATA json") from e
        if not isinstance(header_any, dict):
            raise SigDBFormatError("HEADER_DATA must be an object")
        return cast(dict[str, Any], header_any)


def build_sigdb(
    *,
    rules: object,
    output_path: str | Path,
    metadata: Mapping[str, Any] | None = None,
    signing_key_hex: str | None = None,
    zstd_level: int = 19,
) -> SigDBBuildResult:
    output = Path(output_path)

    items, patterns = _compile_rules(rules)
    automaton = _build_automaton(patterns)

    header_meta: dict[str, Any] = dict(metadata or {})
    header_meta.setdefault("format", "SIGDB-TRIE")
    header_meta.setdefault("version", VERSION)
    header_meta.setdefault("created", int(time.time()))
    header_meta.setdefault("build", date.today().isoformat())
    header_meta.setdefault("items", len(items))
    header_meta.setdefault("patterns", len(patterns))
    header_meta.setdefault("certificate", "ed25519")
    header_meta.setdefault("signature_algorithm", "ed25519")

    generated_signing_key_hex: str | None = None
    if signing_key_hex is None:
        generated_signing_key_hex = generate_signing_key_hex()
        signing_key_hex = generated_signing_key_hex

    public_key_hex = derive_public_key_hex(signing_key_hex)
    if "public_key" in header_meta and header_meta["public_key"] != public_key_hex:
        raise SigDBFormatError("metadata.public_key does not match signing key")
    header_meta.setdefault("public_key", public_key_hex)

    header_data = json.dumps(
        header_meta, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(header_data) > MAX_HEADER_BYTES:
        raise SigDBFormatError("HEADER_DATA too large")

    items_raw = json.dumps(
        [item.to_compact() for item in items],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    automaton_raw = _serialize_automaton(automaton)
    data_hash = sha256(items_raw + automaton_raw)
    signature = sign_hash(data_hash, signing_key_hex=signing_key_hex)

    items_data = compress_zstd(items_raw, level=zstd_level)
    automaton_data = compress_zstd(automaton_raw, level=zstd_level)

    if len(items_data) > 0xFFFFFFFF or len(automaton_data) > 0xFFFFFFFF:
        raise SigDBFormatError("compressed block too large for 32-bit length")

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))

        f.write(struct.pack(">I", len(header_data)))
        f.write(header_data)

        f.write(struct.pack(">I", len(items_data)))
        f.write(items_data)

        f.write(struct.pack(">I", len(automaton_data)))
        f.write(automaton_data)

        f.write(data_hash)
        f.write(signature)

    return SigDBBuildResult(
        output_path=output,
        public_key_hex=public_key_hex,
        signing_key_hex=generated_signing_key_hex,
        data_hash_hex=data_hash.hex(),
        signature_hex=signature.hex(),
        metadata=header_meta,
    )


def load_sigdb(
    path: str | Path,
    *,
    public_key_hex: str | None = None,
    verify_hash: bool = True,
    verify_signature: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> SigDBDatabase:
    header, items_compressed, auto_compressed, stored_hash, signature = _read_container(
        Path(path)
    )

    items_raw = decompress_zstd(items_compressed, max_output_size=max_items_json_size)
    auto_raw = decompress_zstd(auto_compressed, max_output_size=max_automaton_size)

    if verify_hash:
        computed = sha256(items_raw + auto_raw)
        if computed != stored_hash:
            raise SigDBIntegrityError("corrupted database (hash mismatch)")

    if verify_signature:
        pk = public_key_hex or _metadata_public_key(header)
        if pk is None:
            raise SigDBSignatureError("public key not provided and not in metadata")
        verify_hash_signature(stored_hash, signature, public_key_hex=pk)

    items = _parse_items(items_raw)
    automaton = _deserialize_automaton(auto_raw)
    return SigDBDatabase(metadata=header, items=items, automaton=automaton)


def validate_sigdb(
    path: str | Path,
    *,
    public_key_hex: str | None = None,
    verify_hash: bool = True,
    verify_signature: bool = True,
    max_items_json_size: int = 256 * 1024 * 1024,
    max_automaton_size: int = 512 * 1024 * 1024,
) -> SigDBValidationResult:
    errors: list[str] = []
    header: dict[str, Any] | None = None
    stored_hash: bytes | None = None
    computed_hash: bytes | None = None
    signature_ok: bool | None = None
    pk: str | None = None

    try:
        (
            header,
            items_compressed,
            auto_compressed,
            stored_hash,
            signature,
        ) = _read_container(Path(path))
        pk = public_key_hex or _metadata_public_key(header)

        items_raw = decompress_zstd(
            items_compressed, max_output_size=max_items_json_size
        )
        auto_raw = decompress_zstd(auto_compressed, max_output_size=max_automaton_size)

        if verify_hash:
            computed_hash = sha256(items_raw + auto_raw)
            if computed_hash != stored_hash:
                errors.append("hash mismatch")

        if verify_signature:
            if pk is None:
                errors.append("missing public key")
            else:
                try:
                    verify_hash_signature(stored_hash, signature, public_key_hex=pk)
                    signature_ok = True
                except Exception:
                    signature_ok = False
                    errors.append("bad signature")
    except Exception as e:
        errors.append(str(e))

    return SigDBValidationResult(
        ok=(len(errors) == 0),
        errors=errors,
        metadata=header,
        public_key_hex=pk,
        stored_hash_hex=(stored_hash.hex() if stored_hash else None),
        computed_hash_hex=(computed_hash.hex() if computed_hash else None),
        signature_ok=signature_ok,
    )


def _metadata_public_key(metadata: Mapping[str, Any]) -> str | None:
    pk = metadata.get("public_key")
    if isinstance(pk, str) and pk:
        return pk
    return None


def _read_container(path: Path) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes]:
    with path.open("rb") as f:
        magic = read_exact(f, 4)
        if magic != MAGIC:
            raise SigDBFormatError("invalid magic")

        version = read_exact(f, 1)[0]
        if version != VERSION:
            raise SigDBFormatError(f"unsupported sigdb version: {version}")

        header_len = struct.unpack(">I", read_exact(f, 4))[0]
        if header_len > MAX_HEADER_BYTES:
            raise SigDBFormatError("HEADER_DATA too large")

        header_raw = read_exact(f, header_len)
        try:
            header_any = json.loads(header_raw)
        except json.JSONDecodeError as e:
            raise SigDBFormatError("invalid HEADER_DATA json") from e
        if not isinstance(header_any, dict):
            raise SigDBFormatError("HEADER_DATA must be an object")
        header = cast(dict[str, Any], header_any)

        items_len = struct.unpack(">I", read_exact(f, 4))[0]
        items_compressed = read_exact(f, items_len)

        auto_len = struct.unpack(">I", read_exact(f, 4))[0]
        auto_compressed = read_exact(f, auto_len)

        stored_hash = read_exact(f, SHA256_SIZE)
        signature = read_exact(f, ED25519_SIGNATURE_SIZE)

        if f.read(1):
            raise SigDBFormatError("trailing data after signature")

    return header, items_compressed, auto_compressed, stored_hash, signature


def _compile_rules(rules: object) -> tuple[list[SigDBItem], dict[bytes, list[int]]]:
    if not isinstance(rules, Mapping):
        raise SigDBFormatError("rules must be a JSON object")

    # Expected shorthand:
    # { "nginx": {"headers": {"Server": "nginx"}}, ... }
    items: list[SigDBItem] = []
    rules_map = cast(Mapping[object, object], rules)
    for key_any, value_any in rules_map.items():
        if not isinstance(key_any, str) or not key_any:
            raise SigDBFormatError("rule keys must be non-empty strings")
        if not isinstance(value_any, Mapping):
            raise SigDBFormatError("rule value must be an object")
        key = key_any
        value = cast(Mapping[str, Any], value_any)
        headers = _parse_headers(value.get("headers", {}))
        items.append(SigDBItem(key=key, headers=headers))

    patterns: dict[bytes, list[int]] = {}
    for item_id, item in enumerate(items):
        for header_name, needle in item.headers.items():
            # Pattern is "header:needle" and matches as a substring in "header:value".
            pattern = f"{header_name}:{needle}".lower().encode("utf-8")
            patterns.setdefault(pattern, []).append(item_id)

    for pattern, ids in patterns.items():
        if len(ids) > 1:
            patterns[pattern] = sorted(set(ids))

    return items, patterns


def _parse_headers(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SigDBFormatError("headers must be an object")
    m = cast(Mapping[object, object], value)
    out: dict[str, str] = {}
    for k, v in m.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SigDBFormatError("headers keys/values must be strings")
        out[k] = v
    return out


def _parse_items(data: bytes) -> list[SigDBItem]:
    try:
        decoded_any = json.loads(data)
    except json.JSONDecodeError as e:
        raise SigDBFormatError("invalid items json") from e
    if not isinstance(decoded_any, list):
        raise SigDBFormatError("items block must be a JSON array")
    decoded = cast(list[Any], decoded_any)

    items: list[SigDBItem] = []
    for entry in decoded:
        if not isinstance(entry, list):
            raise SigDBFormatError("item must be [key, headers]")
        entry_list = cast(list[object], entry)
        if len(entry_list) != 2:
            raise SigDBFormatError("item must be [key, headers]")
        key_any, headers_any = entry_list[0], entry_list[1]
        if not isinstance(key_any, str) or not key_any:
            raise SigDBFormatError("item key must be a non-empty string")
        headers = _parse_headers(headers_any)
        items.append(SigDBItem(key=key_any, headers=headers))
    return items


def _serialize_automaton(a: Automaton) -> bytes:
    out = bytearray()

    node_count = len(a.children_start)
    edge_count = len(a.labels)
    output_total = len(a.outputs)

    out.extend(encode_varint(node_count))
    out.extend(encode_varint(edge_count))
    out.extend(encode_varint(output_total))

    for i in range(node_count):
        out.extend(encode_varint(a.children_start[i]))
        out.extend(encode_varint(a.children_count[i]))
        out.extend(encode_varint(a.fail[i]))
        out.extend(encode_varint(a.out_start[i]))
        out.extend(encode_varint(a.out_count[i]))

    out.extend(a.labels)
    for nxt in a.next_state:
        out.extend(encode_varint(nxt))
    for out_id in a.outputs:
        out.extend(encode_varint(out_id))

    return bytes(out)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    r = decode_varint(data, pos)
    return r.value, r.offset


def _deserialize_automaton(data: bytes) -> Automaton:
    pos = 0
    node_count, pos = _read_varint(data, pos)
    edge_count, pos = _read_varint(data, pos)
    output_total, pos = _read_varint(data, pos)

    children_start: list[int] = [0] * node_count
    children_count: list[int] = [0] * node_count
    fail: list[int] = [0] * node_count
    out_start: list[int] = [0] * node_count
    out_count: list[int] = [0] * node_count

    for i in range(node_count):
        children_start[i], pos = _read_varint(data, pos)
        children_count[i], pos = _read_varint(data, pos)
        fail[i], pos = _read_varint(data, pos)
        out_start[i], pos = _read_varint(data, pos)
        out_count[i], pos = _read_varint(data, pos)

    labels = data[pos : pos + edge_count]
    pos += edge_count

    next_state: list[int] = [0] * edge_count
    for i in range(edge_count):
        next_state[i], pos = _read_varint(data, pos)

    outputs: list[int] = [0] * output_total
    for i in range(output_total):
        outputs[i], pos = _read_varint(data, pos)

    if pos != len(data):
        raise SigDBFormatError("automaton block has trailing bytes")

    return Automaton(
        children_start=children_start,
        children_count=children_count,
        fail=fail,
        out_start=out_start,
        out_count=out_count,
        labels=labels,
        next_state=next_state,
        outputs=outputs,
    )


def _build_automaton(patterns: Mapping[bytes, list[int]]) -> Automaton:
    trans: list[dict[int, int]] = [{}]
    out: list[list[int]] = [[]]

    for pattern_bytes, item_ids in patterns.items():
        state = 0
        for b in pattern_bytes:
            nxt = trans[state].get(b)
            if nxt is None:
                nxt = len(trans)
                trans[state][b] = nxt
                trans.append({})
                out.append([])
            state = nxt
        out[state].extend(item_ids)

    for i in range(len(out)):
        if len(out[i]) > 1:
            out[i] = sorted(set(out[i]))

    fail: list[int] = [0] * len(trans)
    q: deque[int] = deque()
    for nxt in trans[0].values():
        q.append(nxt)

    while q:
        v = q.popleft()
        for b, u in trans[v].items():
            q.append(u)
            f = fail[v]
            while f != 0 and b not in trans[f]:
                f = fail[f]
            fail[u] = trans[f].get(b, 0)
            if out[fail[u]]:
                out[u].extend(out[fail[u]])
                out[u] = sorted(set(out[u]))

    node_count = len(trans)
    children_start: list[int] = [0] * node_count
    children_count: list[int] = [0] * node_count
    out_start: list[int] = [0] * node_count
    out_count: list[int] = [0] * node_count

    labels = bytearray()
    next_state: list[int] = []
    outputs: list[int] = []

    edge_cursor = 0
    out_cursor = 0
    for i in range(node_count):
        items = sorted(trans[i].items(), key=lambda kv: kv[0])
        children_start[i] = edge_cursor
        children_count[i] = len(items)
        for b, nxt in items:
            labels.append(b)
            next_state.append(nxt)
            edge_cursor += 1

        out_start[i] = out_cursor
        out_count[i] = len(out[i])
        outputs.extend(out[i])
        out_cursor += len(out[i])

    return Automaton(
        children_start=children_start,
        children_count=children_count,
        fail=fail,
        out_start=out_start,
        out_count=out_count,
        labels=bytes(labels),
        next_state=next_state,
        outputs=outputs,
    )
