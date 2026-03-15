from __future__ import annotations

from collections.abc import Mapping, Sequence

from sigdb.types import SigDBFormatError

SIGDB_GROUPS: tuple[str, ...] = (
    "headers",
    "js",
    "meta",
    "html",
    "script_src",
)

SIGDB_GROUPS_MAP: frozenset[str] = frozenset(
    {
        "headers",
        "meta",
    }
)


def parse_string_map(value: object, group: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SigDBFormatError(f"{group} must be an object")
    out: dict[str, str] = {}
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise SigDBFormatError(f"{group} keys/values must be strings")
        out[k] = v
    return out


def parse_string_list(value: object, group: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise SigDBFormatError(f"{group} items must be strings")
            out.append(item)
        return out
    raise SigDBFormatError(f"{group} must be a string or list of strings")


def format_map_pattern(group: str, key: str, value: str) -> str:
    key_s = key.strip()
    value_s = value.strip()
    if group == "headers":
        return f"{key_s}:{value_s}"
    return f"{group}:{key_s}:{value_s}"


def format_list_pattern(group: str, value: str) -> str:
    return f"{group}:{value.strip()}"
