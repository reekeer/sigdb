from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from sigdb.types import SigDBFormatError

SIGDB_GROUPS: tuple[str, ...] = (
    "headers",
    "js",
    "meta",
    "html",
    "script_src",
    "css",
    "url",
    "path",
    "file",
    "dns",
    "subdomain",
    "link",
    "json",
    "api",
    "tls",
    "server",
    "framework",
    "cms",
    "cdn",
)

SIGDB_GROUPS_MAP: frozenset[str] = frozenset(
    {
        "headers",
        "meta",
    }
)

_HTML_TAG_RE = re.compile(r"<\s*([a-zA-Z][\w:-]*)\b([^<>]*)>", re.IGNORECASE)
_HTML_ATTR_RE = re.compile(
    r'([a-zA-Z_:][\w:.-]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?'
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


def parse_group_list(value: object, group: str) -> list[str]:
    if group == "html":
        return parse_html_list(value)
    return parse_string_list(value, group)


def parse_html_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [_html_spec_to_value(value)]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
                continue
            if isinstance(item, Mapping):
                out.append(_html_spec_to_value(item))
                continue
            raise SigDBFormatError("html items must be strings or objects")
        return out
    raise SigDBFormatError("html must be a string, object, or list")


def _html_spec_to_value(spec: Mapping[object, object]) -> str:
    allowed = {"tag", "attr", "value"}
    for key in spec.keys():
        if not isinstance(key, str) or key not in allowed:
            raise SigDBFormatError("html spec has invalid keys")

    tag = spec.get("tag")
    attr = spec.get("attr")
    value = spec.get("value")

    if tag is not None and (not isinstance(tag, str) or not tag):
        raise SigDBFormatError("html tag must be a non-empty string")
    if attr is not None and (not isinstance(attr, str) or not attr):
        raise SigDBFormatError("html attr must be a non-empty string")
    if value is not None and not isinstance(value, str):
        raise SigDBFormatError("html value must be a string")
    if value is not None and attr is None:
        raise SigDBFormatError("html value requires attr")
    if tag is None and attr is None and value is None:
        raise SigDBFormatError("html spec must include tag or attr")

    parts: list[str] = []
    if tag is not None:
        parts.extend(("tag", tag))
    if attr is not None:
        parts.extend(("attr", attr))
    if value is not None:
        parts.extend(("value", value))
    return ":".join(parts)


def html_heads(html: str) -> list[str]:
    heads: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value in seen:
            return
        seen.add(value)
        heads.append(value)

    for tag, attrs in _iter_html_tags(html):
        add(format_list_pattern("html", f"tag:{tag}"))
        for name, value in attrs:
            add(format_list_pattern("html", f"tag:{tag}:attr:{name}"))
            if value is not None:
                add(format_list_pattern("html", f"tag:{tag}:attr:{name}:value:{value}"))
            add(format_list_pattern("html", f"attr:{name}"))
            if value is not None:
                add(format_list_pattern("html", f"attr:{name}:value:{value}"))
    return heads


def _iter_html_tags(html: str) -> Iterable[tuple[str, list[tuple[str, str | None]]]]:
    for match in _HTML_TAG_RE.finditer(html):
        tag = match.group(1)
        attrs_raw = match.group(2)
        attrs: list[tuple[str, str | None]] = []
        for attr in _HTML_ATTR_RE.finditer(attrs_raw):
            name = attr.group(1)
            value = attr.group(2) or attr.group(3) or attr.group(4)
            if value is not None:
                value = value.strip()
            attrs.append((name, value))
        yield tag, attrs


def format_map_pattern(group: str, key: str, value: str) -> str:
    key_s = key.strip()
    value_s = value.strip()
    if group == "headers":
        return f"{key_s}:{value_s}"
    return f"{group}:{key_s}:{value_s}"


def format_list_pattern(group: str, value: str) -> str:
    return f"{group}:{value.strip()}"
