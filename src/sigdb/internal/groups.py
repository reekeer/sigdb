from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from sigdb.types import FormatError, GroupSpec

BUILTIN_GROUPS: tuple[str, ...] = (
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

BUILTIN_MAP_GROUPS: frozenset[str] = frozenset({"headers", "meta"})
RESERVED_RULE_KEYS: frozenset[str] = frozenset({"data"})

_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_KINDS = ("list", "map")
_MODES = ("prefix", "contains", "exact")
_CONFIG_KEYS = frozenset({"kind", "match", "ignore_case", "trim"})

_HTML_TAG_RE = re.compile(r"<\s*([a-zA-Z][\w:-]*)\b([^<>]*)>", re.IGNORECASE)
_HTML_ATTR_RE = re.compile(
    r'([a-zA-Z_:][\w:.-]*)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?'
)


def check_name(name: object, what: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise FormatError(f"invalid {what} name: {name!r}")
    return name


def builtin_spec(name: str) -> GroupSpec:
    kind = "map" if name in BUILTIN_MAP_GROUPS else "list"
    match = "contains" if name == "headers" else "prefix"
    return GroupSpec(name=name, kind=kind, match=match, ignore_case=True, trim=True)


def resolve_groups(config: object) -> dict[str, GroupSpec]:
    specs = {name: builtin_spec(name) for name in BUILTIN_GROUPS}
    if config is None:
        return specs
    if not isinstance(config, Mapping):
        raise FormatError("groups must be an object")
    for name_any, cfg_any in cast(Mapping[object, object], config).items():
        name = check_name(name_any, "group")
        if name in RESERVED_RULE_KEYS:
            raise FormatError(f"group name is reserved: {name}")
        if not isinstance(cfg_any, Mapping):
            raise FormatError(f"group {name} config must be an object")
        cfg = cast(Mapping[str, object], cfg_any)
        unknown = set(cfg) - _CONFIG_KEYS
        if unknown:
            raise FormatError(f"group {name} has unknown config keys: {sorted(unknown)}")
        if name in specs:
            base = specs[name]
        else:
            base = GroupSpec(name=name, kind="list", match="exact", ignore_case=False, trim=False)
        specs[name] = spec_from_json(name, {**base.to_json(), **cfg})
    return specs


def spec_from_json(name: str, raw: object) -> GroupSpec:
    if not isinstance(raw, Mapping):
        raise FormatError(f"group {name} config must be an object")
    cfg = cast(Mapping[str, object], raw)
    kind = cfg.get("kind")
    match = cfg.get("match")
    ignore_case = cfg.get("ignore_case")
    trim = cfg.get("trim")
    if kind not in _KINDS:
        raise FormatError(f"group {name}: kind must be one of {list(_KINDS)}")
    if match not in _MODES:
        raise FormatError(f"group {name}: match must be one of {list(_MODES)}")
    if not isinstance(ignore_case, bool) or not isinstance(trim, bool):
        raise FormatError(f"group {name}: ignore_case and trim must be booleans")
    return GroupSpec(
        name=name,
        kind=cast(Any, kind),
        match=cast(Any, match),
        ignore_case=ignore_case,
        trim=trim,
    )


def normalize(spec: GroupSpec, value: str) -> str:
    if spec.trim:
        if spec.kind == "map":
            i = value.find(":")
            value = value.strip() if i == -1 else f"{value[:i].strip()}:{value[i + 1 :].strip()}"
        else:
            value = value.strip()
    if spec.ignore_case:
        value = value.lower()
    return value


def format_map_value(name: str, value: str) -> str:
    return f"{name}:{value}"


def parse_string_map(value: object, group: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise FormatError(f"{group} must be an object")
    out: dict[str, str] = {}
    for k, v in cast(Mapping[object, object], value).items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise FormatError(f"{group} keys/values must be strings")
        out[k] = v
    return out


def parse_string_list(value: object, group: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out: list[str] = []
        for item in cast(Sequence[object], value):
            if not isinstance(item, str):
                raise FormatError(f"{group} items must be strings")
            out.append(item)
        return out
    raise FormatError(f"{group} must be a string or list of strings")


def parse_html_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [_html_spec_to_value(cast(Mapping[object, object], value))]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out: list[str] = []
        for item in cast(Sequence[object], value):
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, Mapping):
                out.append(_html_spec_to_value(cast(Mapping[object, object], item)))
            else:
                raise FormatError("html items must be strings or objects")
        return out
    raise FormatError("html must be a string, object, or list")


def parse_values(spec: GroupSpec, value: object) -> list[str]:
    if spec.kind == "map":
        pairs = parse_string_map(value, spec.name)
        return [format_map_value(k, v) for k, v in pairs.items()]
    if spec.name == "html":
        return parse_html_list(value)
    return parse_string_list(value, spec.name)


def _html_spec_to_value(spec: Mapping[object, object]) -> str:
    allowed = {"tag", "attr", "value"}
    for key in spec:
        if not isinstance(key, str) or key not in allowed:
            raise FormatError("html spec has invalid keys")

    tag = spec.get("tag")
    attr = spec.get("attr")
    value = spec.get("value")

    if tag is not None and (not isinstance(tag, str) or not tag):
        raise FormatError("html tag must be a non-empty string")
    if attr is not None and (not isinstance(attr, str) or not attr):
        raise FormatError("html attr must be a non-empty string")
    if value is not None and not isinstance(value, str):
        raise FormatError("html value must be a string")
    if value is not None and attr is None:
        raise FormatError("html value requires attr")
    if tag is None and attr is None and value is None:
        raise FormatError("html spec must include tag or attr")

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
        if value not in seen:
            seen.add(value)
            heads.append(value)

    for tag, attrs in _iter_html_tags(html):
        add(f"tag:{tag}")
        for name, value in attrs:
            add(f"tag:{tag}:attr:{name}")
            if value is not None:
                add(f"tag:{tag}:attr:{name}:value:{value}")
            add(f"attr:{name}")
            if value is not None:
                add(f"attr:{name}:value:{value}")
    return heads


def _iter_html_tags(html: str) -> Iterable[tuple[str, list[tuple[str, str | None]]]]:
    for match in _HTML_TAG_RE.finditer(html):
        tag = match.group(1)
        attrs: list[tuple[str, str | None]] = []
        for attr in _HTML_ATTR_RE.finditer(match.group(2)):
            value = attr.group(2) or attr.group(3) or attr.group(4)
            attrs.append((attr.group(1), value.strip() if value is not None else None))
        yield tag, attrs
