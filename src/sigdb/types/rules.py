from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, TypeAlias, TypedDict

from sigdb.types.models import GroupKind, MatchMode

BuiltinGroupName: TypeAlias = Literal[
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
]

StringList: TypeAlias = Sequence[str] | str
StringMap: TypeAlias = Mapping[str, str]


class HtmlSpec(TypedDict, total=False):
    tag: str
    attr: str
    value: str


HtmlPattern: TypeAlias = HtmlSpec | str
HtmlList: TypeAlias = Sequence[HtmlPattern] | HtmlPattern


class GroupConfig(TypedDict, total=False):
    kind: GroupKind
    match: MatchMode
    ignore_case: bool
    trim: bool


class RuleDefinition(TypedDict, total=False):
    data: Any
    headers: StringMap
    js: StringList
    meta: StringMap
    html: HtmlList
    script_src: StringList
    css: StringList
    url: StringList
    path: StringList
    file: StringList
    dns: StringList
    subdomain: StringList
    link: StringList
    json: StringList
    api: StringList
    tls: StringList
    server: StringList
    framework: StringList
    cms: StringList
    cdn: StringList


Rules: TypeAlias = Mapping[str, Mapping[str, Any]]
RulesInput: TypeAlias = Rules | Sequence[Rules]
SearchDefinition: TypeAlias = Mapping[str, Any]


class IndexSpec(TypedDict, total=False):
    rules: RulesInput
    groups: Mapping[str, GroupConfig]
