from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, TypeAlias, TypedDict

SigDBGroupName: TypeAlias = Literal[
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

SigDBGroupMapName: TypeAlias = Literal["headers", "meta"]

SigDBGroupListName: TypeAlias = Literal[
    "js",
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

SigDBStringList: TypeAlias = Sequence[str] | str
SigDBStringMap: TypeAlias = Mapping[str, str]


class SigDBHtmlSpec(TypedDict, total=False):
    tag: str
    attr: str
    value: str


SigDBHtmlPattern: TypeAlias = SigDBHtmlSpec | str
SigDBHtmlList: TypeAlias = Sequence[SigDBHtmlPattern] | SigDBHtmlPattern


class SigDBRuleDefinition(TypedDict, total=False):
    headers: SigDBStringMap
    js: SigDBStringList
    meta: SigDBStringMap
    html: SigDBHtmlList
    script_src: SigDBStringList
    css: SigDBStringList
    url: SigDBStringList
    path: SigDBStringList
    file: SigDBStringList
    dns: SigDBStringList
    subdomain: SigDBStringList
    link: SigDBStringList
    json: SigDBStringList
    api: SigDBStringList
    tls: SigDBStringList
    server: SigDBStringList
    framework: SigDBStringList
    cms: SigDBStringList
    cdn: SigDBStringList


SigDBRules: TypeAlias = Mapping[str, SigDBRuleDefinition]
SigDBSearchDefinition: TypeAlias = SigDBRuleDefinition
