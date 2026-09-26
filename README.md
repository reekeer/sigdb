# SignatureDB

[![PyPI](https://img.shields.io/pypi/v/sigdb)](https://pypi.org/project/sigdb/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Format](https://img.shields.io/badge/format-SIGT%20v3-lightgrey)](#file-format)

Compiler and loader for `.sigdb` files: rules compiled into per-group Aho-Corasick indexes,
with arbitrary JSON per item and named data sections, packed into one zstd-compressed file.
Used for technology fingerprinting (headers, HTML, scripts) and for library fingerprinting
(feature tokens, source strings).

## Install

```sh
pip install sigdb
```

Requires Python 3.11+ and `zstandard`.

## Usage

```python
from sigdb import build, load

rules = {
    "nginx": {"headers": {"Server": "nginx"}},
    "react@18.2.0/index.js": {
        "data": {"package": "react", "version": "18.2.0", "entry": True},
        "features": ["P:useState", "S:react.element"],
        "strings": ["Minified React error #"],
    },
    "zustand@4.5.0/index.js": {
        "data": {"package": "zustand", "version": "4.5.0"},
        "features": ["P:useState", "K:subscribe"],
    },
}
groups = {
    "features": {},                        # exact, case-sensitive, no trimming
    "strings": {"match": "contains"},      # substring search over full text
}

build(rules, "libs.sigdb", groups=groups, sections={"prints": {"version": 1}})

db = load("libs.sigdb")
db.match("Server: nginx/1.25.3").item.key                  # "nginx"
db.match_tokens("features", ["P:useState", "K:subscribe"])  # {2: 2, 1: 1}
db.match_all("features", ["P:useState"])                   # [Hit(item_id=1, hits=1, ...), ...]
db.scan(source_code, "strings")                            # [Occurrence(pattern_id, start, end)]
db.item("react@18.2.0/index.js").data                      # {"package": "react", ...}
db.items_with_prefix("react@")
db.section("prints")                                       # {"version": 1}
```

Other entry points: `build_bytes`, `load_bytes`, `compile_json`, `compile_dir` (merges every
`*.json` under a directory), `read_rules`, `read_metadata`, `validate`, `Reader`.

## Rules

A rule set is a JSON object: item key to its groups. Keys are any non-empty strings
(`pkg@1.0.0/dist/a.js`, `/`, `@` and `\u0000` included). `data` holds any JSON for the item and
is never matched.

Every group has a config:

| field | values | meaning |
|---|---|---|
| `match` | `prefix`, `contains`, `exact` | value starts with / contains / equals the pattern |
| `ignore_case` | bool | lowercase patterns and queries |
| `trim` | bool | strip surrounding whitespace |
| `kind` | `list`, `map` | `map` groups take `{name: value}` and match `name:value` |

Built-in groups: `headers` (map, contains), `meta` (map, prefix), and `js`, `html`,
`script_src`, `css`, `url`, `path`, `file`, `dns`, `subdomain`, `link`, `json`, `api`, `tls`,
`server`, `framework`, `cms`, `cdn` (list, prefix). All built-ins ignore case and trim.
Custom groups are declared in `groups` and default to exact, case-sensitive, no trim.

A file can hold several indexes (`indexes={"functions": {"rules": ..., "groups": ...}}`,
read with `db.index("functions")`). Plain rules go to the `main` index.

Queries:

- `match`, `match_group`, `match_search`, `match_html` return the first hit: earliest match,
  then lowest item id.
- `match_all` and `match_tokens` return every item with the number of distinct patterns hit.
- `scan` returns every occurrence with UTF-8 byte offsets (of the lowercased text when the
  group ignores case).
- `pattern(id)` and `pattern_count(item_id, group)` give pattern text and totals for weighting.

Builds are reproducible: no timestamps unless `timestamp=` is passed.

## File format

```
"SIGT" | u8 version = 3 | u32 header length | header JSON
       | u16 section count | per section: u8 name length, name, u32 raw size,
         u32 stored size, SHA256(raw) | zstd section bodies
```

Integers are big-endian. Sections are `index/<name>` (JSON: groups, items, patterns,
pattern_items), `automaton/<index>/<group>`, `json/<name>` and `blob/<name>`. Each section
is decompressed and hash-checked on first use. Versions 1 and 2 are rejected; rebuild
them from rules.

## Tests

```sh
pip install -e .
for f in tests/test_*.py; do python "$f"; done
```

`tests/golden/` holds rule sets with expected results and section hashes. After an
intentional change, regenerate them with `python tests/test_golden.py --regen` and review
the diff.

## License

MIT
