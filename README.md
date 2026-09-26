# SignatureDB

[![PyPI](https://img.shields.io/pypi/v/sigdb)](https://pypi.org/project/sigdb/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)
[![Format](https://img.shields.io/badge/format-SIGT%20v2-lightgrey)](#file-format)

Compiler and loader for `.sigdb` files: technology fingerprint rules compiled into a single
Aho-Corasick automaton for fast matching of HTTP headers, HTML, scripts and other signals.

## Install

```sh
pip install sigdb
```

Requires Python 3.11+ and `zstandard`.

## Usage

```python
from sigdb.core import SigDBReader, build_sigdb

rules = {
    "nginx": {"headers": {"Server": "nginx"}},
    "wordpress": {
        "meta": {"generator": "WordPress"},
        "html": {"tag": "link", "attr": "rel", "value": "https://api.w.org/"},
    },
    "jquery": {"js": "jquery"},
}

build_sigdb(rules=rules, output_path="tech.sigdb", metadata={"dataset": "example"})

db = SigDBReader("tech.sigdb")
db.match("Server: nginx/1.25.3").item.key                         # "nginx"
db.match_group("meta", "WordPress 6.4", name="generator").item.key  # "wordpress"
db.match_html('<link rel="https://api.w.org/" href="/wp-json/">').item.key  # "wordpress"
db.match_search({"js": ["jquery-3.7.1.min.js"]}).item.key          # "jquery"
```

Rules can also be compiled straight from a JSON file with `compile_sigdb_json`.

## Rules

A rule set is a JSON object: technology name to groups of patterns.

- Map groups (`name -> value`): `headers`, `meta`
- List groups (string or list of strings): `js`, `script_src`, `css`, `url`, `path`, `file`,
  `dns`, `subdomain`, `link`, `json`, `api`, `tls`, `server`, `framework`, `cms`, `cdn`
- `html`: string `tag:X:attr:Y:value:Z` or object `{"tag", "attr", "value"}`, or a list of either

Matching:

- Case-insensitive, leading and trailing whitespace ignored.
- Patterns are literal strings. Regex and version capture are not supported in format v2.
- Inside a group, the value must start with the pattern (`js:jquery` matches `jquery.min.js`).
  `headers` patterns have no group prefix and match anywhere in `Name: value`.
- If several rules share a pattern, the one defined first wins.

## File format

```
"SIGT" | version (u8 = 2) | u32 len + header JSON | u32 len + zstd(items JSON)
       | u32 len + zstd(automaton) | SHA256(items + automaton)
```

Lengths are big-endian. The hash is checked on load (`verify_hash=True` by default).
Version 1 files (Ed25519-signed layout) are rejected; rebuild them from the rules.

## Tests

```sh
pip install -e .
for f in tests/test_*.py tests/validate_lib.py; do python "$f"; done
```

`tests/golden/` holds rule sets with expected match results. After an intentional behavior
change, regenerate them with `python tests/test_golden.py --regen` and review the diff.

## License

MIT
