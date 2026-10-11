#!/usr/bin/env python3
"""Expose the immutable dependency revision to Actions before TLS checkout."""
from pathlib import Path
import re
import tomllib

root = Path(__file__).resolve().parents[2]
dependency = tomllib.loads((root / 'Cargo.toml').read_text())['dependencies']['hibana-tls']
assert dependency['git'] == 'https://github.com/hibanaworks/hibana-tls'
assert re.fullmatch(r'[0-9a-f]{40}', dependency['rev']), 'TLS requires a full commit'
print('revision=' + dependency['rev'])
