#!/usr/bin/env python3
"""Check the exact selected upstream Hibana snapshot."""
import hashlib
import json
import tomllib
from pathlib import Path

here = Path(__file__).resolve().parent
manifest = json.loads((here / 'hibana-provenance.json').read_text())
project = here.parent
selected = tomllib.loads((project / 'Cargo.toml').read_text())['package']['metadata']['hibana-source']['revision']
pins = dict(line.split('=', 1) for line in (project / 'ci/pins.env').read_text().splitlines()
            if line and not line.startswith('#') and '=' in line)
if not (manifest['revision'] == manifest['base_commit'] == selected == pins['HIBANA_REVISION']):
    raise SystemExit('Hibana revision disagrees across manifest, Cargo metadata and CI pin')
root = here / 'hibana'
expected = manifest['files']
actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(root.rglob('*')) if p.is_file()}
missing = sorted(expected.keys() - actual.keys())
extra = sorted(actual.keys() - expected.keys())
changed = sorted(p for p in expected.keys() & actual.keys() if expected[p] != actual[p])
if missing or extra or changed:
    raise SystemExit(f'Hibana snapshot mismatch: missing={missing}, extra={extra}, changed={changed}')
print(f"Hibana {manifest['base_commit']}: {len(actual)} snapshot files verified; local patches: {manifest.get('local_patches', [])}")
