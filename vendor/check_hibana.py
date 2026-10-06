#!/usr/bin/env python3
"""Check the exact selected upstream Hibana snapshot."""
import hashlib
import json
import tomllib
from pathlib import Path

here = Path(__file__).resolve().parent
manifest = json.loads((here / 'hibana-provenance.json').read_text())
root = here / 'hibana'
expected = manifest['files']
actual = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted(root.rglob('*')) if p.is_file()}
missing = sorted(expected.keys() - actual.keys())
extra = sorted(actual.keys() - expected.keys())
changed = sorted(p for p in expected.keys() & actual.keys() if expected[p] != actual[p])
if missing or extra or changed:
    raise SystemExit(f'Hibana snapshot mismatch: missing={missing}, extra={extra}, changed={changed}')
metadata = tomllib.loads((here.parent / 'Cargo.toml').read_text())['package']['metadata']['hibana-source']
pins = dict(line.split('=', 1) for line in (here.parent / 'ci/pins.env').read_text().splitlines()
            if line and not line.startswith('#'))
if not (manifest['revision'] == manifest['base_commit'] == metadata['revision'] == pins['HIBANA_REVISION']):
    raise SystemExit('Hibana Cargo metadata, CI pin and snapshot revision disagree')
if manifest['branch'] != metadata['branch']:
    raise SystemExit('Hibana Cargo metadata and snapshot branch disagree')
if manifest['local_patches'] or metadata['local-patches']:
    raise SystemExit('The selected Hibana snapshot must not have local patches')
executables = {str(p.relative_to(root)) for p in root.rglob('*')
               if p.is_file() and p.stat().st_mode & 0o111}
if executables != set(manifest['executable_files']):
    raise SystemExit('Hibana snapshot executable modes disagree with upstream')
print(f"Hibana {manifest['base_commit']}: {len(actual)} snapshot files verified; local patches: {manifest.get('local_patches', [])}")
