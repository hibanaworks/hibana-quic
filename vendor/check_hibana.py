#!/usr/bin/env python3
"""Check the exact selected upstream Hibana snapshot."""
import hashlib
import json
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
print(f"Hibana {manifest['base_commit']}: {len(actual)} snapshot files verified; local patches: {manifest.get('local_patches', [])}")
