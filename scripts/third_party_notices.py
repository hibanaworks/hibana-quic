#!/usr/bin/env python3
"""Collect exact license texts for the locked core/host normal+build closure."""
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
packages = {}
scopes = {}
for label, manifest in [('core', root / 'Cargo.toml'), ('host', root / 'adapters/host/Cargo.toml')]:
    result = subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1',
                             '--filter-platform', 'x86_64-unknown-linux-gnu', '--manifest-path', str(manifest)],
                            check=True, capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    nodes = {node['id']: node for node in metadata['resolve']['nodes']}
    by_id = {package['id']: package for package in metadata['packages']}
    pending, seen = [metadata['resolve']['root']], set()
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        package = by_id[package_id]
        key = (package['name'], package['version'], package['source'] or 'local')
        packages[key] = package
        scopes.setdefault(key, set()).add(label)
        pending.extend(dep['pkg'] for dep in nodes[package_id]['deps']
                       if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']))

lines = ['# Third-party notices: locked production core and host closure', '',
         'Generated from Cargo normal and build dependencies for Linux x86_64; development-only',
         'fixtures, Rustls reference engine, Neqo peer, native NSS/NSPR and toolchains are excluded.',
         'This is a notice inventory, not a legal opinion or security certification.',
         'Dependency feature and source changes require regeneration.', '']
records, missing = [], []
for key, package in sorted(packages.items()):
    if package['name'] in ('hibana-quic', 'hibana-quic-host'):
        continue
    directory = Path(package['manifest_path']).parent
    candidates = {p for p in directory.iterdir() if p.is_file() and
                  p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE'))}
    if package.get('license_file'):
        candidates.add(directory / package['license_file'])
    texts = []
    for path in sorted(candidates):
        if path.is_file():
            data = path.read_bytes()
            texts.append((path.name, data.decode('utf-8'), hashlib.sha256(data).hexdigest()))
    if not texts:
        missing.append(f"{package['name']} {package['version']}")
    source = package['source'] or ('vendored snapshot; see vendor provenance' if package['name'] in ('hibana', 'rustls-webpki') else 'local package')
    lines += [f"## {package['name']} {package['version']}", '', f"Declared license: {package.get('license')}",
              f'Source: {source}', f"Included in: {', '.join(sorted(scopes[key]))}", '']
    for name, text, digest in texts:
        lines += [f'### {name}', '', f'SHA-256: {digest}', '', '```text', text.rstrip(), '```', '']
    records.append({'name': package['name'], 'version': package['version'], 'source': source,
                    'license': package.get('license'), 'scopes': sorted(scopes[key]),
                    'texts': [{'file': name, 'sha256': digest} for name, _, digest in texts]})
# Mechanically extracted source is not a Cargo package and must be inventoried
# explicitly, even though no allocated upstream RSA crate is a dependency.
helper = root / 'vendor/rustcrypto-rsa-verification-0.9.10'
if helper.exists():
    texts = []
    lines += ['## RustCrypto RSA 0.9.10 extracted verification helpers', '',
              'Upstream: https://github.com/RustCrypto/RSA/tree/da2af9a0ff814762957c428460e4098720f394a6',
              'Only six provenance-pinned function bodies are reused; see the vendor README.',
              'Declared license: MIT OR Apache-2.0', '']
    for name in ('LICENSE-APACHE', 'LICENSE-MIT'):
        data = (helper / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        lines += [f'### {name}', '', f'SHA-256: {digest}', '', '```text', data.decode().rstrip(), '```', '']
        texts.append({'file': name, 'sha256': digest})
    records.append({'name': 'rustcrypto-rsa-verification-helpers', 'version': '0.9.10',
                    'source': 'mechanically extracted upstream source; vendor provenance',
                    'license': 'MIT OR Apache-2.0', 'scopes': ['core', 'host'], 'texts': texts})
if missing:
    raise SystemExit('Missing license texts; no complete bundle written: ' + ', '.join(missing))
(root / 'THIRD_PARTY_NOTICES.md').write_text('\n'.join(lines))
(root / 'artifacts/license-notices.json').write_text(json.dumps(records, indent=2) + '\n')
print(f'Collected exact notice texts for {len(records)} production/build packages; no missing texts')
