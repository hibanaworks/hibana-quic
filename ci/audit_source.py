#!/usr/bin/env python3
"""Fail-closed source inventory and accidental-secret/artifact guard."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'ci/source-manifest.json'
IGNORED = {'.git', '__pycache__', '.ci-work', 'ci-safe-results'}
PUBLIC_BINARY = {
 'artifacts/rsa-feasibility/20261002-044400/foundations/vectors/rsa2048.der',
 'artifacts/rsa-feasibility/20261002-044400/foundations/vectors/rsa2048.sig',
}

PUBLIC_PROOF_ARCHIVES = {'vendor/hibana/proofs/elastic-roll-colors/roll-membership-capacity-model.json.gz': 'e27e3818431fc37e750026a88334cc525df7c37a4c8504c67540b726a74dac81', 'vendor/hibana/proofs/elastic-roll-colors/color-capacity-model.json.gz': 'cae665d3e498621c31ed6ab60cf207e21efe14632e54b3cebd20396ca8cda19c'}

def inventory():
    entries = {}
    for path in sorted(ROOT.rglob('*')):
        rel = path.relative_to(ROOT)
        if any(part in IGNORED for part in rel.parts) or path == MANIFEST:
            continue
        if path.is_symlink():
            raise ValueError('source symlink not admitted: ' + str(rel))
        if not path.is_file():
            continue
        name = str(rel)
        if any(part in {'target', 'inputs', 'node_modules'} for part in rel.parts):
            raise ValueError('private/generated input directory: ' + name)
        if path.suffix.lower() in {'.key', '.pem', '.p12', '.pfx', '.pk8', '.pcap', '.pcapng', '.qlog', '.pyc'}:
            raise ValueError('private fixture/raw/generated artifact: ' + name)
        data = path.read_bytes()
        public_vector = (name in PUBLIC_BINARY or name.startswith('tests/vectors/') and path.suffix in {'.bin', '.der', '.sig'} or name.startswith('vendor/rustls-webpki-0.103.15/src/data/') and path.suffix == '.der')
        if name in PUBLIC_PROOF_ARCHIVES:
            if hashlib.sha256(data).hexdigest() != PUBLIC_PROOF_ARCHIVES[name]:
                raise ValueError("public proof archive changed: " + name)
        elif not public_vector:
            text = data.decode('utf-8')
            if re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[M-Za-z0-9+/]{24,}', text):
                raise ValueError('private key block: ' + name)
            if re.search(r'\bgh[pousr]_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b', text):
                raise ValueError('credential-looking token: ' + name)
            if re.search(r'(?m)^(?:CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s*$', text):
                raise ValueError('TLS key log: ' + name)
        entries[name] = hashlib.sha256(data).hexdigest()
    return entries

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    current = inventory()
    if args.write:
        MANIFEST.write_text(json.dumps(current, indent=2) + '\n')
    else:
        expected = json.loads(MANIFEST.read_text())
        if current != expected:
            raise ValueError('audited source inventory mismatch')
    print(f'Source audit passed: {len(current)} files; binary contents restricted to audited public certificate/signature, TLS-hello and algorithm vectors')

if __name__ == '__main__':
    main()
