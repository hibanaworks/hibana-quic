#!/usr/bin/env python3
"""Export the actual paired owned sources; never fetch or select another TLS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
SKIP = {'.git', 'target', '__pycache__', '.ci-work', 'ci-safe-results', 'node_modules'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = tomllib.loads((ROOT / 'Cargo.toml').read_text())
    tls = (ROOT.parent / 'hibana-tls').resolve(strict=True)
    dependency = config['dependencies']['hibana-tls']
    revision = dependency['rev']
    assert dependency['git'] == 'https://github.com/hibanaworks/hibana-tls'
    assert re.fullmatch(r'[0-9a-f]{40}', revision), 'TLS requires an immutable commit'
    actual = subprocess.check_output(['git', '-C', str(tls), 'rev-parse', 'HEAD'], text=True).strip()
    assert actual == revision, 'sibling TLS checkout differs from the dependency revision'
    assert not subprocess.check_output(['git', '-C', str(tls), 'status', '--porcelain', '--untracked-files=all']), 'TLS checkout must be clean'
    assert tomllib.loads((tls / 'Cargo.toml').read_text())['package']['name'] == 'hibana-tls'
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error('--output must be new or empty; do not combine source attempts')
    output.mkdir(parents=True, exist_ok=True)
    roots = [(ROOT, 'hibana-quic'), (tls, 'hibana-tls')]
    entries = {}
    for root, name in roots:
        for parent, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP)
            for directory in dirs:
                assert not (Path(parent) / directory).is_symlink(), 'source directory symlink'
            for filename in sorted(files):
                if filename in SKIP:
                    continue
                source = Path(parent) / filename
                relative = source.relative_to(root)
                assert not source.is_symlink(), 'source file symlink'
                destination = output / name / relative
                data = source.read_bytes()
                if filename == 'Cargo.toml':
                    def normalize(match):
                        dependency = (source.parent / match.group(1)).resolve(strict=True)
                        for origin, exported in roots:
                            if dependency.is_relative_to(origin):
                                mapped = output / exported / dependency.relative_to(origin)
                                path = Path(os.path.relpath(mapped, destination.parent)).as_posix()
                                return 'path = ' + json.dumps(path)
                        raise ValueError('path outside the paired source: ' + match.group(1))
                    data = re.sub(r'\bpath\s*=\s*"([^"\n]+)"', normalize, data.decode()).encode()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                entries[str(destination.relative_to(output))] = hashlib.sha256(data).hexdigest()
    digests = {}
    for _, name in roots:
        subset = {p: h for p, h in sorted(entries.items()) if p.startswith(name + '/')}
        digests[name] = hashlib.sha256(json.dumps(subset, sort_keys=True).encode()).hexdigest()
    (output / 'source-files.json').write_text(json.dumps(entries, indent=2) + '\n')
    (output / 'source-pair.json').write_text(json.dumps({'trees': digests, 'file_count': len(entries), 'tls_repository': dependency['git'], 'tls_revision': revision}, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'trees': digests, 'files': len(entries)}))


if __name__ == '__main__':
    main()
