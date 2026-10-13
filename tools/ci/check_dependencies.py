#!/usr/bin/env python3
"""Verify Hibana identity and prevent eliminated packages returning transitively."""
from pathlib import Path
import tomllib
ROOT = Path(__file__).resolve().parents[2]
pins = dict(line.split('=', 1) for line in (ROOT/'tools/ci/pins.env').read_text().splitlines() if line and not line.startswith('#'))
version = pins['HIBANA_VERSION']
checksum = pins['HIBANA_CHECKSUM']
registry = 'registry+https://github.com/rust-lang/crates.io-index'
assert len(checksum) == 64 and all(c in '0123456789abcdef' for c in checksum)

def check_core_dependency(dependency):
    assert dependency == {'version': '=' + version, 'default-features': False}, dependency

def check_core_package(package):
    assert package['version'] == version, package
    assert package.get('source') == registry, package
    assert package.get('checksum') == checksum, package

# This ratchet grows as replacement implementations are qualified.
# It is not a claim that all remaining third-party packages are eliminated.
eliminated = {'hkdf', 'pkcs1', 'chacha20', 'chacha20poly1305', 'poly1305', 'aes', 'aes-gcm', 'ghash', 'polyval', 'ctr', 'cipher', 'inout', 'aead', 'universal-hash', 'opaque-debug', 'x25519-dalek', 'curve25519-dalek', 'curve25519-dalek-derive', 'fiat-crypto'}
eliminated |= {'ff', 'primeorder', 'signature', 'spki', 'base16ct', 'elliptic-curve', 'const-oid', 'rfc6979', 'sec1', 'pkcs8', 'group', 'hmac', 'p256', 'ecdsa'}

eliminated |= {'crypto-common', 'version_check', 'cpufeatures', 'typenum', 'digest', 'generic-array', 'block-buffer', 'sha2'}

eliminated |= {'crypto-bigint', 'rand_core'}

for relative in ('Cargo.toml', 'pal/Cargo.toml', 'examples/Cargo.toml', 'tests/interop/driver/Cargo.toml', 'tests/tls-reference/Cargo.toml', 'pal/examples/pico/Cargo.toml'):
    path = ROOT/relative
    cargo = tomllib.loads(path.read_text())
    dependency = (cargo['dependencies'].get('hibana') or cargo.get('dev-dependencies', {}).get('hibana'))
    if dependency is not None:
        check_core_dependency(dependency)
    for overrides in cargo.get('patch', {}).values():
        assert 'hibana' not in overrides, (relative, 'Hibana source override')
    lock = tomllib.loads(path.with_name('Cargo.lock').read_text())
    names = {p['name'] for p in lock['package']}
    assert not names & eliminated, (relative, names & eliminated)
    if relative in ('Cargo.toml', 'pal/Cargo.toml', 'examples/Cargo.toml', 'tests/interop/driver/Cargo.toml', 'pal/examples/pico/Cargo.toml'):
        assert names <= {'hibana', 'hibana-quic', 'hibana-tls', 'hibana-quic-pal', 'actor-test-allocator', 'hibana-quic-pico-example', 'hibana-quic-examples', 'hibana-quic-interop'}, (relative, names)
        assert 'der' not in names, 'DER is allowed only in the independent reference workspace'
    matches = [p for p in lock['package'] if p['name'] == 'hibana']
    assert len(matches) == 1, (relative, 'multiple Hibana package identities')
    package = matches[0]
    check_core_package(package)
print('Exact crates.io version and checksum verified:', version, checksum)

print('Eliminated packages absent from all complete locks:', ', '.join(sorted(eliminated)))

# Certificate packages may remain in independent reference/fixture generators,
# but never in a production root or Host normal/build dependency closure.
import subprocess
for relative in ('Cargo.toml', 'pal/Cargo.toml', 'examples/Cargo.toml', 'tests/interop/driver/Cargo.toml'):
    tree = subprocess.check_output(['cargo','tree','--locked','--manifest-path',str(ROOT/relative),'-e','normal,build','--prefix','none'], text=True)
    normal = {line.split()[0] for line in tree.splitlines() if line.strip()}
    assert normal <= {'hibana','hibana-quic','hibana-tls','hibana-quic-pal','hibana-quic-examples', 'hibana-quic-interop'}, (relative, normal)
    assert not normal & {'rustls-webpki','rustls-pki-types','untrusted','subtle','zeroize','nix','libc','memoffset','autocfg','cfg-if','cfg_aliases','bitflags'}, (relative,normal)
material = (ROOT.parent/'hibana-tls').resolve(strict=True)
assert not (ROOT/'vendor/rustls-webpki-0.103.15').exists()
assert not (material/'vendor/rustls-webpki-0.103.15').exists()
print('Owned cryptography normal/build dependency and vendor-copy ratchet passed')

# All consumers must resolve one immutable TLS package, including reference tests.
tls_url = 'https://github.com/hibanaworks/hibana-tls'
tls_revision = pins['HIBANA_TLS_REVISION']
for relative in ('Cargo.toml', 'pal/Cargo.toml', 'examples/Cargo.toml', 'tests/interop/driver/Cargo.toml', 'tests/tls-reference/Cargo.toml'):
    cargo = tomllib.loads((ROOT/relative).read_text())
    dependency = (cargo['dependencies'].get('hibana-tls') or cargo.get('dev-dependencies', {}).get('hibana-tls'))
    if dependency is not None:
        assert dependency.get('git') == tls_url and dependency.get('rev') == tls_revision
        assert dependency.get('default-features') is False and 'path' not in dependency
    lock = tomllib.loads((ROOT/relative).with_name('Cargo.lock').read_text())
    packages = [p for p in lock['package'] if p['name'] == 'hibana-tls']
    assert len(packages) == 1, (relative, 'multiple TLS identities')
    assert packages[0]['source'] == f'git+{tls_url}?rev={tls_revision}#{tls_revision}'
tls_cargo = tomllib.loads((material/'Cargo.toml').read_text())
check_core_dependency(tls_cargo['dependencies']['hibana'])
for overrides in tls_cargo.get('patch', {}).values():
    assert 'hibana' not in overrides, 'TLS must not override the Hibana source'
tls_lock = tomllib.loads((material/'Cargo.lock').read_text())
tls_core = [p for p in tls_lock['package'] if p['name'] == 'hibana']
assert len(tls_core) == 1, 'TLS lock must contain one Hibana identity'
check_core_package(tls_core[0])
print('Exact TLS Git source and all consumer locks verified:', tls_revision)

pico_lock = tomllib.loads((ROOT/'pal/examples/pico/Cargo.lock').read_text())
pico_tls = [p for p in pico_lock['package'] if p['name'] == 'hibana-tls']
assert len(pico_tls) == 1
assert pico_tls[0]['source'] == f'git+{tls_url}?rev={tls_revision}#{tls_revision}'
print('Pico uses the same TLS identity')
