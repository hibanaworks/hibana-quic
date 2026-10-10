#!/usr/bin/env python3
"""Same unchanged reference sender and bytes; candidate/reference release clients."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import test_native_neqo_transfer as fixture

p = argparse.ArgumentParser()
for name in ('hq', 'neqo-client', 'neqo-server', 'nss', 'output'):
    p.add_argument('--' + name, type=Path, required=True)
p.add_argument('--bytes', type=int, default=32 * 1024 * 1024)
p.add_argument('--repeats', type=int, default=3)
p.add_argument('--cipher', choices=('aes128', 'chacha20'), default='aes128')
a = p.parse_args()
if a.repeats < 1 or a.bytes < 1:
    p.error("--repeats and --bytes must both be positive")
hq, nc, ns, nss = (x.resolve() for x in (a.hq, a.neqo_client, a.neqo_server, a.nss))
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = str(nss / 'lib')
env['RUST_LOG'] = 'info'
env.pop('SSLKEYLOGFILE', None)
measure = Path(__file__).with_name('measure_process.py')
suite = 'TLS_AES_128_GCM_SHA256' if a.cipher == 'aes128' else 'TLS_CHACHA20_POLY1305_SHA256'
report = {'cipher': a.cipher, 'scope': 'release-client-end-to-end-download-comparison', 'bytes': a.bytes,
          'qualifications': ['loopback; one stream; selected cipher; PMTUD disabled',
                             'same Neqo generated-zero sender; both clients write real files',
                             'download latency includes process startup and handshake, excludes final draining',
                             'does not establish server performance or full Neqo parity'],
          'binaries': {k: fixture.sha(v) for k, v in [('hq', hq), ('neqo-client', nc), ('neqo-server', ns)]},
          'runs': []}
with tempfile.TemporaryDirectory(prefix='hibana-client-perf-') as temporary:
    root = Path(temporary)
    fixture.fixture.credentials(root)
    db = root / 'db'; db.mkdir()
    fixture.checked([str(nss / 'bin/certutil'), '-N', '-d', str(db), '--empty-password'], env)
    fixture.checked(['openssl', 'pkcs12', '-export', '-inkey', str(root / 'server.key'), '-in', str(root / 'server.pem'), '-certfile', str(root / 'ca.pem'), '-name', 'native-peer', '-passout', 'pass:', '-out', str(root / 'fixture.p12')], env)
    fixture.checked([str(nss / 'bin/pk12util'), '-i', str(root / 'fixture.p12'), '-d', str(db), '-W', '', '-K', ''], env)
    expected = hashlib.sha256(bytes(a.bytes)).hexdigest()
    for repeat in range(a.repeats + 1):
        for kind in (('neqo', 'hibana') if repeat % 2 == 0 else ('hibana', 'neqo')):
            directory = root / f'{repeat}-{kind}'; directory.mkdir()
            port = fixture.unused_port(False)
            address = f'127.0.0.1:{port}'
            logpath = directory / 'server.log'
            with logpath.open('w') as log:
                server = subprocess.Popen([str(ns), '-a', 'hq-interop', '-Q', '1', '-d', str(db), '-k', 'native-peer', '--idle', '60', '--no-pmtud', '-c', suite, address], env=env, stdout=log, stderr=log)
                try:
                    fixture.wait_ready(server, logpath)
                    downloads = directory / 'downloads'; downloads.mkdir()
                    url = f'https://localhost:{port}/{a.bytes}'
                    if kind == 'hibana':
                        command = [str(hq), 'client', '--connect', address, '--server-name', 'localhost', '--ca', str(root / 'ca.pem'), '--downloads', str(downloads), '--cipher', a.cipher, '--request', url, '--timeout-seconds', '60']
                    else:
                        command = [str(nc), '--qns-test', 'transfer', '-Q', '1', '--ipv4-only', '--no-pmtud', '-c', suite, '--output-dir', str(downloads), '--idle', '60', url]
                    stats = directory / 'usage.json'
                    with (directory / 'client.log').open('w') as clientlog:
                        result = subprocess.run([sys.executable, str(measure), str(stats), *command], env=env, stdout=clientlog, stderr=clientlog, timeout=70)
                    usage = json.loads(stats.read_text())
                    path = downloads / str(a.bytes)
                    if result.returncode != 0 or not path.exists() or fixture.sha(path) != expected:
                        failure = {'client': kind, 'warmup': repeat == 0, 'complete': False, **usage,
                                   'partial_bytes': sum(item.stat().st_size for item in downloads.rglob('*') if item.is_file())}
                        report['runs'].append(failure)
                        a.output.parent.mkdir(parents=True, exist_ok=True)
                        a.output.write_text(json.dumps(report, indent=2) + '\n')
                        raise AssertionError({**failure, 'log': (directory / 'client.log').read_text()[-2000:]})
                    seconds = (path.stat().st_mtime_ns - usage['started_unix_ns']) / 1e9
                    assert seconds > 0, usage
                    row = {'client': kind, 'warmup': repeat == 0, 'download_seconds': seconds,
                           'download_mib_per_second': a.bytes / (1024 * 1024) / seconds, **usage}
                    if kind == 'hibana':
                        records = [json.loads(line) for line in (directory / 'client.log').read_text().splitlines()
                                   if line.startswith('{')]
                        actual = next(item for item in reversed(records) if item.get('status') == 'success')
                        row['transport_counters'] = {
                            key: actual[key] for key in (
                                'datagrams_sent', 'datagrams_received', 'reactor_polls',
                                'reactor_waits', 'reactor_socket_events', 'reactor_timer_events')
                        }
                    report['runs'].append(row)
                    a.output.parent.mkdir(parents=True, exist_ok=True)
                    a.output.write_text(json.dumps(report, indent=2) + '\n')
                    print(json.dumps(row), flush=True)
                finally:
                    fixture.stop(server)
report['median'] = {kind: {metric: statistics.median(r[metric] for r in report['runs'] if r['client'] == kind and not r['warmup'])
                          for metric in ('download_seconds', 'download_mib_per_second', 'user_seconds', 'system_seconds', 'max_rss_kib')}
                    for kind in ('neqo', 'hibana')}
a.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report['median']), flush=True)
