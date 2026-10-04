#!/usr/bin/env python3
"""Native reference/candidate byte-transfer diagnostics, never an official verdict.

The pinned Neqo binaries are unchanged. Credentials and raw logs are temporary
or explicitly retained outside the source tree. Only bounded structural results
and content hashes are written to the JSON report.
"""
import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from udp_impairment import UdpProxy

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fixture', HERE / 'test_direct_handshake_localhost.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env, *, timeout=70):
    return subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)


def checked(command, env):
    result = run(command, env)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} fixture setup failed ({result.returncode})')


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def unused_port(ipv6):
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('::1' if ipv6 else '127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_ready(process, log):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'server exited before readiness ({process.returncode})')
        text = log.read_text(errors='replace').lower()
        if 'listening' in text or 'waiting for connection' in text:
            return
        time.sleep(0.02)
    raise TimeoutError('server readiness timeout')


def main():
    parser = argparse.ArgumentParser()
    for name in ('hq', 'neqo-client', 'neqo-server', 'nss', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--scenario', choices=('clean', 'longrtt', 'loss', 'corruption', 'ipv6'), default='clean')
    parser.add_argument('--private-log-dir', type=Path)
    args = parser.parse_args()
    hq, nc, ns, nss = (p.resolve() for p in (args.hq, args.neqo_client, args.neqo_server, args.nss))
    env = os.environ.copy()
    env['RUST_LOG'] = 'debug'
    env['LD_LIBRARY_PATH'] = str(nss / 'lib')
    env.pop('SSLKEYLOGFILE', None)
    ipv6 = args.scenario == 'ipv6'
    sizes = [1024] if args.scenario == 'longrtt' else ([2 << 20] if args.scenario in ('loss', 'corruption') else [2 << 20, 3 << 20, 5 << 20])
    options = {'delay': 0.75} if args.scenario == 'longrtt' else (
        {'drop_every': 50} if args.scenario == 'loss' else (
            {'corrupt_every': 50} if args.scenario == 'corruption' else None
        )
    )
    report = {
        'scope': 'native-peer-diagnostics', 'official_interop_pass': False,
        'scenario': args.scenario, 'impairment': options,
        'coverage_gaps': ['not ns-3 topology or exact stochastic impairment', 'no packet-trace verdicts', 'forward ordinary-Neqo generated-zero payloads'],
        'binaries': {name: sha(path) for name, path in [('hq', hq), ('neqo-client', nc), ('neqo-server', ns)]},
        'runs': [],
    }

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    with tempfile.TemporaryDirectory(prefix='hibana-native-peer-') as temporary:
        root = Path(temporary)
        fixture.credentials(root)
        db = root / 'db'
        db.mkdir()
        checked([str(nss / 'bin/certutil'), '-N', '-d', str(db), '--empty-password'], env)
        checked(['openssl', 'pkcs12', '-export', '-inkey', str(root / 'server.key'), '-in', str(root / 'server.pem'), '-certfile', str(root / 'ca.pem'), '-name', 'native-peer', '-passout', 'pass:', '-out', str(root / 'fixture.p12')], env)
        checked([str(nss / 'bin/pk12util'), '-i', str(root / 'fixture.p12'), '-d', str(db), '-W', '', '-K', ''], env)
        for direction in ('baseline', 'forward', 'reverse'):
            destination = root / direction
            destination.mkdir()
            www = root / ('www-' + direction)
            www.mkdir()
            names = [str(size) for size in sizes]
            for size, name in zip(sizes, names):
                (www / name).write_bytes(bytes([37 if direction == 'reverse' else 0]) * size)
            server_port = unused_port(ipv6)
            server_address = f'[::1]:{server_port}' if ipv6 else f'127.0.0.1:{server_port}'
            if direction == 'reverse':
                server_command = [str(hq), 'server', '--listen', server_address, '--cert', str(root / 'server.pem'), '--key', str(root / 'server.key'), '--www', str(www), '--max-requests', str(len(names)), '--timeout-seconds', '60']
            else:
                server_command = [str(ns), '-a', 'hq-interop', '-Q', '1', '-d', str(db), '-k', 'native-peer', '--idle', '60', server_address]
            log_path = root / 'server.log'
            with log_path.open('w') as log:
                server = subprocess.Popen(server_command, env=env, stdout=log, stderr=log, text=True)
                result = None
                try:
                    wait_ready(server, log_path)
                    proxy_context = UdpProxy(('127.0.0.1', server_port), **options) if options else nullcontext(None)
                    with proxy_context as proxy:
                        client_port = proxy.address[1] if proxy else server_port
                        address = f'[::1]:{client_port}' if ipv6 else f'127.0.0.1:{client_port}'
                        urls = [f'https://localhost:{client_port}/{name}' for name in names]
                        if direction == 'forward':
                            command = [str(hq), 'client', '--connect', address, '--server-name', 'localhost', '--ca', str(root / 'ca.pem'), '--downloads', str(destination), '--timeout-seconds', '60']
                            for url in urls:
                                command += ['--request', url]
                        else:
                            command = [str(nc), '--qns-test', 'transfer', '-Q', '1', '--ipv6-only' if ipv6 else '--ipv4-only', '--output-dir', str(destination), '--idle', '60'] + urls
                        started = time.monotonic()
                        try:
                            result = run(command, env)
                            returncode = result.returncode
                        except subprocess.TimeoutExpired:
                            returncode = 'timeout'
                        files = [{'name': name, 'bytes': (destination / name).stat().st_size if (destination / name).exists() else None, 'expected_sha256': sha(www / name), 'received_sha256': sha(destination / name) if (destination / name).exists() else None} for name in names]
                        row = {'direction': direction, 'client_exit': returncode, 'elapsed_seconds': round(time.monotonic() - started, 3), 'files': files, 'proxy': dict(proxy.stats) if proxy else None}
                        report['runs'].append(row)
                        save()
                        if returncode != 0 or any(x['expected_sha256'] != x['received_sha256'] for x in files):
                            raise AssertionError(f'{args.scenario}/{direction}: exit={returncode}, received byte hashes did not all qualify')
                finally:
                    stop(server)
                    if args.private_log_dir:
                        args.private_log_dir.mkdir(parents=True, exist_ok=True)
                        (args.private_log_dir / f'{args.scenario}-{direction}-server.log').write_bytes(log_path.read_bytes())
                        if result is not None:
                            (args.private_log_dir / f'{args.scenario}-{direction}-client.log').write_text(result.stdout + result.stderr)
    save()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
