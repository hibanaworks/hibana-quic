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

from udp_impairment import UdpProxy, EarlyWireProbe

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
    parser.add_argument('--scenario', choices=('clean', 'longrtt', 'loss', 'corruption', 'ipv6', 'chacha20', 'resumption', 'zerortt', 'blackhole', 'keyupdate'), default='clean')
    parser.add_argument('--private-log-dir', type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=60)
    parser.add_argument('--early-files', type=int, choices=[2, 40], default=2)
    parser.add_argument('--client-keyupdate', action='store_true')
    parser.add_argument('--client-early', action='store_true')
    parser.add_argument('--client-early-loss', action='store_true', help='drop the first real 0-RTT datagram; forward direction only')
    parser.add_argument('--client-early-reject', action='store_true', help='native Neqo startup rejection; forward direction only')
    parser.add_argument('--ordinary-files', type=int, choices=[3, 5, 40, 64], default=3)
    args = parser.parse_args()
    if (args.client_early_reject or args.client_early_loss) and (args.scenario != 'zerortt' or not args.client_early):
        parser.error('early fault scenarios require --scenario zerortt --client-early')
    if args.client_early_reject and args.client_early_loss:
        parser.error('select acceptance/loss or rejection separately')
    if args.client_keyupdate and args.scenario != 'keyupdate':
        parser.error('--client-keyupdate requires --scenario keyupdate')
    hq, nc, ns, nss = (p.resolve() for p in (args.hq, args.neqo_client, args.neqo_server, args.nss))
    env = os.environ.copy()
    env['RUST_LOG'] = 'debug'
    if args.scenario in ('blackhole', 'keyupdate'):
        env['HIBANA_QUIC_DIAGNOSTICS'] = '1'
    env['LD_LIBRARY_PATH'] = str(nss / 'lib')
    env.pop('SSLKEYLOGFILE', None)
    ipv6 = args.scenario == 'ipv6'
    sizes = [5 << 10, 10 << 10] if args.scenario == 'resumption' else [32, 33] if args.scenario == 'zerortt' else [3 << 20] if args.scenario in ('chacha20', 'keyupdate') else [1024] if args.scenario == 'longrtt' else ([2 << 20] if args.scenario in ('loss', 'corruption') else [2 << 20, 3 << 20, 5 << 20])
    if args.scenario == 'blackhole':
        sizes = [10 << 20]
    if args.ordinary_files != 3:
        if args.scenario != 'clean':
            parser.error('--ordinary-files requires the clean scenario')
        sizes = [131072 + index for index in range(args.ordinary_files)]
    options = {'delay': 0.75} if args.scenario == 'longrtt' else (
        {'drop_every': 50} if args.scenario == 'loss' else (
            {'corrupt_every': 50} if args.scenario == 'corruption' else None
        )
    )
    if args.scenario == 'blackhole':
        options = {'blackhole_after_bytes': 4 << 20, 'blackhole_seconds': 2.0}
    report = {
        'scope': 'native-peer-diagnostics', 'official_interop_pass': False,
        'scenario': args.scenario, 'impairment': options, 'ordinary_files': len(sizes),
        'coverage_gaps': ['not ns-3 topology or exact stochastic impairment', 'no packet-trace verdicts', 'forward ordinary-Neqo generated-zero payloads'],
        'binaries': {name: sha(path) for name, path in [('hq', hq), ('neqo-client', nc), ('neqo-server', ns)]},
        'runs': [],
    }

    if args.scenario == 'zerortt' and args.early_files == 40:
        report['coverage_gaps'].append(
            'native forty-file early baseline uses numeric names and 32..71-byte generated bodies'
        )

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
        directions = ('forward',) if args.client_early_reject or args.client_early_loss else (('baseline', 'reverse') if args.scenario == 'zerortt' and not args.client_early else ('baseline', 'forward', 'reverse'))
        if args.scenario == 'keyupdate':
            directions = ('baseline', 'forward', 'reverse') if args.client_keyupdate else ('baseline', 'reverse')
        for direction in directions:
            destination = root / direction
            destination.mkdir()
            www = root / ('www-' + direction)
            www.mkdir()
            case_sizes = sizes
            names = [str(size) for size in sizes]
            if args.scenario == 'zerortt' and args.early_files == 40:
                if direction == 'reverse':
                    names = [f'{index:03d}' + 'x' * 247 for index in range(40)]
                    case_sizes = [32] * 40
                else:
                    # Native Neqo generates numeric response sizes. Preserve
                    # forty 250-byte request names without patching its source
                    # or requiring the QNS-only /www mount. Bodies are 32..71
                    # bytes, so this remains a diagnostic, not the exact runner.
                    case_sizes = list(range(32, 72))
                    names = [str(size).zfill(250) for size in case_sizes]
            for size, name in zip(case_sizes, names):
                (www / name).write_bytes(bytes([37 if direction == 'reverse' else 0]) * size)
            server_port = unused_port(ipv6)
            server_address = f'[::1]:{server_port}' if ipv6 else f'127.0.0.1:{server_port}'
            if direction == 'reverse':
                server_command = [str(hq), 'server', '--listen', server_address, '--cert', str(root / 'server.pem'), '--key', str(root / 'server.key'), '--www', str(www), '--max-requests', str(64 if args.scenario in ('resumption', 'zerortt') else len(names)), '--timeout-seconds', str(args.timeout_seconds)]
            else:
                server_command = [str(ns), '-a', 'hq-interop', '-Q', '1', '-d', str(db), '-k', 'native-peer', '--idle', str(args.timeout_seconds), server_address]
            if args.scenario == 'zerortt' and direction != 'reverse':
                # Match the reference's QNS zerortt stream-credit configuration.
                server_command += ['--max-streams-bidi', '100']
            if args.scenario in ('resumption', 'zerortt') and direction == 'reverse':
                server_command += ['--session', 'resume']
                if args.scenario == 'zerortt':
                    server_command += ['--early', 'buffered']
            if args.scenario == 'chacha20':
                server_command += ['--cipher', 'chacha20'] if direction == 'reverse' else ['-c', 'TLS_CHACHA20_POLY1305_SHA256']
            log_path = root / 'server.log'
            with log_path.open('w') as log:
                server = subprocess.Popen(server_command, env=env, stdout=log, stderr=log, text=True)
                result = None
                try:
                    wait_ready(server, log_path)
                    if args.scenario == 'zerortt' and direction != 'reverse' and not args.client_early_reject:
                        # Native Neqo correctly rejects early data for ten seconds
                        # after startup. Unlike its QNS mode, do not shift its clock.
                        time.sleep(11)
                    proxy_context = (EarlyWireProbe(('127.0.0.1', server_port), client_endpoints=2 if direction == 'forward' else 1, drop_first_early=args.client_early_loss) if args.scenario == 'zerortt' else UdpProxy(('127.0.0.1', server_port), **options) if options else nullcontext(None))
                    with proxy_context as proxy:
                        client_port = proxy.address[1] if proxy else server_port
                        address = f'[::1]:{client_port}' if ipv6 else f'127.0.0.1:{client_port}'
                        urls = [f'https://localhost:{client_port}/{name}' for name in names]
                        if direction == 'forward':
                            command = [str(hq), 'client', '--connect', address, '--server-name', 'localhost', '--ca', str(root / 'ca.pem'), '--downloads', str(destination), '--timeout-seconds', str(args.timeout_seconds)]
                            if args.scenario in ('resumption', 'zerortt'):
                                command += ['--session', 'resume']
                                if args.scenario == 'zerortt':
                                    command += ['--early', 'replay-safe']
                            if args.scenario == 'keyupdate':
                                command += ['--key-update', 'once']
                            for url in urls:
                                command += ['--request', url]
                        else:
                            command = [str(nc), '--qns-test', args.scenario if args.scenario in ('resumption', 'zerortt', 'keyupdate') else 'transfer', '-Q', '1', '--ipv6-only' if ipv6 else '--ipv4-only', '--output-dir', str(destination), '--idle', str(args.timeout_seconds)] + urls
                        if args.scenario == 'chacha20':
                            command += ['--cipher', 'chacha20'] if direction == 'forward' else ['-c', 'TLS_CHACHA20_POLY1305_SHA256']
                        started = time.monotonic()
                        try:
                            result = run(command, env, timeout=args.timeout_seconds + 5)
                            returncode = result.returncode
                        except subprocess.TimeoutExpired as error:
                            result = error
                            returncode = 'timeout'
                        resumed_report = None
                        if args.scenario in ('resumption', 'zerortt') and direction != 'baseline' and returncode == 0:
                            if direction == 'reverse':
                                server.wait(timeout=args.timeout_seconds + 5)
                                if server.returncode != 0:
                                    raise AssertionError('resumption server did not complete')
                                lines = log_path.read_text().splitlines()
                            else:
                                lines = result.stdout.splitlines()
                            candidates = [json.loads(line) for line in lines if line.startswith('{')]
                            resumed_report = next((row for row in candidates if row.get('backend') == 'direct-hibana-roles'), None)
                            assert resumed_report and resumed_report['connections'] == 2 and resumed_report['resumed'], resumed_report
                            assert resumed_report['lifecycle_closed'], resumed_report
                            if direction == 'forward':
                                assert resumed_report['all_streams_acked'], resumed_report
                            if args.scenario == 'zerortt':
                                if args.client_early_reject:
                                    assert resumed_report['early_accepted_packets'] == 0, resumed_report
                                    assert resumed_report['early_finished_streams'] == 0, resumed_report
                                    assert resumed_report['early_stream_bytes'] == 0, resumed_report
                                else:
                                    assert resumed_report['early_accepted_packets'] > 0, resumed_report
                                    assert 0 < resumed_report['early_finished_streams'] <= len(names) - 1, resumed_report
                                    assert resumed_report['early_stream_bytes'] > 0, resumed_report
                                assert proxy.stats['zero_rtt_packets'] > 0, dict(proxy.stats)
                                assert proxy.stats['unclassified_client_datagrams'] == 0, dict(proxy.stats)
                                if args.early_files == 40 and not args.client_early_reject:
                                    # Match the runner's protected-payload bound conservatively,
                                    # retaining protected PN/tag/padding and all retransmissions.
                                    assert proxy.stats['one_rtt_protected_payload_upper_bound'] <= 5000, dict(proxy.stats)
                        if args.scenario == 'zerortt' and direction == 'baseline' and args.early_files == 40:
                            assert proxy.stats['unclassified_client_datagrams'] == 0, dict(proxy.stats)
                            assert proxy.stats['zero_rtt_packets'] > 0, dict(proxy.stats)
                            assert proxy.stats['one_rtt_protected_payload_upper_bound'] <= 5000, dict(proxy.stats)
                        files = [{'name': name, 'bytes': (destination / name).stat().st_size if (destination / name).exists() else None, 'expected_sha256': sha(www / name), 'received_sha256': sha(destination / name) if (destination / name).exists() else None} for name in names]
                        row = {'direction': direction, 'client_exit': returncode, 'elapsed_seconds': round(time.monotonic() - started, 3), 'files': files, 'proxy': dict(proxy.stats) if proxy else None, 'resumed_two_connections': bool(resumed_report), 'early_accepted_packets': resumed_report.get('early_accepted_packets', 0) if resumed_report else 0, 'early_stream_bytes': resumed_report.get('early_stream_bytes', 0) if resumed_report else 0, 'early_finished_streams': resumed_report.get('early_finished_streams', 0) if resumed_report else 0}
                        report['runs'].append(row)
                        save()
                        if args.client_early_loss:
                            assert proxy.stats['first_early_dropped'] == 1, dict(proxy.stats)
                        if args.scenario == 'blackhole':
                            assert sum(v for k, v in proxy.stats.items() if k.endswith('_blackhole_dropped')) > 0, dict(proxy.stats)
                        if args.scenario == 'keyupdate' and returncode == 0:
                            if direction == 'forward':
                                actual = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith('{'))
                                assert actual['key_generation'] >= 1 and actual['lifecycle_closed'], actual
                            else:
                                assert 'Initiating key update' in result.stderr, 'reference never actually initiated key update'
                        if returncode != 0 or any(x['expected_sha256'] != x['received_sha256'] for x in files):
                            if args.scenario == 'keyupdate':
                                try:
                                    server.wait(timeout=1)
                                except subprocess.TimeoutExpired:
                                    pass
                            raise AssertionError(f'{args.scenario}/{direction}: exit={returncode}, received byte hashes did not all qualify')
                finally:
                    stop(server)
                    if args.private_log_dir:
                        args.private_log_dir.mkdir(parents=True, exist_ok=True)
                        (args.private_log_dir / f'{args.scenario}-{direction}-server.log').write_bytes(log_path.read_bytes())
                        if result is not None:
                            (args.private_log_dir / f'{args.scenario}-{direction}-client.log').write_text(''.join(
                                part.decode(errors='replace') if isinstance(part, bytes) else part or ''
                                for part in (result.stdout, result.stderr)))
    save()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
