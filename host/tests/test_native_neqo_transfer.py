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
import re
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from udp_impairment import UdpProxy, EarlyWireProbe, MultiEndpointProxy, VersionWireProbe, RebindingWireProbe

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fixture', HERE / 'test_direct_handshake_localhost.py')
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def version_probe(port, ipv6=False):
    # The unmodified QNS simulator waits for this reserved-version response
    # before it starts captures or the reference client. No connection is used.
    probe = b'\xc0WAIT\x00\x00' + bytes(1200)
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = ('::1' if ipv6 else '127.0.0.1', port)
    with socket.socket(family, socket.SOCK_DGRAM) as peer:
        peer.settimeout(2)
        peer.sendto(probe, address)
        reply, source = peer.recvfrom(1500)
    assert source[1] == port
    assert len(reply) <= 3 * len(probe)
    assert reply[0] & 0x80 and reply[1:7] == bytes(6), reply.hex()
    assert reply[7:] == b'\x00\x00\x00\x01', reply.hex()


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
    parser.add_argument('--scenario', choices=('clean', 'handshake', 'longrtt', 'loss', 'corruption', 'ipv6', 'chacha20', 'resumption', 'zerortt', 'blackhole', 'keyupdate', 'multiconnect', 'multiplexing', 'v2', 'rebind-port', 'rebind-addr', 'connectionmigration', 'http3'), default='clean')
    parser.add_argument('--private-log-dir', type=Path)
    parser.add_argument('--require-ecn', action='store_true', help='require actual ECN send, authenticated feedback, received marks and accepted ACK_ECN in clean native transfers')
    parser.add_argument('--client-retry', action='store_true', help='native Retry reception, forward clean direction only')
    parser.add_argument('--server-retry', action='store_true', help='native Retry admission, reverse clean direction only')
    parser.add_argument('--direction', choices=('all', 'baseline', 'forward', 'reverse'), default='all')
    parser.add_argument('--timeout-seconds', type=int, default=60)
    parser.add_argument('--migration-delay-ms', type=int, default=0,
                        help='finite initial-path delay for native preferred-address diagnostics')
    parser.add_argument('--migration-preferred-ip', choices=('127.0.0.1', '127.0.0.2'), default='127.0.0.1')
    parser.add_argument('--migration-ipv6', action='store_true')
    parser.add_argument('--migration-wildcard', action='store_true',
                        help='bind the unchanged reference to [::], matching its QNS listener')
    parser.add_argument('--migration-body-mib', type=int, choices=(2, 16), default=2)
    parser.add_argument('--early-files', type=int, choices=[2, 40], default=2)
    parser.add_argument('--client-keyupdate', action='store_true')
    parser.add_argument('--expect-idle-expiry', action='store_true')
    parser.add_argument('--multi-burst', type=int, choices=(1, 3), default=1)
    parser.add_argument('--multi-impairment', choices=('none', 'loss', 'corruption'), default='none')
    parser.add_argument('--client-early', action='store_true')
    parser.add_argument('--client-early-loss', action='store_true', help='drop the first real 0-RTT datagram; forward direction only')
    parser.add_argument('--client-early-reject', action='store_true', help='native Neqo startup rejection; forward direction only')
    parser.add_argument('--ordinary-files', type=int, choices=[3, 5, 40, 64], default=3)
    args = parser.parse_args()
    if not 0 <= args.migration_delay_ms <= 1000 or (args.migration_delay_ms and args.scenario != 'connectionmigration'):
        parser.error('--migration-delay-ms requires connectionmigration and 0..1000 ms')
    if args.migration_ipv6 and (args.scenario != 'connectionmigration'):
        parser.error('--migration-ipv6 requires connectionmigration')
    if args.migration_wildcard and not args.migration_ipv6:
        parser.error('--migration-wildcard requires --migration-ipv6')
    if (args.client_early_reject or args.client_early_loss) and (args.scenario != 'zerortt' or not args.client_early):
        parser.error('early fault scenarios require --scenario zerortt --client-early')
    if args.client_early_reject and args.client_early_loss:
        parser.error('select acceptance/loss or rejection separately')
    if args.client_keyupdate and args.scenario != 'keyupdate':
        parser.error('--client-keyupdate requires --scenario keyupdate')
    if args.expect_idle_expiry and (args.scenario != 'multiconnect' or args.direction != 'reverse' or args.multi_impairment == 'none'):
        parser.error('--expect-idle-expiry requires impaired reverse multiconnect')
    if args.require_ecn and (args.scenario != 'clean' or args.direction not in ('forward', 'reverse')):
        parser.error('--require-ecn requires one clean candidate direction')
    if args.client_retry and (args.direction != 'forward' or args.scenario != 'clean'):
        parser.error('--client-retry requires --direction forward --scenario clean')
    if args.server_retry and (args.direction != 'reverse' or args.scenario != 'clean'):
        parser.error('--server-retry requires --direction reverse --scenario clean')
    hq, nc, ns, nss = (p.resolve() for p in (args.hq, args.neqo_client, args.neqo_server, args.nss))
    env = os.environ.copy()
    env['RUST_LOG'] = 'debug'
    if args.scenario in ('blackhole', 'keyupdate', 'multiconnect', 'connectionmigration'):
        env['HIBANA_QUIC_DIAGNOSTICS'] = '1'
    env['LD_LIBRARY_PATH'] = str(nss / 'lib')
    env.pop('SSLKEYLOGFILE', None)
    ipv6 = args.scenario == 'ipv6' or args.migration_ipv6
    sizes = [5 << 10, 10 << 10] if args.scenario == 'resumption' else [32, 33] if args.scenario == 'zerortt' else [3 << 20] if args.scenario in ('chacha20', 'keyupdate') else [1024] if args.scenario == 'longrtt' else ([2 << 20] if args.scenario in ('loss', 'corruption') else [2 << 20, 3 << 20, 5 << 20])
    if args.scenario == 'handshake':
        sizes = [1024]
    if args.scenario == 'http3':
        sizes = [5 << 10, 10 << 10, 500 << 10]
    if args.scenario == 'v2':
        sizes = [1024]
    if args.scenario == 'connectionmigration':
        sizes = [args.migration_body_mib << 20]
    if args.scenario in ('rebind-port','rebind-addr'):
        sizes = [10 << 20]
    if args.scenario == 'multiconnect':
        sizes = list(range(1024, 1074))
    if args.scenario == 'multiplexing':
        sizes = [32] * 1999
    if args.scenario == 'blackhole':
        sizes = [10 << 20]
    if args.ordinary_files != 3:
        if args.scenario != 'clean':
            parser.error('--ordinary-files requires the clean scenario')
        sizes = [131072 + index for index in range(args.ordinary_files)]
    options = {'delay': 0.75} if args.scenario == 'longrtt' else (
        {'delay': 0.015, 'drop_rate': 2, 'burst': 3} if args.scenario == 'loss' else (
            {'delay': 0.015, 'corrupt_rate': 2, 'burst': 3} if args.scenario == 'corruption' else None
        )
    )
    if args.scenario == 'blackhole':
        options = {'blackhole_after_bytes': 4 << 20, 'blackhole_seconds': 2.0}
    if args.scenario == 'connectionmigration' and args.migration_delay_ms:
        options = {'delay': args.migration_delay_ms / 1000}
    if args.multi_impairment != 'none':
        if args.scenario != 'multiconnect':
            parser.error('--multi-impairment requires multiconnect')
        options = {'client_endpoints': 50, 'delay': 0.015,
                   ('drop_every' if args.multi_impairment == 'loss' else 'corrupt_every'): 10 if args.multi_burst == 3 else 3,
                   'burst': args.multi_burst}
    report = {
        'scope': 'native-peer-diagnostics', 'official_interop_pass': False,
        'scenario': args.scenario, 'server_retry': args.server_retry, 'client_retry': args.client_retry, 'impairment': options, 'ordinary_files': len(sizes),
        'migration_ipv6': args.migration_ipv6, 'migration_preferred_ip': args.migration_preferred_ip,
        'migration_wildcard': args.migration_wildcard,
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
        if args.direction != 'all':
            directions = tuple(d for d in directions if d == args.direction)
            if not directions:
                parser.error('direction is incompatible with the selected scenario')
        for direction in directions:
            destination = root / direction
            destination.mkdir()
            www = root / ('www-' + direction)
            www.mkdir()
            case_sizes = sizes
            names = [str(size) for size in sizes]
            if args.scenario == 'multiplexing':
                if direction == 'reverse':
                    names = [f'file-{index:04d}' for index in range(1999)]
                else:
                    # Unmodified native Neqo serves numeric-sized resources.
                    # Distinct names are required: repeating /32 is not 1999 files.
                    case_sizes = list(range(32, 2031))
                    names = [str(size) for size in case_sizes]
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
            preferred_port = unused_port(ipv6)
            server_address = f'[::1]:{server_port}' if ipv6 else f'127.0.0.1:{server_port}'
            if args.migration_wildcard and direction != 'reverse':
                server_address = f'[::]:{server_port}'
            if direction == 'reverse':
                server_command = [str(hq), 'server', '--listen', server_address, '--cert', str(root / 'server.pem'), '--key', str(root / 'server.key'), '--www', str(www), '--max-requests', str(64 if args.scenario in ('resumption', 'zerortt') else len(names)), '--timeout-seconds', str(args.timeout_seconds)]
            else:
                server_command = [str(ns), '-a', 'h3' if args.scenario == 'http3' else 'hq-interop', '-Q', '1', '-d', str(db), '-k', 'native-peer', '--idle', str(args.timeout_seconds), server_address]
            if args.scenario == 'http3' and direction == 'reverse':
                server_command += ['--http', '3']
            if args.scenario == 'connectionmigration':
                if direction == 'reverse': server_command += ['--preferred-port', str(preferred_port)]
                elif ipv6: server_command += ['--preferred-address-v6', f'[::1]:{preferred_port}']
                else: server_command += ['--preferred-address-v4', f'{args.migration_preferred_ip}:{preferred_port}']
            if args.scenario == 'v2':
                if direction == 'reverse': server_command += ['--version','2']
                else:
                    server_command[server_command.index('-Q')+1]='6b3343cf'
                    server_command += ['-Q','1']
            if args.client_retry:
                server_command += ['--retry']
            if args.server_retry:
                server_command += ['--retry', 'required']
            if args.scenario == 'zerortt' and direction != 'reverse':
                # Match the reference's QNS zerortt stream-credit configuration.
                server_command += ['--max-streams-bidi', '100']
            if args.scenario in ('resumption', 'zerortt') and direction == 'reverse':
                server_command += ['--session', 'resume']
                if args.scenario == 'zerortt':
                    server_command += ['--early', 'buffered']
            if args.scenario == 'multiconnect' and direction == 'reverse':
                server_command += ['--session', 'multi', '--connections', str(len(names))]
            if args.scenario == 'chacha20':
                server_command += ['--cipher', 'chacha20'] if direction == 'reverse' else ['-c', 'TLS_CHACHA20_POLY1305_SHA256']
            log_path = root / 'server.log'
            with log_path.open('w') as log:
                server = subprocess.Popen(server_command, env=env, stdout=log, stderr=log, text=True)
                result = None
                try:
                    wait_ready(server, log_path)
                    if direction == 'reverse':
                        version_probe(server_port, ipv6)
                    if args.scenario == 'zerortt' and direction != 'reverse' and not args.client_early_reject:
                        # Native Neqo correctly rejects early data for ten seconds
                        # after startup. Unlike its QNS mode, do not shift its clock.
                        time.sleep(11)
                    proxy_context = (EarlyWireProbe(('127.0.0.1', server_port), client_endpoints=2 if direction == 'forward' else 1, drop_first_early=args.client_early_loss) if args.scenario == 'zerortt' else (MultiEndpointProxy if args.scenario == 'multiconnect' else UdpProxy)(('::1' if ipv6 else '127.0.0.1', server_port), **options) if options else nullcontext(None))
                    if args.scenario == 'v2': proxy_context = VersionWireProbe(('127.0.0.1',server_port))
                    if args.scenario in ('rebind-port','rebind-addr'): proxy_context = RebindingWireProbe(('127.0.0.1',server_port),change_address=args.scenario=='rebind-addr')
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
                            if args.scenario == 'multiconnect':
                                command += ['--session', 'multi']
                            if args.scenario == 'keyupdate':
                                command += ['--key-update', 'once']
                            for url in urls:
                                command += ['--request', url]
                        else:
                            command = [str(nc), '--qns-test', args.scenario if args.scenario in ('resumption', 'zerortt', 'keyupdate', 'multiconnect', 'v2', 'http3') else 'transfer', '-Q', '1', '--ipv6-only' if ipv6 else '--ipv4-only', '--output-dir', str(destination), '--idle', str(args.timeout_seconds)] + urls
                        if args.scenario == 'http3' and direction == 'forward':
                            command += ['--http', '3']
                        if args.scenario == 'v2':
                            command += ['--version','2'] if direction=='forward' else ['-Q','6b3343cf','-Q','1']
                        if args.scenario == 'chacha20':
                            command += ['--cipher', 'chacha20'] if direction == 'forward' else ['-c', 'TLS_CHACHA20_POLY1305_SHA256']
                        started = time.monotonic()
                        try:
                            result = run(command, env, timeout=args.timeout_seconds + 5)
                            returncode = result.returncode
                        except subprocess.TimeoutExpired as error:
                            result = error
                            returncode = 'timeout'
                        client_elapsed = time.monotonic() - started
                        if direction == 'reverse' and returncode != 0:
                            # Diagnostic tail only: a failed client remains failed.
                            try: server.wait(timeout=2)
                            except subprocess.TimeoutExpired: pass

                        # Retain verified transfer observations even when the
                        # later clean-retirement assertion fails. Never turn
                        # this diagnostic into an official/closed verdict.
                        observed = [{'name': name,
                                     'expected_sha256': sha(www / name),
                                     'received_sha256': sha(destination / name) if (destination / name).is_file() else None}
                                    for name in names]
                        report.setdefault('transfer_observations', []).append({
                            'direction': direction, 'client_exit': returncode,
                            'client_elapsed_seconds': round(client_elapsed, 3),
                            'expected_files': len(names),
                            'matching_files': sum(item['expected_sha256'] == item['received_sha256'] for item in observed),
                            'retirement_verified': False,
                        })
                        save()
                        resumed_report = None
                        if args.scenario == 'multiplexing' and direction != 'baseline' and returncode == 0:
                            if direction == 'reverse':
                                server.wait(timeout=args.timeout_seconds + 5)
                                assert server.returncode == 0, 'multiplexing server retirement failed'
                                actual_text = log_path.read_text()
                            else:
                                actual_text = result.stdout
                            resumed_report = next(json.loads(line) for line in actual_text.splitlines() if line.startswith('{'))
                            assert resumed_report['connections'] == 1, resumed_report
                            assert resumed_report['files_completed'] == 1999, resumed_report
                            assert resumed_report['resources_retired'] and resumed_report['lifecycle_closed'] and resumed_report['http_transfer_complete'], resumed_report
                            assert isinstance(resumed_report['all_streams_acked'], bool), resumed_report
                            report['transfer_observations'][-1]['retirement_verified'] = True
                            save()
                        if args.scenario in ('resumption', 'zerortt', 'multiconnect') and direction != 'baseline' and returncode == 0:
                            if direction == 'reverse':
                                server.wait(timeout=args.timeout_seconds + 5)
                                if server.returncode != 0:
                                    raise AssertionError(f'{args.scenario} server did not complete')
                                lines = log_path.read_text().splitlines()
                            else:
                                lines = result.stdout.splitlines()
                            candidates = [json.loads(line) for line in lines if line.startswith('{')]
                            resumed_report = next((row for row in candidates if row.get('backend') == 'direct-hibana-roles'), None)
                            assert resumed_report and resumed_report['connections'] == (50 if args.scenario == 'multiconnect' else 2), resumed_report
                            if args.scenario != 'multiconnect':
                                assert resumed_report['resumed'], resumed_report
                            else:
                                assert 0 <= resumed_report['resumed_connections'] < 50, resumed_report
                                if direction == 'reverse' and args.multi_impairment == 'none':
                                    assert resumed_report['resumed_connections'] == 49, resumed_report
                            if args.expect_idle_expiry:
                                assert resumed_report['resources_retired'], resumed_report
                                assert 0 < resumed_report['idle_expired_connections'] <= 50, resumed_report
                                assert not resumed_report['lifecycle_closed'], resumed_report
                                assert not resumed_report['http_transfer_complete'], resumed_report
                            else:
                                assert resumed_report['lifecycle_closed'], resumed_report
                            report['transfer_observations'][-1]['retirement_verified'] = resumed_report.get('resources_retired', False)
                            if direction == 'forward':
                                # ResponsesComplete is an actual FIN-based application terminal.
                                # Keep the ACK observation distinct; never fabricate true.
                                assert resumed_report['http_transfer_complete'], resumed_report
                                assert resumed_report['files_completed'] == len(names), resumed_report
                                assert isinstance(resumed_report['all_streams_acked'], bool), resumed_report
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
                        ecn_observation = None
                        if args.require_ecn and returncode == 0:
                            if direction == 'reverse':
                                server.wait(timeout=args.timeout_seconds + 5)
                                assert server.returncode == 0, 'ECN server retirement failed'
                                actual_text = log_path.read_text()
                                peer_text = result.stdout + result.stderr
                            else:
                                actual_text = result.stdout
                                peer_text = log_path.read_text()
                            actual = next(json.loads(line) for line in actual_text.splitlines() if line.startswith('{'))
                            for key in ('ecn_accepted_packets', 'ecn_validated_packets', 'ecn_received_packets', 'ecn_acknowledgments_sent'):
                                assert actual[key] > 0, (key, actual)
                            assert actual['ecn_feedback_error'] is None, actual
                            assert actual['resources_retired'] and actual['lifecycle_closed'] and actual['http_transfer_complete'], actual
                            ecn_observation = {key: actual[key] for key in ('ecn_accepted_packets', 'ecn_validated_packets', 'ecn_received_packets', 'ecn_acknowledgments_sent', 'ecn_feedback_error')}
                            # The peer may legitimately still be testing its first ten
                            # probes. Record its report without inventing capability.
                            ecn_observation['peer_reported_capable'] = 'ECN validation succeeded, path is capable' in peer_text
                            report['transfer_observations'][-1]['retirement_verified'] = True
                        files = [{'name': name, 'bytes': (destination / name).stat().st_size if (destination / name).exists() else None, 'expected_sha256': sha(www / name), 'received_sha256': sha(destination / name) if (destination / name).exists() else None} for name in names]
                        row = {'direction': direction, 'client_exit': returncode, 'client_elapsed_seconds': round(client_elapsed, 3), 'post_client_verification_and_retirement_seconds': round(time.monotonic() - started - client_elapsed, 3), 'elapsed_seconds': round(time.monotonic() - started, 3), 'files': files, 'proxy': dict(proxy.stats) if proxy else None, 'connections': resumed_report.get('connections') if resumed_report else None, 'resources_retired': resumed_report.get('resources_retired') if resumed_report else None, 'idle_expired_connections': resumed_report.get('idle_expired_connections') if resumed_report else None, 'lifecycle_closed': resumed_report.get('lifecycle_closed') if resumed_report else None, 'resumed_connections': resumed_report.get('resumed_connections', 0) if resumed_report else None, 'resumed_two_connections': bool(args.scenario != 'multiconnect' and resumed_report and resumed_report['resumed']), 'early_accepted_packets': resumed_report.get('early_accepted_packets', 0) if resumed_report else 0, 'early_stream_bytes': resumed_report.get('early_stream_bytes', 0) if resumed_report else 0, 'early_finished_streams': resumed_report.get('early_finished_streams', 0) if resumed_report else 0}
                        if ecn_observation is not None:
                            row['ecn_observation'] = ecn_observation
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
                        if args.scenario == 'v2' and returncode == 0:
                            actual=dict(proxy.stats)
                            assert actual.get('to_server_v1_type0',0)>0,actual
                            assert actual.get('to_client_v6b3343cf_type0',0)>0,actual
                            for side in ('to_server','to_client'):
                                assert actual.get(side+'_v6b3343cf_type2',0)>0,actual
                                assert actual.get(side+'_v1_type2',0)==0,actual
                            row['version_wire_observations']=actual
                        if args.scenario in ('rebind-port','rebind-addr') and returncode == 0:
                            assert proxy.stats['actual_rebindings']==2,proxy.stats
                            assert len(set(proxy.paths))==3,proxy.paths
                            if args.scenario=='rebind-addr': assert len({p[0] for p in proxy.paths})==3,proxy.paths
                            row['observed_paths']=proxy.paths
                            if direction!='reverse':
                                text=log_path.read_text()
                                sent=set(re.findall(r'TX -> PathChallenge \{ data: (\[[0-9, ]+\])',text))
                                received=set(re.findall(r'-> RX PathResponse \{ data: (\[[0-9, ]+\])',text))
                                assert len(sent&received)>=2,(len(sent),len(received))
                                row['peer_matched_path_responses']=len(sent&received)
                            else:
                                text=result.stdout+result.stderr
                                challenges=set(re.findall(r'-> RX PathChallenge \{ data: (\[[0-9, ]+\])',text))
                                responses=set(re.findall(r'TX -> PathResponse \{ data: (\[[0-9, ]+\])',text))
                                assert len(challenges&responses)>=2,(len(challenges),len(responses))
                                row['peer_matched_path_responses']=len(challenges&responses)
                        if returncode == 0 and direction != 'baseline' and not args.expect_idle_expiry:
                            if direction=='reverse':
                                server.wait(timeout=max(0.001, args.timeout_seconds - (time.monotonic() - started)))
                                row['candidate_server_exit'] = server.returncode
                                assert server.returncode == 0, f'{args.scenario}/{direction}: candidate server exited {server.returncode}'
                            text=result.stdout if direction=='forward' else log_path.read_text()
                            terminal=next((json.loads(line) for line in reversed(text.splitlines()) if line.startswith('{')), None)
                            assert terminal is not None, f'{args.scenario}/{direction}: candidate did not publish terminal JSON'
                            assert terminal['tls_finished_authenticated'] and terminal['http_transfer_complete'] and terminal['resources_retired'] and terminal['lifecycle_closed'],terminal
                            if args.scenario == 'http3':
                                assert terminal['connections'] == 1, terminal
                                assert terminal['body_bytes'] == sum(case_sizes), terminal
                                row['application_protocol'] = 'h3'
                            if args.scenario == 'connectionmigration':
                                assert terminal['validated_paths'] >= 1,terminal
                                if direction=='forward': assert terminal['preferred_address_used'],terminal
                                peer_text=log_path.read_text() if direction=='forward' else result.stdout+result.stderr
                                assert 'Path validated' in peer_text, 'reference has no actual path validation'
                                assert str(preferred_port) in peer_text, 'preferred transport endpoint not observed'
                                row['validated_paths']=terminal['validated_paths']
                                row['preferred_address_used']=terminal['preferred_address_used']
                            row.update(resources_retired=True,lifecycle_closed=True)
                            report['transfer_observations'][-1]['retirement_verified']=True
                        if args.client_retry and returncode == 0:
                            assert 'Send retry for' in log_path.read_text(), 'reference never actually issued Retry'
                            terminal = next(json.loads(line) for line in reversed(result.stdout.splitlines()) if line.startswith('{'))
                            assert terminal['tls_finished_authenticated'] and terminal['http_transfer_complete'], terminal
                            assert terminal['resources_retired'] and terminal['lifecycle_closed'], terminal
                            assert terminal['files_completed'] == len(names) and terminal['idle_expired_connections'] == 0, terminal
                            row.update(resources_retired=terminal['resources_retired'], lifecycle_closed=terminal['lifecycle_closed'])
                            report['transfer_observations'][-1]['retirement_verified'] = True
                        if args.server_retry and returncode == 0:
                            server.wait(timeout=max(0.001, args.timeout_seconds - (time.monotonic() - started)))
                            server_text = log_path.read_text()
                            assert 'Retry admission joined with validated token' in server_text, 'no actual token admission receipt'
                            terminal = next(json.loads(line) for line in reversed(server_text.splitlines()) if line.startswith('{'))
                            assert terminal['tls_finished_authenticated'] and terminal['http_transfer_complete'], terminal
                            assert terminal['resources_retired'] and terminal['lifecycle_closed'], terminal
                            assert terminal['files_completed'] == len(names) and terminal['idle_expired_connections'] == 0, terminal
                            row.update(resources_retired=terminal['resources_retired'], lifecycle_closed=terminal['lifecycle_closed'])
                            report['transfer_observations'][-1]['retirement_verified'] = True
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
