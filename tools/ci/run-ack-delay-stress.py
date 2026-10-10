#!/usr/bin/env python3
"""Keep delivery qualification and strict close observations distinct."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def delivery_passed(report, connections=50):
    """Actual authenticated bytes and retirement; never infer a missing close."""
    files = report.get('files', [])
    if (report.get('client_exit') != 0 or report.get('server_exit') != 0
            or len(files) != connections
            or any(not item.get('received_sha256')
                   or item.get('expected_sha256') != item.get('received_sha256')
                   for item in files)):
        return False
    for side in ('client', 'server'):
        result = report.get(side)
        if not isinstance(result, dict):
            return False
        if (result.get('connections') != connections
                or result.get('tls_finished_authenticated') is not True
                or result.get('quic_handshake_confirmed') is not True
                or result.get('resources_retired') is not True
                or result.get('files_submitted') != connections
                or result.get('files_completed') != connections):
            return False
        idle = result.get('idle_expired_connections')
        if not isinstance(idle, int) or not 0 <= idle <= connections:
            return False
        if side == 'client' or idle == 0:
            if (result.get('status') != 'success'
                    or result.get('http_transfer_complete') is not True
                    or result.get('lifecycle_closed') is not True or idle != 0):
                return False
        elif (result.get('status') != 'idle-expired'
              or result.get('lifecycle_closed') is not False):
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=300)
    parser.add_argument('--idle-timeout-seconds', type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 300 or not 0 <= args.idle_timeout_seconds <= 300:
        parser.error('operation timeout must be 1..300 and idle timeout 0..300 seconds')
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(__file__).resolve().parents[2] / 'tests/interop/native/test_direct_parallel_localhost.py'
    summary = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'scope': 'native self-peer stress; separate from official independent interop',
               'criterion': 'authenticated matching files and retired owners; server idle is reported separately',
               'operation_timeout_seconds': args.timeout_seconds,
               'local_idle_timeout_seconds': args.idle_timeout_seconds,
               'cases': []}
    for impairment in ('loss', 'corruption'):
        for seed in range(20261009, 20261014):
            name = f'{impairment}-{seed}'
            path = output / (name + '.json')
            result = subprocess.run([sys.executable, str(fixture), '--binary', str(binary),
                                     '--connections', '50', '--impairment', impairment,
                                     '--impairment-model', 'random', '--impairment-seed', str(seed),
                                     '--loss-scope', 'global', '--timeout-seconds', str(args.timeout_seconds),
                                     '--idle-timeout-seconds', str(args.idle_timeout_seconds),
                                     '--output', str(path)])
            report = json.loads(path.read_text()) if path.exists() else {}
            summary['cases'].append({'name': name, 'exit_code': result.returncode,
                                     'strict_lifecycle_passed': result.returncode == 0,
                                     'server_idle_expired_connections': (report.get('server') or {}).get('idle_expired_connections'),
                                     'passed': delivery_passed(report)})
            summary['passed'] = all(case['passed'] for case in summary['cases'])
            (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
