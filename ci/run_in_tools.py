#!/usr/bin/env python3
"""Unchanged pinned runner; separate implementation config, bounded safe evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(os.environ['ROOT']).resolve()
RUNNER = ROOT / '.ci-work/runner'
SAFE = ROOT / 'ci-safe-results'
RAW = ROOT / '.ci-work/raw'
EXPECTED = {'handshake', 'transfer'}
SAFE_VALIDATION_ERRORS = {'wrong QUIC version', 'wrong matrix direction', 'missing result row', 'unexpected/duplicate case', 'case abbreviation mismatch', 'missing case', 'unknown case result'}
CONSOLE_CLASSES = {'ModuleNotFoundError': 'python-dependency', 'unrecognized arguments:': 'runner-cli-arguments', 'No such file or directory': 'missing-tool-or-file', 'Cannot connect to the Docker daemon': 'docker-daemon-unavailable', 'Error response from daemon': 'docker-environment', 'no matching manifest': 'container-image-platform', 'permission denied': 'permission-denied', 'tshark not found': 'tshark-unavailable',
    'not compliant.': 'implementation-compliance-failed',
    'pull access denied': 'image-pull-denied', 'no such image': 'image-unavailable',
    'invalid reference format': 'image-reference-invalid',
    'unable to get image': 'image-resolution-failed',
    'client version': 'docker-api-client-version',
    'interface_name requires Docker Engine': 'docker-engine-interface-name-prerequisite',
    'unknown flag': 'docker-cli-flag', 'additional property': 'compose-schema',
    'must be a mapping': 'compose-schema', 'invalid interpolation': 'compose-interpolation',
    'failed to create network': 'docker-network-create',
    'pool overlaps': 'docker-network-overlap', 'ipv6 is disabled': 'docker-ipv6-disabled',
    'failed to create task': 'container-task-create', 'oci runtime': 'container-runtime',
    'executable file not found': 'container-executable',
    'address already in use': 'address-in-use', 'operation not permitted': 'operation-not-permitted'}

def console_classes(text):
    return sorted({label for pattern, label in CONSOLE_CLASSES.items() if pattern.lower() in text.lower()})

def docker_metadata():
    # Only fixed fields/classifications are published, never subprocess output.
    proc = subprocess.run(['docker', 'version', '--format', '{{json .Server}}'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    record = {'version_exit_code': proc.returncode,
        'error_classes': console_classes(proc.stderr), 'effective_uid': os.geteuid(),
        'runner_owner_uid': RUNNER.stat().st_uid,
        'socket_gid': Path('/var/run/docker.sock').stat().st_gid,
        'process_groups': os.getgroups()}
    if proc.returncode == 0:
        data = json.loads(proc.stdout)
        record['server'] = {key: data.get(key) for key in ('Version', 'ApiVersion', 'MinAPIVersion', 'GitCommit')}
    record['images'] = {}
    for key in ('NEQO_IMAGE', 'BOUNDED_IMAGE', 'SIM_IMAGE'):
        image = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', os.environ[key]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        value = image.stdout.strip()
        record['images'][key] = {'exit_code': image.returncode,
            'id': value if re.fullmatch(r'sha256:[a-f0-9]{64}', value) else None,
            'error_classes': console_classes(image.stderr)}
    write('docker-preflight.json', record)
    require(proc.returncode == 0 and all(v['exit_code'] == 0 and v['id'] for v in record['images'].values()), 'docker preflight failed')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(name, value):
    (SAFE / name).write_text(json.dumps(value, indent=2) + '\n')

def require(test, message):
    if not test:
        raise RuntimeError(message)

def checked_result(path, client, server):
    data = json.loads(path.read_text())
    require(data.get('quic_version') == '0x1', 'wrong QUIC version')
    require(data.get('clients') == [client] and data.get('servers') == [server], 'wrong matrix direction')
    rows = data.get('results')
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], list), 'missing result row')
    seen = set()
    normalized = []
    for entry in rows[0]:
        name, result, abbr = entry.get('name'), entry.get('result'), entry.get('abbr')
        require(name in EXPECTED and name not in seen, 'unexpected/duplicate case')
        require(data.get('tests', {}).get(abbr, {}).get('name') == name, 'case abbreviation mismatch')
        require(result in (None, 'succeeded', 'failed', 'unsupported'), 'unknown case result')
        seen.add(name)
        normalized.append({'name': name, 'result': result, 'abbr': abbr})
    require(seen == EXPECTED, 'missing case')
    return {'quic_version': '0x1', 'client': client, 'server': server,
            'results': normalized, 'original_json_sha256': sha(path),
            'non_null_case_results': sum(item['result'] is not None for item in normalized),
            'unexecuted_case_results': sum(item['result'] is None for item in normalized),
            'passed': all(item['result'] == 'succeeded' for item in normalized)}

def setup_workdir(name, candidate):
    work = ROOT / '.ci-work' / name
    work.mkdir()
    # Only registration/config lives outside the untouched source checkout.
    for path in RUNNER.iterdir():
        if path.name not in ('.git', 'implementations_quic.json'):
            (work / path.name).symlink_to(path)
    config = json.loads((RUNNER / 'implementations_quic.json').read_text())
    config['neqo']['image'] = os.environ['NEQO_IMAGE']
    if candidate:
        config['hibana-quic'] = {'image': os.environ['BOUNDED_IMAGE'],
            'url': 'https://github.com/hibanaworks/hibana-quic', 'role': 'both'}
    (work / 'implementations_quic.json').write_text(json.dumps(config, indent=2) + '\n')
    overlay = work / 'pinned-images.override.yml'
    overlay.write_text('services:\n  sim:\n    image: ' + os.environ['SIM_IMAGE'] + '\n    pull_policy: never\n')
    return work, overlay

def phase(name, client, server, candidate):
    work, overlay = setup_workdir(name, candidate)
    output = RAW / (name + '.json')
    logs = RAW / (name + '-logs')
    console = RAW / (name + '-console.log')
    env = os.environ.copy()
    env['COMPOSE_FILE'] = str(RUNNER / 'docker-compose.yml') + ':' + str(overlay)
    env['COMPOSE_PROJECT_NAME'] = 'hibana-pilot'
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    cmd = [sys.executable, str(RUNNER / 'run.py'), '-s', server, '-c', client,
           '-d', '-t', 'handshake,transfer', '-n', client + ',' + server,
           '-j', str(output), '-l', str(logs)]
    record = {'phase': name, 'client': client, 'server': server, 'status': 'NOT_RUN'}
    started = time.monotonic()
    try:
        print('Starting ' + name, flush=True)
        with console.open('wb') as log:
            proc = subprocess.run(cmd, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        record['exit_code'] = proc.returncode
        record['runner_log_sha256'] = sha(console)
        record.update(checked_result(output, client, server))
        record['status'] = 'PASSED' if proc.returncode == 0 and record['passed'] else 'FAILED'
    except subprocess.TimeoutExpired:
        record['status'] = 'TIMEOUT'
    except Exception as error:
        record['status'] = 'INFRASTRUCTURE_OR_RESULT_FAILURE'
        # Only our bounded validation/exception class, never raw peer logs.
        record['error_type'] = type(error).__name__
        if isinstance(error, RuntimeError) and str(error) in SAFE_VALIDATION_ERRORS:
            record['validation_reason'] = str(error)
    finally:
        try:
            cleanup = subprocess.run(['docker', 'compose', '--env-file', 'empty.env', 'down', '--timeout', '1'], cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            record['cleanup_exit_code'] = cleanup.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            record['cleanup_error_type'] = type(error).__name__
        if console.exists():
            text = console.read_text(errors='replace')
            record['console_error_classes'] = console_classes(text)
        record['duration_seconds'] = round(time.monotonic() - started, 3)
        # Hash/count evidence only. Packet captures, qlogs, certificate/private-key
        # fixtures, raw application logs and all TLS key logs are never uploaded.
        captures = sorted(logs.rglob('*.pcap')) if logs.exists() else []
        record['captures'] = [{'name': str(p.relative_to(logs)), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in captures]
        write(name + '.json', record)
        print(name + ': ' + record['status'], flush=True)
    return record

def main():
    SAFE.mkdir(exist_ok=True)
    RAW.mkdir(exist_ok=True)
    version = subprocess.check_output(['tshark', '--version'], text=True).splitlines()[0]
    match = re.search(r'(\d+)\.(\d+)\.\d+', version)
    require(match and tuple(map(int, match.groups())) >= (4, 5), 'tshark too old')
    write('tools.json', {'tshark': version, 'python': sys.version,
        'compose': subprocess.check_output(['docker', 'compose', 'version'], text=True).strip(),
        'python_packages': subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'], text=True).splitlines()})
    require(subprocess.check_output(['git', '-C', str(RUNNER), 'rev-parse', 'HEAD'], text=True).strip() == os.environ['RUNNER_REVISION'], 'runner pin mismatch')
    require(not subprocess.check_output(['git', '-C', str(RUNNER), 'status', '--porcelain'], text=True).strip(), 'runner checkout changed')
    docker_metadata()
    records = []
    baseline = phase('neqo-baseline', 'neqo', 'neqo', False)
    records.append(baseline)
    if baseline['status'] == 'PASSED':
        records.append(phase('bounded-client', 'hibana-quic', 'neqo', True))
        records.append(phase('bounded-server', 'neqo', 'hibana-quic', True))
    clean = not subprocess.check_output(['git', '-C', str(RUNNER), 'status', '--porcelain'], text=True).strip()
    passed = len(records) == 3 and all(r['status'] == 'PASSED' for r in records) and clean
    write('summary.json', {'status': 'PASSED' if passed else 'NOT_PASSED',
        'scope': 'one unmodified runner pilot: Neqo baseline plus two-case bounded subset each direction',
        'runner_source_unchanged': clean, 'phases': [r['phase'] for r in records],
        'case_results': sum(len(r.get('results', [])) for r in records),
        'non_null_case_results': sum(r.get('non_null_case_results', 0) for r in records),
        'unexecuted_case_results': sum(r.get('unexecuted_case_results', 0) for r in records),
        'full_runner_gate_passed': False,
        'not_claimed': ['remaining runner cases', 'three release attempts', 'Pico hardware', 'whole-host zero allocation'],
        'withheld': ['TLS secrets/key logs', 'private certificate keys', 'tickets', 'raw logs', 'raw packet captures']})
    return 0 if passed else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        write('infrastructure-failure.json', {'status': 'NOT_PASSED', 'error_type': type(error).__name__})
        raise
