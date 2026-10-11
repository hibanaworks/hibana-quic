#!/usr/bin/env python3
"""Local Docker entrypoint for the unchanged pinned quic-interop-runner.

Work/results live outside the source checkout. No GitHub Actions impersonation,
daemon upgrade, runner patch, test substitution, or verdict override is used.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def output(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-root', type=Path, required=True)
    parser.add_argument('--tools-image', default='hibana-local-interop-tools')
    parser.add_argument('--neqo-image', default='hibana-local-neqo')
    parser.add_argument('--candidate-image', default='hibana-local-quic')
    parser.add_argument('--sim-image', required=True)
    parser.add_argument('--mode', choices=['baseline', 'pilot', 'matrix'], default='pilot')
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--in-tools', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    work = args.work_root.resolve()
    if work == ROOT or ROOT in work.parents:
        parser.error('--work-root must be outside the source checkout')
    if not re.fullmatch(r'martenseemann/quic-network-simulator@sha256:[a-f0-9]{64}', args.sim_image):
        parser.error('--sim-image must be an immutable simulator digest')
    if args.repetitions < 1:
        parser.error('--repetitions must be positive')
    work.mkdir(parents=True, exist_ok=True)
    if not args.in_tools:
        # Docker bind paths must have the same absolute names in tools and host.
        # /tmp is shared because the official runner creates its fixture there.
        roots = sorted({str(ROOT), str(work)})
        command = ['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}',
                   '--group-add', str(Path('/var/run/docker.sock').stat().st_gid),
                   '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', '/tmp:/tmp']
        for root in roots:
            command += ['-v', f'{root}:{root}']
        command += ['-w', str(ROOT), args.tools_image, 'python3', str(Path(__file__).resolve()),
                    *sys.argv[1:], '--in-tools']
        return subprocess.call(command)

    pins = dict(line.split('=', 1) for line in (ROOT / 'tools/ci/pins.env').read_text().splitlines()
                if line and not line.startswith('#'))
    runner = work / 'runner'
    for checkout, url, revision in [
        (runner, 'https://github.com/quic-interop/quic-interop-runner', pins['RUNNER_REVISION']),
        (work / 'neqo', 'https://github.com/mozilla/neqo', pins['NEQO_REVISION']),
    ]:
        assert output(['git', '-C', str(checkout), 'rev-parse', 'HEAD']) == revision
        assert not output(['git', '-C', str(checkout), 'status', '--porcelain'])
    server = json.loads(output(['docker', 'version', '--format', '{{json .Server}}']))
    assert tuple(map(int, server['ApiVersion'].split('.'))) >= (1, 49), 'interface_name needs API 1.49'
    compose = output(['docker', 'compose', 'version'])
    tshark = output(['tshark', '--version']).splitlines()[0]
    assert tuple(map(int, re.search(r'(\d+)\.(\d+)\.', tshark).groups())) >= (4, 5)
    source = output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'])
    assert not output(['git', '-C', str(ROOT), 'status', '--porcelain']), 'commit candidate source before measuring'
    images = {'neqo': args.neqo_image, 'sim': args.sim_image, 'tools': args.tools_image}
    if args.mode != 'baseline':
        images['hibana-quic'] = args.candidate_image
    image_ids = {name: output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image])
                 for name, image in images.items()}
    if args.mode != 'baseline':
        built_source = output(['docker', 'image', 'inspect', '--format',
            '{{index .Config.Labels "org.opencontainers.image.revision"}}', args.candidate_image])
        assert built_source == source, 'candidate image source SHA differs from checkout'
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    attempt = work / ('attempt-' + stamp)
    attempt.mkdir()
    os.environ['ROOT'] = str(ROOT)
    spec = importlib.util.spec_from_file_location('safe_evidence', ROOT / 'tools/ci/run_in_tools.py')
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    sys.path.insert(0, str(runner))
    from testcases_quic import TESTCASES_QUIC
    # The requested 20 cases target hq-interop and QUIC v1. HTTP/3 and v2 are
    # separate upstream cases and are explicitly excluded from this scope.
    cases = {case.name(): case.abbreviation() for case in TESTCASES_QUIC
             if case.name() not in ('http3', 'v2')}
    assert len(cases) == 20
    records = []

    def phase(name, client, peer, selected, repetition):
        directory = attempt / name
        directory.mkdir()
        for path in runner.iterdir():
            if path.name not in ('.git', 'implementations_quic.json'):
                (directory / path.name).symlink_to(path)
        config = json.loads((runner / 'implementations_quic.json').read_text())
        config['neqo']['image'] = image_ids['neqo']
        if 'hibana-quic' in image_ids:
            config['hibana-quic'] = {'image': image_ids['hibana-quic'],
                'url': 'https://github.com/hibanaworks/hibana-quic', 'role': 'both'}
        save(directory / 'implementations_quic.json', config)
        override = directory / 'images.override.yml'
        override.write_text('services:\n  sim:\n    image: ' + args.sim_image + '\n    pull_policy: never\n')
        env = dict(os.environ, COMPOSE_FILE=f'{runner}/docker-compose.yml:{override}',
                   COMPOSE_PROJECT_NAME='hibana-local', PYTHONDONTWRITEBYTECODE='1')
        command = [sys.executable, str(runner / 'run.py'), '-s', peer, '-c', client,
                   '-d', '-t', ','.join(selected), '-n', f'{client},{peer}',
                   '-j', str(directory / 'raw.json'), '-l', str(directory / 'logs'), '-f', 'true']
        record = dict(phase=name, client=client, server=peer, repetition=repetition,
                      command=command, cwd=str(directory), results=[], exit_code=None)
        start = time.monotonic()
        print('Starting ' + name, flush=True)
        try:
            with (directory / 'console.log').open('wb') as log:
                record['exit_code'] = subprocess.run(command, cwd=directory, env=env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=1800).returncode
            evidence.EXPECTED = set(selected)
            evidence.CASE_ABBREVIATIONS = {name: cases[name] for name in selected}
            record.update(evidence.checked_result(directory / 'raw.json', client, peer))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            record['infrastructure_error'] = type(error).__name__
        finally:
            try:
                record['cleanup_exit_code'] = subprocess.run(
                    ['docker', 'compose', '--env-file', 'empty.env', 'down', '--timeout', '1'],
                    cwd=directory, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=30).returncode
            except (OSError, subprocess.TimeoutExpired):
                record['cleanup_exit_code'] = None
        record['duration_seconds'] = round(time.monotonic() - start, 3)
        raw = (directory / 'console.log').read_bytes()
        record['console_sha256'] = hashlib.sha256(raw).hexdigest()
        record['console_diagnostics'] = evidence.summarize_log(raw)
        record['passed'] = record.get('passed', False) and record['exit_code'] == 0
        for case in selected:
            if not any(row['name'] == case for row in record['results']):
                record['results'].append({'name': case, 'result': None, 'abbr': cases[case]})
        records.append(record)
        save(directory / 'result.json', record)
        print(name + ': ' + str([(row['name'], row['result']) for row in record['results']]), flush=True)
        return record['passed']

    baseline_ok = phase('neqo-baseline', 'neqo', 'neqo', ['handshake', 'transfer'], 1)
    pilot_ok = False
    if baseline_ok and args.mode != 'baseline':
        forward = phase('pilot-client', 'hibana-quic', 'neqo', ['handshake', 'transfer'], 1)
        reverse = phase('pilot-server', 'neqo', 'hibana-quic', ['handshake', 'transfer'], 1)
        pilot_ok = forward and reverse
    if pilot_ok and args.mode == 'matrix':
        for repetition in range(1, args.repetitions + 1):
            phase(f'client-{repetition}', 'hibana-quic', 'neqo', list(cases), repetition)
            phase(f'server-{repetition}', 'neqo', 'hibana-quic', list(cases), repetition)
    clean = not output(['git', '-C', str(runner), 'status', '--porcelain'])
    target_cases = list(cases) if args.mode == 'matrix' else ['handshake', 'transfer']
    repetitions = range(1, args.repetitions + 1) if args.mode == 'matrix' else [1]
    cells = []
    if args.mode != 'baseline':
        for repetition in repetitions:
            for direction, client, peer in [('client', 'hibana-quic', 'neqo'),
                                             ('server', 'neqo', 'hibana-quic')]:
                phase_name = f'{direction}-{repetition}' if args.mode == 'matrix' else f'pilot-{direction}'
                record = next((r for r in records if r['phase'] == phase_name), None)
                for case in target_cases:
                    row = next((r for r in record['results'] if r['name'] == case), None) if record else None
                    result = row['result'] if row else None
                    cells.append(dict(direction=direction, client=client, server=peer,
                        repetition=repetition, case=case, result=result,
                        blocked_by=None if record else ('baseline' if not baseline_ok else 'pilot')))
    counts = {status: sum(c['result'] == status for c in cells)
              for status in ['succeeded', 'failed', 'unsupported', None]}
    counts = dict(passed=counts['succeeded'], executed=counts['succeeded'] + counts['failed'],
                  unsupported=counts['unsupported'], not_run=counts[None], total=len(cells))
    full_passed = bool(cells) and all(c['result'] == 'succeeded' for c in cells)
    summary = dict(source_commit=source, runner_revision=pins['RUNNER_REVISION'],
        neqo_revision=pins['NEQO_REVISION'], hibana_revision=pins['HIBANA_REVISION'],
        image_ids=image_ids, simulator_image=args.sim_image, docker=server['Version'],
        docker_api=server['ApiVersion'], compose=compose, tshark=tshark,
        scope='hq-interop QUIC v1; 20 upstream cases; excludes http3 and v2',
        runner_source_unchanged=clean, baseline_passed=baseline_ok, pilot_passed=pilot_ok,
        full_selected_scope_passed=full_passed, counts=counts, cells=cells, records=records)
    save(attempt / 'summary.json', summary)
    print('Evidence: ' + str(attempt / 'summary.json'), flush=True)
    return 0 if clean and baseline_ok and (args.mode == 'baseline' or full_passed) else 1


if __name__ == '__main__':
    raise SystemExit(main())
