#!/usr/bin/env python3
"""Bounded, manual compile-capacity diagnostic; strict tests remain strict.

Only structured allowlisted evidence is uploaded. Cargo/test stdout and stderr,
GNU time's complete output, and binaries stay below ignored .ci-work/.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.ci-work/actor-diagnostic'
RAW = WORK / 'raw'
TARGET = WORK / 'target'
SAFE = ROOT / 'ci-safe-results/actor-diagnostic'
TOOLCHAIN = '1.95.0'
VENDOR_SHA = '3aef31ba015c75ea824b8b41f5603b03f5dd336b'
COMPILE_SECONDS = 270
TEST_SECONDS = 15
# These are existing real graph tests. No generated reduced grammar, cfg edits,
# ignored-test changes, assertion rewrites, or vendored Hibana changes are used.
TARGETS = {
    'early_owner_no_alloc': [
        'first_retire_requires_no_dummy_work_and_no_allocations',
        'real_tls_claim_owned_q1_setup_inspect_and_retire_do_not_allocate',
        'real_tls_claim_owned_q1_pending_cancellation_does_not_allocate',
        'original_after_inspect_retirement_remains_unresolved',
    ],
    'stream_owner_roles': [
        'q1_owner_moves_and_copies_early_intent_without_heap',
        'cancelling_after_command_publication_revokes_the_admission_capability',
        'projected_bootstrap_has_no_application_open_edge',
        'projected_preparation_cannot_escape_without_owner_settlement_suffix',
    ],
    'protocol': [
        'independent_guarded_tx_and_timer_progress_while_rx_is_parked',
        'carrier_backpressure_wakes_current_sender_and_delivers_fifo_once',
        'carrier_close_wakes_pending_receive_and_quarantines_queue',
        'forbidden_publish_without_reservation_fails_closed',
        'forbidden_authentication_before_key_installation_fails_closed',
        'forbidden_delivery_and_credit_before_authentication_fail_closed',
        'legal_typed_contract_completes',
        'forbidden_reservation_reuse_before_adapter_result_fails_closed',
        'actual_key_services_reject_use_before_install_at_hibana_endpoint',
        'actual_service_rejects_early_release_before_verified_finished',
        'actual_service_rejects_client_intent_import_before_finished',
        'actual_service_rejects_deferred_control_release_before_finished',
    ],
    'lib': [
        'roles::recovery_owner::tests::q1_projected_owner_runs_real_reserve_accept_ack_and_retire',
        'roles::path_owner::tests::q1_projected_reservation_branch_waits_for_exact_callback_then_retires',
        'roles::stream_owner::tests::q1_preparation_scope_retries_stale_cancel_without_releasing_next_frame',
        'roles::early_owner::tests::first_finished_then_repeated_inspection_and_retirement_needs_no_dummy_packet',
    ],
}
KNOWN_FAILURES = set(TARGETS['early_owner_no_alloc'][:2])
ORIGINAL_REPRO = TARGETS['early_owner_no_alloc'][3]
TIME_FIELDS = {
    'User time (seconds)': 'user_seconds',
    'System time (seconds)': 'system_seconds',
    'Maximum resident set size (kbytes)': 'peak_rss_kib',
    'Major (requiring I/O) page faults': 'major_page_faults',
    'Minor (reclaiming a frame) page faults': 'minor_page_faults',
    'Exit status': 'time_exit_status',
}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix(path.suffix + '.tmp')
    pending.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    pending.replace(path)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def require_source():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('PUBLIC_REPOSITORY') != 'true':
        raise ValueError('Only the explicitly authorized public GitHub Actions job may execute this diagnostic')
    expected = os.environ.get('EXPECTED_SOURCE_SHA', '')
    actual = checked('git', 'rev-parse', 'HEAD')
    if not re.fullmatch('[0-9a-f]{40}', expected) or actual != expected:
        raise ValueError('Exact source SHA mismatch')
    checked('git', 'diff', '--exit-code', 'HEAD', '--')
    return actual


def environment():
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='1',
               CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0',
               CARGO_PROFILE_TEST_DEBUG='0', RUST_BACKTRACE='0', LC_ALL='C')
    # Do not let ambient flags silently shrink the graph or disable assertions.
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        if env.get(key):
            raise ValueError('Unexpected compiler override: ' + key)
    return env


def parse_time(text):
    metrics = {}
    for line in text.splitlines():
        for label, key in TIME_FIELDS.items():
            if line.strip().startswith(label + ':'):
                value = line.split(':', 1)[1].strip()
                if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value):
                    metrics[key] = float(value) if '.' in value else int(value)
    return metrics


def measured(stage, command, seconds):
    """Measure the command tree; do not print or publish its unfiltered output."""
    RAW.mkdir(parents=True, exist_ok=True)
    evidence = {'stage': stage, 'state': 'running', 'timeout_seconds': seconds,
                'command': command, 'source_sha': os.environ['EXPECTED_SOURCE_SHA']}
    destination = SAFE / (stage + '.json')
    write(destination, evidence)
    stdout_path, stderr_path, time_path = [RAW / (stage + suffix) for suffix in ('.stdout', '.stderr', '.time')]
    start = time.monotonic()
    with stdout_path.open('w') as out, stderr_path.open('w') as err:
        result = subprocess.run(
            ['/usr/bin/time', '-v', '-o', str(time_path), 'timeout',
             '--signal=TERM', '--kill-after=3s', str(seconds) + 's', *command],
            cwd=ROOT, env=environment(), stdout=out, stderr=err, check=False)
    stdout = stdout_path.read_text(errors='replace')
    stderr = stderr_path.read_text(errors='replace')
    combined = stdout + '\n' + stderr
    evidence.update(state='finished', process_exit=result.returncode,
                    elapsed_seconds=round(time.monotonic() - start, 3),
                    time_v=parse_time(time_path.read_text(errors='replace')),
                    timeout_reported=result.returncode == 124,
                    signal_9_mentioned=bool(re.search(r'signal[: ]+9\b|SIGKILL', combined)),
                    phase_invariant_mentioned='PhaseInvariant' in combined,
                    early_retired_send_100_mentioned=bool(re.search(
                        r'HibanaStep\s*\{\s*label:\s*100,\s*source:.*?operation:\s*"send".*?PhaseInvariant',
                        combined, re.S)))
    write(destination, evidence)
    print(json.dumps({'stage': stage, 'exit': result.returncode,
                      'peak_rss_kib': evidence['time_v'].get('peak_rss_kib')}), flush=True)
    return evidence, stdout, stderr


def prepare():
    source = require_source()
    if not Path('/usr/bin/time').is_file():
        raise ValueError('GNU /usr/bin/time is required; no substitute measurement is used')
    if WORK.exists() or SAFE.exists():
        raise ValueError('Diagnostic requires fresh work/results directories; no cached binaries admitted')
    checked('python3', 'ci/audit_source.py', '--check')
    provenance = json.loads((ROOT / 'vendor/hibana-provenance.json').read_text())
    if provenance['base_commit'] != VENDOR_SHA or provenance.get('local_patches') != []:
        raise ValueError('Unmodified Hibana base pin is required')
    checked('python3', 'vendor/check_hibana.py')
    version = checked('rustc', '+' + TOOLCHAIN, '-Vv')
    if not version.startswith('rustc ' + TOOLCHAIN + ' '):
        raise ValueError('Unexpected rustc version')
    write(SAFE / 'environment.json', {
        'source_sha': source, 'workflow_sha': os.environ.get('GITHUB_SHA'),
        'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'runner_os': os.environ.get('RUNNER_OS'), 'runner_image': os.environ.get('ImageVersion'),
        'rustc_verbose': version, 'cargo_version': checked('cargo', '+' + TOOLCHAIN, '-V'),
        'hibana_revision': VENDOR_SHA, 'hibana_local_patches': [],
        'manifest_sha256': sha256(ROOT / 'ci/source-manifest.json'),
        'cargo_lock_sha256': sha256(ROOT / 'Cargo.lock'),
        'selected_test_targets': TARGETS,
        'source_files_sha256': {name: sha256(ROOT / name) for name in (
            'src/roles/protocol_stream.rs', 'src/roles/protocol_early.rs',
            'src/roles/protocol_tls.rs', 'tests/early_owner_no_alloc.rs',
            'tests/stream_owner_roles.rs', 'tests/tls_owner_roles.rs')},
        'profile': {'mode': 'test (debug assertions retained)', 'debug_info': 0,
                    'incremental': False, 'jobs': 1, 'cache': 'fresh target directory; later targets reuse dependencies'},
        'measurement': '/usr/bin/time -v on timeout-wrapped command tree; peak RSS is not summed whole-job RAM',
        'known_early_failure': {'tests': sorted(KNOWN_FAILURES), 'observation': 'owner Retired send100 PhaseInvariant'},
        'historical_reproduction': {'test': ORIGINAL_REPRO, 'observation': 'asserts original client send99 PhaseInvariant; passing does not fix it'},
        'scope': 'Compile capacity plus selected actual actor graph tests; actor replacement/integration is incomplete. Prior interop outcomes remain historical. Not a complete semantic, interop, or hardware qualification',
    })
    result, _, _ = measured('fetch', ['cargo', '+' + TOOLCHAIN, 'fetch', '--locked'], 120)
    return int(result['process_exit'] != 0)


def compile_targets():
    require_source()
    failures = 0
    for target in TARGETS:
        selector = ['--lib'] if target == 'lib' else ['--test', target]
        command = ['cargo', '+' + TOOLCHAIN, 'test', '--locked', '--offline',
                   '--no-run', '--message-format=json-render-diagnostics', *selector]
        result, stdout, _ = measured('compile-' + target, command, COMPILE_SECONDS)
        executables = set()
        for line in stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            expected_name = 'hibana_quic' if target == 'lib' else target
            if (record.get('reason') == 'compiler-artifact' and record.get('target', {}).get('name') == expected_name
                    and record.get('profile', {}).get('test') and record.get('executable')):
                executable = Path(record['executable']).resolve()
                if not executable.is_relative_to(TARGET.resolve()) or not executable.is_file():
                    raise ValueError('Compiler returned an unexpected executable location')
                executables.add(str(executable))
        compiled = result['process_exit'] == 0 and len(executables) == 1
        result.update(compile_passed=compiled, runtime_semantics='not run in compile stage')
        write(SAFE / ('compile-' + target + '.json'), result)
        # Paths are local state, not uploaded evidence.
        if compiled:
            write(WORK / (target + '-executable.json'), {'path': executables.pop()})
        failures += not compiled
    return int(failures > 0)


def test_targets():
    require_source()
    failures = 0
    for target, names in TARGETS.items():
        compilation = SAFE / ('compile-' + target + '.json')
        compiled = compilation.exists() and json.loads(compilation.read_text()).get('compile_passed') is True
        if not compiled:
            write(SAFE / ('tests-' + target + '.json'), {'state': 'not_run_compile_unavailable', 'tests': names})
            failures += 1
            continue
        executable = json.loads((WORK / (target + '-executable.json')).read_text())['path']
        try:
            listed = subprocess.run([executable, '--list', '--format', 'terse'], cwd=ROOT,
                                    env=environment(), capture_output=True, text=True, timeout=6, check=False)
        except (subprocess.TimeoutExpired, OSError):
            write(SAFE / ('tests-' + target + '.json'), {'state': 'test_inventory_unavailable', 'tests': names})
            failures += 1
            continue
        available = set(re.findall(r'^(.+): test$', listed.stdout, re.M))
        if listed.returncode != 0 or any(name not in available for name in names):
            write(SAFE / ('tests-' + target + '.json'), {'state': 'test_inventory_mismatch', 'tests': names})
            failures += 1
            continue
        groups = [names] if target == 'protocol' else [[name] for name in names]
        for index, group in enumerate(groups):
            name = group[0] if len(group) == 1 else 'protocol_complete_12_tests'
            stage = 'test-' + target + '-' + str(index + 1)
            result, stdout, _ = measured(stage, [executable, *group, '--exact', '--test-threads=1', '--nocapture'], 30 if target == 'protocol' else TEST_SECONDS)
            match = re.search(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', stdout)
            counts = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), map(int, match.groups()[1:]))) if match else None
            passed = (result['process_exit'] == 0 and counts is not None and counts['passed'] == len(group)
                      and counts['failed'] == counts['ignored'] == counts['measured'] == 0)
            result.update(test=name, test_names=group, counts=counts, strict_test_passed=passed,
                          known_positive_failure=name in KNOWN_FAILURES,
                          historical_expected_failure_reproduction=name == ORIGINAL_REPRO)
            write(SAFE / (stage + '.json'), result)
            failures += not passed
    return int(failures > 0)


def summary():
    if not SAFE.exists():
        print('No source-audited evidence exists; preparation did not complete.')
        return 1
    records = {p.stem: json.loads(p.read_text()) for p in SAFE.glob('*.json') if p.name != 'summary.json'}
    compile_ok = all(records.get('compile-' + name, {}).get('compile_passed') is True for name in TARGETS)
    expected = sum(map(len, TARGETS.values()))
    tested = [value for name, value in records.items() if name.startswith('test-')]
    observed = sum(len(test.get('test_names', [])) for test in tested)
    strict_ok = observed == expected and all(test.get('strict_test_passed') is True for test in tested)
    result = {'source_sha': os.environ.get('EXPECTED_SOURCE_SHA'), 'all_selected_targets_compiled': compile_ok,
              'selected_strict_tests_passed': strict_ok, 'selected_tests_expected': expected,
              'selected_test_records': len(tested), 'selected_tests_observed': observed, 'semantic_success_inferred_from_compilation': False,
              'full_semantic_qualification': False, 'historical_early_defect_remains_explicit': True,
              'known_positive_early_failures': {test['test']: {
                  'strict_passed': test.get('strict_test_passed'),
                  'send100_phase_invariant_observed': test.get('early_retired_send_100_mentioned')}
                  for test in tested if test.get('known_positive_failure')},
              'note': 'Known positive Early failures remain failures. A passing historical reproduction confirms its expected defect, not a fix. Missing, timed-out, or uncompiled tests are not passes. Actor replacement/integration remains incomplete; earlier interop outcomes are historical.'}
    write(SAFE / 'summary.json', result)
    message = ('Actor graph diagnostic\n\nSource SHA: ' + str(result['source_sha'])
               + '\nAll selected targets compiled: ' + str(compile_ok)
               + '\nSelected strict runtime tests passed: ' + str(strict_ok)
               + '\nSelected tests observed: ' + str(observed) + '/' + str(expected)
               + '\nCompilation alone establishes no runtime semantic success.\n' + result['note'] + '\n')
    print(message)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
            handle.write(message)
    return int(not (compile_ok and strict_ok))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'compile', 'test', 'summary'))
    args = parser.parse_args()
    os.chdir(ROOT)
    functions = {'prepare': prepare, 'compile': compile_targets, 'test': test_targets, 'summary': summary}
    raise SystemExit(functions[args.stage]())
