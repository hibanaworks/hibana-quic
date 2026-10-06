"""Untrusted runner/endpoint logs must not become public raw-log artifacts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'ci/run_in_tools.py'


class Diagnostics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # The production module intentionally requires ROOT. Tests never import
        # it against the caller's real checkout or its current environment.
        with patch.dict(os.environ, {'ROOT': str(self.root)}):
            spec = importlib.util.spec_from_file_location('ci_diagnostics', SOURCE)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.logs = self.root / 'raw/logs'
        self.case = self.logs / 'neqo_hibana-quic/transfer'
        self.case.mkdir(parents=True)

    def test_requested_multiplexing_is_registered_and_unknown_cases_still_fail(self):
        self.assertEqual(self.module.requested_cases(['multiplexing']), {'multiplexing'})
        self.assertEqual(self.module.CASE_ABBREVIATIONS['multiplexing'], 'M')
        with self.assertRaises(RuntimeError):
            self.module.requested_cases(['unregistered'])
        with self.assertRaises(RuntimeError):
            self.module.requested_cases(['multiplexing', 'multiplexing'])

    def put(self, relative, data):
        path = self.case / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def collect(self):
        return self.module.collect_case_diagnostics(self.logs, 'hibana-quic', 'neqo')['transfer']

    def test_simulator_faults_are_classified_without_raw_details(self):
        secret = 'PRIVATE_PATH_AND_TOKEN_NOT_FOR_ARTIFACT'
        self.put('sim/sim.log', f'NS_FATAL_ERROR msg=Device or resource busy file={secret} line=42\n')
        result = self.collect()['simulator_log']
        self.assertEqual(result['state'], 'present')
        self.assertIn('simulator-fatal', result['runner_classes'])
        self.assertIn('device-busy', result['runner_classes'])
        self.assertIn('simulator-fatal-location', result['runner_classes'])
        self.assertNotIn(secret, json.dumps(result))

    def test_fixed_runner_events_and_numeric_exit_codes(self):
        self.put('output.txt', '\n'.join([
            'Container sim  Starting', 'Container sim  Started',
            'client exited with code 1', 'server exited with code 0',
            'sim exited with code 137', 'secret-client exited with code 55',
            'client exited with code 256', 'client exited with code 1000',
            'Aborting on container exit...', 'Test failed: took longer than 60s.',
            'Copying logs from sim failed: RAW_SECRET',
            'RTNETLINK answers: Operation not permitted',
            'File size of RAW_PATH doesn\'t match. Original: 100 bytes, downloaded: 5 bytes.',
            'File contents of RAW_PATH do not match.',
        ]))
        result = self.collect()['runner_output']
        self.assertEqual(result['container_exit_codes'], {'client': [1], 'server': [0], 'sim': [137]})
        self.assertEqual(result['case_timeout_count'], 1)
        self.assertEqual(result['case_timeout_seconds'], [60])
        for label in ('container-exit-abort', 'simulator-started', 'copy-simulator-log-failed',
                      'network-setup-failed', 'case-timeout', 'file-length-mismatch', 'file-content-mismatch'):
            self.assertIn(label, result['runner_classes'])
        self.assertNotIn('RAW_', json.dumps(result))

    def test_endpoint_known_report_and_error_categories(self):
        report = {'status': 'success', 'role': 'client', 'lifecycle_closed': True,
                  'handshake_mode': 'full', 'authentication': 'verified-certificate',
                  'body_bytes': 10485760, 'files_completed': 3, 'duration_ms': 12000,
                  'send_key_generation': 0, 'authenticated_receive_key_generation': 1}
        self.put('client/client.log', json.dumps(report))
        actual = self.collect()['client_log']['json_records'][0]
        for key, value in report.items():
            self.assertEqual(actual[key], value)
        failure = self.module.endpoint_json(json.dumps({'status': 'failure', 'error':
            'server initial receive: non-native UDP source address'}))
        self.assertIn('non-native-udp-source', failure['error_classes'])
        self.assertTrue(failure['error']['withheld'])

    def test_early_runner_reason_and_sizes_are_bounded_metadata_only(self):
        raw = b"DEBUG:root:0-RTT size: 10023\nDEBUG:root:1-RTT size: 7000\nClient sent too much data in 1-RTT packets.\nPRIVATE secret-token\n1-RTT size: -10\n0-RTT size: 99999999999999\n"
        result = self.module.summarize_log(raw)
        self.assertEqual(result['early_payload_diagnostics'], {'zero_rtt_payload_bytes':[10023], 'one_rtt_payload_bytes':[7000]})
        self.assertIn('early-late-payload-limit', result['runner_classes'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('secret-token', json.dumps(result))
        missing = self.module.summarize_log(b"Client didn't send any 0-RTT data.\nExpected exactly 2 handshakes. Got: 3\n")
        self.assertIn('early-data-not-sent', missing['runner_classes'])
        self.assertIn('two-handshake-count-mismatch', missing['runner_classes'])

    def test_native_frontiers_and_terminals_are_bounded_exact_metadata(self):
        raw = b"connection-frontier session=12 ordinal=31 event=514 metadata=123 finished=false elapsed_ms=10 sent=3 received=4\nconnection-frontier session=12 ordinal=32 event=515 metadata=124 finished=true elapsed_ms=20 sent=3 received=4\nconnection-frontier session=4294967296 ordinal=1 event=514 metadata=1 finished=false elapsed_ms=1 sent=3 received=4\nconnection-frontier session=4 ordinal=1 event=999 metadata=1 finished=false elapsed_ms=1 sent=3 received=4\nconnection-terminal index=2 idle=0 confirmed=true completed=1 submitted=1 acked=false closed=true elapsed_ms=25\nconnection-terminal index=3 failure=PRIVATE_SECRET\nPRIVATE_PREFIX connection-frontier session=3 ordinal=1 event=514 metadata=1 finished=false elapsed_ms=1 sent=3 received=4\n"
        result = self.module.summarize_log(raw, endpoint=True)
        self.assertEqual(result['frontier_sample_count'], 2)
        self.assertEqual(result['latest_connection_frontiers'], [dict(session=12, ordinal=32, event=515, metadata=124, finished=True, elapsed_ms=20, sent=3, received=4)])
        self.assertEqual(result['connection_terminal_count'], 1)
        self.assertFalse(result['connection_terminals'][0]['acked'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        many = b''.join(f'connection-frontier session={i} ordinal=1 event=514 metadata=1 finished=false elapsed_ms=1 sent=3 received=4\n'.encode() for i in range(70))
        bounded = self.module.summarize_log(many, endpoint=True)
        self.assertEqual(bounded['frontier_sample_count'], 70)
        self.assertEqual(len(bounded['latest_connection_frontiers']), 64)
        self.assertEqual(bounded['frontier_samples_omitted_for_capacity'], 6)

    def test_native_clock_reports_actual_deadline_without_a_completion_inference(self):
        raw = b'connection-clock session=8 now_us=25000000 deadline_us=500000000 stage=requested\nconnection-clock session=9 now_us=2 deadline_us=1 stage=returned\nconnection-clock session=8 now_us=3 deadline_us=4 stage=PRIVATE\nconnection-clock session=8 now_us=3 deadline_us=99999999999999 stage=requested\n'
        result = self.module.summarize_log(raw, endpoint=True)
        self.assertEqual(result['latest_connection_clocks'], [dict(session=8, now_us=25000000, deadline_us=500000000, stage='requested'), dict(session=9, now_us=2, deadline_us=1, stage='returned')])
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_native_trace_keeps_only_bounded_numeric_tails(self):
        raw = b''.join(f'connection-trace session=7 ordinal={i} event=515 metadata=50357248\n'.encode() for i in range(30))
        raw += b'connection-trace session=7 ordinal=31 event=515 metadata=PRIVATE\nconnection-trace-capacity session=7\n'
        result = self.module.summarize_log(raw, endpoint=True)
        self.assertEqual(result['connection_trace_records'], 30)
        self.assertEqual(result['connection_trace_records_omitted'], 14)
        self.assertEqual(result['connection_trace_capacity_sessions'], [7])
        self.assertEqual([x['ordinal'] for x in result['connection_trace_tails'][0]['events']], list(range(14, 30)))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_panic_backtrace_refcell_without_messages(self):
        raw = b"thread 'PRIVATE_NAME' panicked at PRIVATE_PATH\nalready borrowed: BorrowMutError\nstack backtrace:\nfatal runtime error: stack overflow\n"
        result = self.module.summarize_log(raw, endpoint=True)
        self.assertEqual(result['error_classes'], ['refcell-borrow', 'runtime-fatal', 'rust-backtrace', 'rust-panic', 'stack-overflow'])
        self.assertNotIn('PRIVATE_', json.dumps(result))

    def test_timeout_progress_only_extracts_fixed_numeric_fields(self):
        result = self.module.endpoint_json(json.dumps({'status': 'failure', 'error':
            'deadline expired on connection 2: 1 complete files, 3 live; ticket acceptance SECRET, age PRIVATE; no overall success reported'}))
        self.assertEqual(result['timeout_progress'], {'connection_index': 2, 'files_completed': 1, 'live_streams': 3})
        self.assertEqual(result['error_classes'], ['connection-timeout'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_keylogs_keys_tickets_and_unknown_names_never_escape(self):
        secret = 'unique-secret-not-for-publication'
        keylog = 'CLIENT_' + 'TRAFFIC_SECRET_0 ' + 'ab' * 32 + ' ' + 'cd' * 32
        pem = '-----BEGIN ' + 'PRIVATE KEY-----\n' + 'X' * 80 + '\n-----END PRIVATE KEY-----'
        data = {'status': secret, 'role': pem, 'authentication': keylog,
                'error': secret, secret: {'ticket': secret, 'key': pem},
                'body_bytes': secret}
        self.put('client/client.log', json.dumps(data) + '\n' + keylog + '\n' + pem)
        self.put('client/keys.log', keylog)
        self.put('server/private.key', pem)
        self.put('client/qlog/secret.qlog', secret)
        self.put('sim/' + secret + '.pcap', secret)
        output = json.dumps(self.collect())
        for value in (secret, keylog, pem, 'CLIENT_TRAFFIC_SECRET_0', 'PRIVATE KEY'):
            self.assertNotIn(value, output)
        record = self.collect()['client_log']['json_records'][0]
        self.assertTrue(record['status']['withheld'])
        self.assertEqual(record['unknown_fields_count'], 1)
        self.assertRegex(record['unknown_fields']['sha256'], '^[a-f0-9]{64}$')

    def test_json_rejects_duplicates_nested_duplicates_and_bad_input(self):
        inputs = ['{"status":"success","status":"failure"}',
                  '{"extra":{"secret":1,"secret":2}}', '{"status":',
                  '{"body_bytes":NaN}', '{"body_bytes":Infinity}',
                  '{"body_bytes":1e9999}', '{"body_bytes":1.0}',
                  '[]', '{"nested":' + '[' * 10 + '1' + ']' * 10 + '}',
                  '{"nested":' + '[' * 1500 + '1' + ']' * 1500 + '}',
                  json.dumps({'x': [1] * 129}),
                  json.dumps({str(i): i for i in range(129)})]
        for text in inputs:
            with self.subTest(text=text[:70]):
                result = self.module.endpoint_json(text)
                self.assertEqual(result['state'], 'invalid-or-oversized-json')
                self.assertEqual(set(result), {'state', 'record_sha256'})

    def test_json_types_and_numeric_limits_fail_closed(self):
        values = {'status': ['success'], 'role': {'x': 'client'}, 'lifecycle_closed': 1,
                  'body_bytes': -1, 'files_completed': True,
                  'duration_ms': 3600001, 'send_key_generation': 1000001,
                  'next_deadline_us': -2, 'close_deadline_us': -2}
        result = self.module.endpoint_json(json.dumps(values))
        for key in values:
            self.assertTrue(result[key]['withheld'], key)
        valid = self.module.endpoint_json('{"next_deadline_us":-1,"close_deadline_us":-1}')
        self.assertEqual(valid['next_deadline_us'], -1)
        self.assertEqual(valid['close_deadline_us'], -1)

    def test_progress_schema_and_bounded_first_latest_samples(self):
        records = []
        for value in range(61):
            records.append(json.dumps({'event': 'hq_progress', 'role': 'client',
                'stage': 'connection', 'elapsed_us': value * 1000000,
                'files_completed': 0, 'body_bytes': value * 200,
                'lifecycle': 'Active', 'handshake_complete': True,
                'pending_work': False, 'next_deadline_us': -1, 'close_deadline_us': -1,
                'reactor_polls': value, 'reactor_waits': value,
                'reactor_socket_events': value, 'reactor_timer_events': 0,
                'reactor_wake_events': 0}))
        result = self.module.summarize_log('\n'.join(records).encode(), endpoint=True)
        self.assertEqual(result['json_record_count'], 61)
        self.assertEqual(result['json_records_omitted'], 45)
        self.assertEqual(len(result['json_records']), 16)
        self.assertEqual(result['json_records'][0]['elapsed_us'], 0)
        self.assertEqual(result['json_records'][-1]['elapsed_us'], 60000000)
        self.assertEqual(result['json_records'][-1]['body_bytes'], 12000)
        self.assertNotIn('unknown_fields', result['json_records'][-1])

    def test_byte_line_json_and_record_limits(self):
        m = self.module
        with patch.object(m, 'MAX_LOG_BYTES', 16):
            self.assertEqual(m.summarize_log(b'x' * 17)['parse_state'], 'too-large')
        with patch.object(m, 'MAX_LOG_LINES', 2):
            self.assertEqual(m.summarize_log(b'a\nb\nc')['parse_state'], 'too-many-lines')
        with patch.object(m, 'MAX_LINE_BYTES', 2):
            self.assertEqual(m.summarize_log(b'abc')['parse_state'], 'line-too-large')
        with patch.object(m, 'MAX_JSON_BYTES', 16):
            self.assertEqual(m.endpoint_json('{"status":"success"}')['state'], 'invalid-or-oversized-json')
        result = m.summarize_log(b'{}\n' * (m.MAX_JSON_RECORDS + 1), endpoint=True)
        self.assertEqual(result['json_state'], 'too-many-records')
        self.assertEqual(result['json_records'], [])
        self.assertEqual(m.summarize_log(b'\xff')['parse_state'], 'invalid-utf8')

    def test_file_metadata_missing_empty_hash_and_size_limit(self):
        missing = self.collect()['client_log']
        self.assertEqual(missing, {'state': 'missing'})
        self.put('client/client.log', b'')
        result = self.collect()['client_log']
        self.assertEqual(result['bytes'], 0)
        self.assertEqual(result['sha256'], hashlib.sha256(b'').hexdigest())
        self.put('client/client.log', b'secret' * 4)
        result, raw = self.module.diagnostic_file(self.case, ('client', 'client.log'), limit=16)
        self.assertEqual(result, {'state': 'too-large', 'bytes': 24})
        self.assertIsNone(raw)

    def test_file_and_ancestor_symlinks_and_traversal_are_rejected(self):
        outside = self.root / 'secret'
        outside.write_text('secret')
        (self.case / 'output.txt').symlink_to(outside)
        self.assertEqual(self.collect()['runner_output']['state'], 'rejected-or-unreadable')
        (self.case / 'client').symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.collect()['client_log']['state'], 'rejected-or-unreadable')
        alias = self.root / 'alias'
        alias.symlink_to(self.logs, target_is_directory=True)
        result = self.module.collect_case_diagnostics(alias, 'hibana-quic', 'neqo')
        self.assertEqual(result['transfer']['runner_output']['state'], 'rejected-or-unreadable')
        result, raw = self.module.diagnostic_file(self.case, ('..', 'secret'))
        self.assertEqual(result['state'], 'rejected-or-unreadable')
        self.assertIsNone(raw)

    def test_hardlinks_and_special_files_are_rejected_without_blocking(self):
        outside = self.root / 'secret'
        outside.write_text('secret')
        os.link(outside, self.case / 'output.txt')
        self.assertEqual(self.collect()['runner_output']['state'], 'rejected-nonregular-or-linked')
        (self.case / 'client').mkdir()
        os.mkfifo(self.case / 'client/client.log')
        self.assertEqual(self.collect()['client_log']['state'], 'rejected-nonregular-or-linked')

    def test_capture_numeric_fields_preserve_coalescing_without_payload(self):
        values = ['1', '283.130335', '50000', '443', '7', '0,2', '19,4',
                  '0x02,0x06', '0', '90', '18', '0', '', '']
        result = self.module.numeric_capture_rows(('\t'.join(values) + '\n').encode())
        self.assertEqual(result['state'], 'parsed')
        self.assertEqual(result['rows'][0]['time_us'], 283130335)
        self.assertEqual(result['rows'][0]['quic.long.packet_type'], [0, 2])
        self.assertEqual(result['rows'][0]['quic.frame_type'], [2, 6])
        self.assertTrue(result['coalesced_fields_are_independent_lists'])

    def test_capture_rejects_strings_overflow_and_excess_rows(self):
        values = [''] * len(self.module.CAPTURE_FIELDS)
        for field, value in [(0, 'PRIVATE_SECRET'), (0, str(1 << 62)),
                             (1, 'nan'), (1, '-1'), (0, ','.join(['1'] * 65))]:
            row = values.copy()
            row[field] = value
            result = self.module.numeric_capture_rows(('\t'.join(row) + '\n').encode())
            self.assertNotEqual(result['state'], 'parsed')
            self.assertNotIn('PRIVATE_SECRET', json.dumps(result))
        with patch.object(self.module, 'MAX_CAPTURE_ROWS', 1):
            raw = ('\t'.join(values) + '\n') * 2
            self.assertEqual(self.module.numeric_capture_rows(raw.encode())['state'], 'too-many-rows')
        self.assertEqual(self.module.numeric_capture_rows(b'1\t2\n')['state'], 'invalid-fields')

    def test_capture_tool_reads_held_descriptor_with_fixed_field_allowlist(self):
        self.put('sim/trace_node_left.pcap', b'not a real pcap')
        def run(command, **kwargs):
            self.assertEqual(command[:3], ['tshark', '-n', '-r'])
            self.assertEqual(command[3], '/proc/self/fd/' + str(kwargs['pass_fds'][0]))
            self.assertIn('tls.keylog_file:', command)
            fields = [command[i + 1] for i, item in enumerate(command) if item == '-e']
            self.assertEqual(fields, list(self.module.CAPTURE_FIELDS))
            self.assertEqual(kwargs['timeout'], 20)
            kwargs['stdout'].write(('\t'.join(['1'] + [''] * (len(fields) - 1)) + '\n').encode())
            return SimpleNamespace(returncode=0)
        with patch.object(self.module.subprocess, 'run', side_effect=run):
            result = self.module.capture_observations(self.case, ('sim', 'trace_node_left.pcap'))
        self.assertEqual(result['state'], 'parsed')

    def test_capture_tool_failure_never_publishes_partial_output(self):
        self.put('sim/trace_node_left.pcap', b'not a real pcap')
        def run(command, **kwargs):
            kwargs['stdout'].write(b'PRIVATE_SECRET')
            return SimpleNamespace(returncode=1)
        with patch.object(self.module.subprocess, 'run', side_effect=run):
            result = self.module.capture_observations(self.case, ('sim', 'trace_node_left.pcap'))
        self.assertEqual(result, {'state': 'dissector-failed'})

    def test_only_known_capture_names_metadata_and_hash_are_exported(self):
        self.put('sim/trace_node_left.pcap', b'PRIVATE_PACKET_CONTENT')
        self.put('sim/SECRET_NAME.pcap', b'PRIVATE_PACKET_CONTENT')
        result = self.collect()['captures']
        self.assertEqual(result['left']['bytes'], len(b'PRIVATE_PACKET_CONTENT'))
        self.assertEqual(result['left']['sha256'], hashlib.sha256(b'PRIVATE_PACKET_CONTENT').hexdigest())
        self.assertEqual(result['right'], {'state': 'missing'})
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('SECRET', json.dumps(result))

    def test_application_file_metadata_never_exports_names_or_contents(self):
        self.put('server_www/PRIVATE_FILENAME', b'x' * 10)
        self.put('server_www/OTHER_PRIVATE_NAME', b'x' * 20)
        self.put('server_www/MISSING_NAME', b'x' * 40)
        self.put('client_downloads/PRIVATE_FILENAME', b'x' * 10)
        self.put('client_downloads/OTHER_PRIVATE_NAME', b'x' * 5)
        self.put('client_downloads/.hibana-0123456789abcdef.part', b'x' * 3)
        self.put('client_downloads/UNEXPECTED_NAME', b'x' * 2)
        result = self.collect()['application_files']['client_downloads']
        self.assertEqual(result['file_sizes'], [2, 3, 5, 10])
        self.assertEqual(result['length_complete_files'], 1)
        self.assertEqual(result['length_complete_bytes'], 10)
        self.assertEqual(result['partial_files'], 2)
        self.assertEqual(result['partial_bytes'], 8)
        self.assertEqual(result['missing_expected_files'], 1)
        self.assertEqual(result['unclassified_files'], 1)
        self.assertTrue(result['length_only_not_content_verified'])
        self.assertNotIn('NAME', json.dumps(result))

    def test_application_directory_limits_and_links_fail_closed(self):
        self.put('server_www/a', b'a')
        self.put('server_www/b', b'b')
        with patch.object(self.module, 'MAX_DIRECTORY_ENTRIES', 1):
            result, private_sizes = self.module.directory_sizes(self.case, ('server_www',))
        self.assertEqual(result, {'state': 'too-many-entries'})
        self.assertIsNone(private_sizes)
        (self.case / 'server_www/b').unlink()
        (self.case / 'server_www/b').symlink_to(self.root / 'secret')
        result, private_sizes = self.module.directory_sizes(self.case, ('server_www',))
        self.assertEqual(result, {'state': 'rejected-entry'})
        self.assertIsNone(private_sizes)

    def test_invalid_matrix_identifier_is_not_a_path_or_export(self):
        result = self.module.collect_case_diagnostics(self.logs, '../SECRET', 'neqo')
        self.assertEqual(result, {'state': 'invalid-matrix-identifiers'})

    def test_main_runs_only_selected_candidate_directions_and_requires_baseline(self):
        def checked_output(command, **kwargs):
            if command[0] == 'tshark':
                return 'TShark 4.6.0\n'
            if 'rev-parse' in command:
                return 'pinned\n'
            return ''
        self.module.RAW.parent.mkdir(parents=True, exist_ok=True)
        request = self.root / 'ci/interop-request.json'
        request.parent.mkdir(parents=True, exist_ok=True)
        cases = [(['server'], True, {}, True), (['client', 'server'], True, {}, True),
                 (['server'], False, {}, True),
                 (['server'], False, {'status':'TIMEOUT'}, False),
                 (['server'], False, {'cleanup_exit_code':1}, False),
                 (['server'], False, {'non_null_case_results':0}, False),
                 (['server'], False, {'unexecuted_case_results':1}, False),
                 (['server'], False, {'runner_progress':{}}, False),
                 (['client', 'server'], True, {'runner_progress':{}}, True)]
        for reference, directions, baseline_ok, overrides, run_candidate in [
                (reference, *case) for reference in ('neqo', 'quiche') for case in cases]:
            request.write_text(json.dumps({'cases':['zerortt'], 'candidate_directions':directions, 'reference_implementation':reference}))
            calls = []
            def phase(name, client, server, candidate):
                calls.append(name)
                self.assertEqual((client, server),
                    ('hibana-quic', reference) if name == 'bounded-client' else
                    (reference, 'hibana-quic') if name == 'bounded-server' else (reference, reference))
                status = 'PASSED' if baseline_ok or candidate else 'FAILED'
                record = {'phase':name, 'status':status, 'results':[{}],
                        'cleanup_exit_code':0, 'non_null_case_results':1, 'unexecuted_case_results':0,
                        'runner_progress':{'client_compliance_passed':True, 'server_compliance_passed':True}}
                if not candidate:
                    record.update(overrides)
                return record
            with patch.dict(os.environ, {'RUNNER_REVISION':'pinned'}), \
                 patch.object(self.module.subprocess, 'check_output', side_effect=checked_output), \
                 patch.object(self.module, 'docker_metadata'), \
                 patch.object(self.module, 'phase', side_effect=phase):
                self.assertEqual(self.module.main(), 0 if baseline_ok else 1)
            expected = [reference + '-baseline'] + (['bounded-' + direction for direction in directions] if run_candidate else [])
            self.assertEqual(calls, expected)
            summary = json.loads((self.module.SAFE / 'summary.json').read_text())
            self.assertEqual(summary['candidate_directions'], sorted(directions))
            self.assertEqual(summary['reference_implementation'], reference)
            self.assertFalse(summary['full_runner_gate_passed'])
            self.assertEqual(summary['baseline_passed'], baseline_ok)
            self.assertEqual(summary['candidate_diagnostic_after_failed_control'], run_candidate and not baseline_ok)
            self.assertEqual(summary['status'], 'PASSED' if baseline_ok else 'NOT_PASSED')

    def test_reference_selection_is_explicit_and_fail_closed(self):
        for name in ('neqo', 'quiche'):
            self.assertEqual(self.module.requested_reference(name), name)
        for invalid in (None, [], {}, 'unknown', '../neqo', 'neqo;echo'):
            with self.assertRaises(RuntimeError):
                self.module.requested_reference(invalid)

    def test_candidate_directions_are_explicit_and_fail_closed(self):
        self.assertEqual(self.module.requested_directions(['client', 'server']), {'client', 'server'})
        self.assertEqual(self.module.requested_directions(['server']), {'server'})
        for invalid in ([], ['client', 'client'], ['unknown'], ['../secret'], 'server', [None]):
            with self.assertRaises(RuntimeError):
                self.module.requested_directions(invalid)

    def test_requested_case_scope_is_explicit_and_fail_closed(self):
        self.assertEqual(self.module.requested_cases(['chacha20']), {'chacha20'})
        self.assertEqual(self.module.requested_cases(['resumption']), {'resumption'})
        self.assertEqual(self.module.requested_cases(['zerortt']), {'zerortt'})
        self.assertEqual(self.module.requested_cases(['blackhole']), {'blackhole'})
        self.assertEqual(self.module.requested_cases(['keyupdate']), {'keyupdate'})
        self.assertEqual(self.module.requested_cases(['amplificationlimit']), {'amplificationlimit'})
        self.assertEqual(self.module.requested_cases(['longrtt', 'transferloss', 'transfercorruption', 'ipv6']), {'longrtt', 'transferloss', 'transfercorruption', 'ipv6'})
        for invalid in ([], ['transfer', 'transfer'], ['unknown'], ['../secret'], ['http3'], 'transfer', [None]):
            with self.assertRaises(RuntimeError):
                self.module.requested_cases(invalid)

    def fixture(self, states=('succeeded', 'failed')):
        return {'start_time': 1790942400.123456, 'end_time': 1790942460.123456,
                'quic_version': '0x1', 'clients': ['hibana-quic'], 'servers': ['neqo'],
                'tests': {'H': {'name': 'handshake'}, 'DC': {'name': 'transfer'}},
                'results': [[{'name': name, 'abbr': abbr, 'result': state}
                    for name, abbr, state in zip(('handshake', 'transfer'), ('H', 'DC'), states)]]}

    def test_original_result_enum_is_preserved_and_never_promoted(self):
        output = self.root / 'result.json'
        for state in ('failed', 'unsupported', None):
            data = self.fixture(('succeeded', state))
            output.write_text(json.dumps(data))
            result = self.module.checked_result(output, 'hibana-quic', 'neqo')
            self.assertEqual(result['results'], data['results'][0])
            self.assertFalse(result['passed'])
            self.assertEqual(result['unexecuted_case_results'], int(state is None))

    def test_result_duplicate_json_and_arbitrary_abbreviation_are_rejected(self):
        output = self.root / 'result.json'
        output.write_text('{"results":[],"results":[]}')
        with self.assertRaises(ValueError):
            self.module.checked_result(output, 'hibana-quic', 'neqo')
        data = self.fixture()
        data['results'][0][0]['abbr'] = 'SECRET'
        data['tests']['SECRET'] = {'name': 'handshake'}
        output.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, 'case abbreviation mismatch'):
            self.module.checked_result(output, 'hibana-quic', 'neqo')

    def test_traceback_unknown_filename_function_and_exception_are_withheld(self):
        raw = ('Traceback (most recent call last):\n'
               '  File "/SECRET_PATH.py", line 123, in SECRET_FUNCTION\n'
               'SECRET_EXCEPTION: SECRET_MESSAGE\n')
        result = self.module.traceback_evidence(raw)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result[0]['frames'][0]['source'], 'external-source-withheld')
        self.assertEqual(result[0]['frames'][0]['line'], 123)
        self.assertTrue(result[0]['exception_type']['withheld'])

    def test_phase_collects_diagnostics_without_changing_failed_verdict(self):
        m = self.module
        m.SAFE.mkdir()
        m.RAW.mkdir(parents=True)
        (m.RAW / 'bounded-client.json').write_text(json.dumps(self.fixture()))
        directory = m.RAW / 'bounded-client-logs/neqo_hibana-quic/transfer/client'
        directory.mkdir(parents=True)
        (directory / 'client.log').write_text('{"status":"success","files_completed":3}')
        work = self.root / 'work'
        work.mkdir()
        def execute(command, **kwargs):
            if command[0] != 'docker':
                kwargs['stdout'].write(b'client exited with code 0\n')
            return SimpleNamespace(returncode=0)
        with patch.object(m, 'setup_workdir', return_value=(work, work / 'overlay')):
            with patch.object(m.subprocess, 'run', side_effect=execute) as run:
                result = m.phase('bounded-client', 'hibana-quic', 'neqo', True)
        self.assertEqual(result['status'], 'FAILED')
        self.assertEqual(result['console_diagnostics']['container_exit_codes']['client'], [0])
        self.assertEqual(result['results'][1]['result'], 'failed')
        self.assertFalse(result['passed'])
        self.assertEqual(result['case_diagnostics']['transfer']['client_log']['json_records'][0]['status'], 'success')
        self.assertEqual(run.call_args_list[0].args[0][-2:], ['-f', 'true'])
        saved = json.loads((m.SAFE / 'bounded-client.json').read_text())
        self.assertEqual(saved['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main()
