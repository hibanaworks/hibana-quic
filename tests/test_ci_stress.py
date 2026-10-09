"""Negative tests prevent idle observation from concealing delivery failures."""
import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
from unittest.mock import patch
from types import SimpleNamespace

SPEC = importlib.util.spec_from_file_location('stress', Path(__file__).resolve().parents[1] / 'tools/ci/run-ack-delay-stress.py')
STRESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STRESS)


class StressVerdict(unittest.TestCase):
    def setUp(self):
        side = dict(connections=50, tls_finished_authenticated=True,
                    quic_handshake_confirmed=True, resources_retired=True,
                    files_submitted=50, files_completed=50,
                    idle_expired_connections=0, status='success',
                    http_transfer_complete=True, lifecycle_closed=True)
        self.report = dict(client_exit=0, server_exit=0, client=side,
                           server=copy.deepcopy(side),
                           files=[dict(expected_sha256='a' * 64, received_sha256='a' * 64) for _ in range(50)])

    def test_larger_operation_budget_does_not_change_negotiated_idle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'hq'
            binary.write_bytes(b'test executable identity')
            calls = []
            def run(command):
                calls.append(command)
                path = Path(command[command.index('--output') + 1])
                path.write_text(json.dumps(self.report))
                return SimpleNamespace(returncode=0)
            with patch.object(STRESS.sys, 'argv', ['stress', '--binary', str(binary), '--output', str(root / 'results')]), patch.object(STRESS.subprocess, 'run', side_effect=run):
                self.assertEqual(STRESS.main(), 0)
            self.assertEqual(len(calls), 10)
            for command in calls:
                self.assertEqual(command[command.index('--timeout-seconds') + 1], '300')
                self.assertEqual(command[command.index('--idle-timeout-seconds') + 1], '90')
            summary = json.loads((root / 'results/summary.json').read_text())
            self.assertEqual(summary['operation_timeout_seconds'], 300)
            self.assertEqual(summary['local_idle_timeout_seconds'], 90)

    def test_clean(self):
        self.assertTrue(STRESS.delivery_passed(self.report))

    def test_completed_server_idle_remains_observed(self):
        self.report['server'].update(idle_expired_connections=1, status='idle-expired',
                                     http_transfer_complete=False, lifecycle_closed=False)
        self.assertTrue(STRESS.delivery_passed(self.report))
        self.assertFalse(self.report['server']['lifecycle_closed'])

    def test_missing_or_corrupt_file_fails_even_after_server_idle(self):
        for digest in (None, 'b' * 64):
            with self.subTest(digest=digest):
                self.report['files'][0]['received_sha256'] = digest
                self.assertFalse(STRESS.delivery_passed(self.report))

    def test_failed_process_missing_result_or_truncated_files_fail(self):
        for field, value in [('client_exit', 1), ('server_exit', 1), ('server', None), ('files', [])]:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report); report[field] = value
                self.assertFalse(STRESS.delivery_passed(report))

    def test_authentication_ownership_confirmation_and_counts_are_required(self):
        for side in ('client', 'server'):
            for field, value in [('tls_finished_authenticated', False), ('resources_retired', False),
                                 ('quic_handshake_confirmed', False), ('files_completed', 49),
                                 ('files_submitted', 49), ('connections', 49)]:
                with self.subTest(side=side, field=field):
                    report = copy.deepcopy(self.report); report[side][field] = value
                    self.assertFalse(STRESS.delivery_passed(report))

    def test_client_idle_is_not_success(self):
        self.report['client'].update(idle_expired_connections=1, status='idle-expired',
                                     http_transfer_complete=False, lifecycle_closed=False)
        self.assertFalse(STRESS.delivery_passed(self.report))


if __name__ == '__main__':
    unittest.main()
