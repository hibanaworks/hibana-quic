"""Negative tests prevent idle observation from concealing delivery failures."""
import copy
import importlib.util
from pathlib import Path
import unittest

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
