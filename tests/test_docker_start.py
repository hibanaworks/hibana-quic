"""Exercise the literal CI restart block without touching a host service."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DockerStart(unittest.TestCase):
    def run_case(self, failure):
        source = (ROOT / 'ci/run-interop.sh').read_text()
        block = source.split('if ! sudo systemctl restart docker; then\n', 1)[1]
        block = 'if ! sudo systemctl restart docker; then\n' + block.split('\nfor attempt in ', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ci-safe-results').mkdir()
            (root / 'sudo').write_text('#!/bin/sh\nexec "$@"\n')
            (root / 'systemctl').write_text('''#!/usr/bin/env python3
import os,sys,pathlib
p=pathlib.Path('calls')
old=p.read_text() if p.exists() else ''
p.write_text(old+' '.join(sys.argv[1:])+'\\n')
if sys.argv[1]=='show': print(os.environ['TEST_FAILURE'])
elif sys.argv[1]=='restart' and 'restart' not in old and os.environ['TEST_FAILURE']:
    sys.exit(1)
''')
            for name in ('sudo', 'systemctl'):
                (root / name).chmod(0o700)
            result = subprocess.run(['bash', '-eu', '-c', block], cwd=root,
                                    env=dict(os.environ, PATH=str(root)+':'+os.environ['PATH'],
                                             TEST_FAILURE=failure), capture_output=True)
            report = root / 'ci-safe-results/docker-start-failure.json'
            return result.returncode, (root / 'calls').read_text().splitlines(), (
                json.loads(report.read_text()) if report.exists() else None)

    def test_success_is_not_restarted_again(self):
        code, calls, report = self.run_case('')
        self.assertEqual(code, 0)
        self.assertEqual(calls, ['restart docker'])
        self.assertIsNone(report)

    def test_only_actual_start_limit_gets_one_reset_and_retry(self):
        code, calls, report = self.run_case('start-limit-hit')
        self.assertEqual(code, 0)
        self.assertEqual(calls[-2:], ['reset-failed docker.service', 'restart docker.service'])
        self.assertEqual(sum(c.startswith('restart') for c in calls), 2)
        self.assertTrue(report['retry_permitted'])
        self.assertFalse(report['testcases_started'])

    def test_daemon_failure_is_not_hidden_by_retry(self):
        code, calls, report = self.run_case('exit-code')
        self.assertNotEqual(code, 0)
        self.assertFalse(any(c.startswith('reset-failed') for c in calls))
        self.assertEqual(sum(c.startswith('restart') for c in calls), 1)
        self.assertFalse(report['retry_permitted'])


if __name__ == '__main__':
    unittest.main()
