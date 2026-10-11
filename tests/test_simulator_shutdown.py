import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location('shutdown', Path(__file__).resolve().parents[1] / 'tools/ci/simulator_shutdown.py')
SHUTDOWN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHUTDOWN)


class CaptureShutdown(unittest.TestCase):
    def test_only_exact_terminal_tail_is_changed(self):
        prefix = '#!/bin/bash\nset -e\n# unchanged simulator and capture startup\n'
        self.assertEqual(SHUTDOWN.patch(prefix + SHUTDOWN.OLD), prefix + SHUTDOWN.NEW)
        for source in ('wait\n', SHUTDOWN.OLD + 'echo unexpected\n', SHUTDOWN.OLD * 2):
            with self.assertRaises(ValueError):
                SHUTDOWN.patch(source)

    def capture_at_container_exit(self, tail):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / 'capture.py'
            child.write_text('import signal,time,pathlib\n'
                             'def flush(*args):\n'
                             ' time.sleep(0.2)\n'
                             ' pathlib.Path("flushed").write_text("complete")\n'
                             ' raise SystemExit(0)\n'
                             'signal.signal(signal.SIGTERM,flush)\n'
                             'pathlib.Path("ready").touch()\n'
                             'signal.pause()\n')
            script = 'set -e\npython3 capture.py &\nPID=$!\n' + tail
            parent = subprocess.Popen(['bash', '-c', script], cwd=root, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists():
                    if parent.poll() is not None or time.monotonic() >= deadline:
                        self.fail('capture child did not start')
                    time.sleep(0.01)
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=5)
                # Container exit kills any surviving capture before it can flush.
                try:
                    os.killpg(parent.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return (root / 'flushed').read_text() if (root / 'flushed').exists() else None
            finally:
                if parent.poll() is None:
                    os.killpg(parent.pid, signal.SIGKILL)
                    parent.wait()

    def test_original_tail_exits_before_capture_flush(self):
        self.assertIsNone(self.capture_at_container_exit(SHUTDOWN.OLD))

    def test_reap_tail_preserves_capture_before_container_exit(self):
        self.assertEqual(self.capture_at_container_exit(SHUTDOWN.NEW), 'complete')


if __name__ == '__main__':
    unittest.main()
