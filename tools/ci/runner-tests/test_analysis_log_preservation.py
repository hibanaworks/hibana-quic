"""AST-isolated case execution tests; no Docker or protocol analyzer imports."""

import logging
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from test_result_checkpoint import TestResult, make_runner, read_results


def executable_case(label, payload, error=None, cleanup_error=None):
    instances = []

    class Case:
        name = staticmethod(lambda: label)
        abbreviation = staticmethod(lambda: label)
        desc = staticmethod(lambda: "mock analyzer " + label)

        def __init__(self, **kwargs):
            instances.append(self)
            self.check = mock.Mock(side_effect=error, return_value=TestResult.SUCCEEDED)
            self.cleanup = mock.Mock(side_effect=cleanup_error)
            self.result = mock.Mock(return_value=1)

        def __str__(self):
            return label

        get_paths = staticmethod(lambda: [])
        get_paths_server = staticmethod(lambda: [])
        testname = staticmethod(lambda _perspective: label)
        certs_dir = staticmethod(lambda: str(payload))
        client_www_dir = staticmethod(lambda: str(payload))
        client_download_dir = staticmethod(lambda: str(payload))
        server_www_dir = staticmethod(lambda: str(payload))
        server_download_dir = staticmethod(lambda: str(payload))
        scenario = staticmethod(lambda: "mock-scenario")
        additional_envs = staticmethod(lambda: [])
        additional_containers = staticmethod(lambda: [])
        timeout = staticmethod(lambda: 1)

    Case.instances = instances
    return Case


class AnalyzerLogPreservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        (self.payload / "file.bin").write_bytes(b"fixture-payload")
        self.output = self.root / "result.json"
        # Prevent logging.basicConfig from changing global handlers during tests.
        handler = logging.NullHandler()
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        self.handlers = list(logging.getLogger().handlers)
        self.temporary_directories = []
        temporary_directory = tempfile.TemporaryDirectory

        def tracked_directory(*args, **kwargs):
            directory = temporary_directory(*args, **kwargs)
            original_cleanup = directory.cleanup
            directory.cleanup = mock.Mock(wraps=original_cleanup)
            self.temporary_directories.append(directory)
            self.addCleanup(original_cleanup)
            return directory

        self.temp_patch = mock.patch.object(tempfile, "TemporaryDirectory", side_effect=tracked_directory)
        self.temp_patch.start()
        self.addCleanup(self.temp_patch.stop)
        self.process_patch = mock.patch.object(
            subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=b"client exited with code 0\n"),
        )
        self.process = self.process_patch.start()
        self.addCleanup(self.process_patch.stop)

    def runner(self, cases):
        runner = make_runner(self.output, cases)
        # Use the AST-loaded real wrappers instead of the default execution mock.
        del runner._run_testcase
        runner._log_dir = str(self.root / "logs")
        runner._save_files = True
        runner._is_unsupported = mock.Mock(return_value=False)

        def copy_logs(container, directory):
            (Path(directory.name) / "captured.log").write_text(container + "-evidence")

        runner._copy_logs = mock.Mock(side_effect=copy_logs)
        return runner

    def assert_evidence_saved(self, label, save_files=True):
        location = self.root / "logs" / "server_client" / label
        for role in ["server", "client", "sim"]:
            self.assertEqual((location / role / "captured.log").read_text(), role + "-evidence")
        self.assertTrue((location / "output.txt").is_file())
        if save_files:
            for role in ["server_www", "client_downloads", "client_www", "server_downloads"]:
                self.assertEqual((location / role / "file.bin").read_bytes(), b"fixture-payload")

    def assert_cleaned_up(self):
        self.assertEqual(logging.getLogger().handlers, self.handlers)
        for directory in self.temporary_directories:
            directory.cleanup.assert_called_once_with()
            self.assertFalse(Path(directory.name).exists())

    def test_runtime_error_preserves_logs_and_propagates_same_exception(self):
        error = RuntimeError("analyzer primary failure")
        case = executable_case("crashes", self.payload, error)
        runner = self.runner([case])
        with self.assertRaises(RuntimeError) as caught:
            runner.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(read_results(self.output), [None])
        self.assert_evidence_saved("crashes")
        case.instances[0].cleanup.assert_called_once_with()
        case.instances[0].result.assert_not_called()
        runner._postprocess_results.assert_not_called()
        self.assert_cleaned_up()

    def test_keyboard_interrupt_is_preserved_without_a_verdict(self):
        error = KeyboardInterrupt("interrupted analyzer")
        case = executable_case("interrupted", self.payload, error)
        runner = self.runner([case])
        with self.assertRaises(KeyboardInterrupt) as caught:
            runner.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(read_results(self.output), [None])
        self.assert_evidence_saved("interrupted")
        case.instances[0].result.assert_not_called()
        self.assert_cleaned_up()

    def test_prior_success_survives_real_case_execution_then_exception(self):
        error = RuntimeError("second analyzer failed")
        cases = [
            executable_case("done", self.payload),
            executable_case("crashes", self.payload, error),
            executable_case("not-run", self.payload),
        ]
        runner = self.runner(cases)
        with self.assertRaises(RuntimeError) as caught:
            runner.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(read_results(self.output), ["succeeded", None, None])
        self.assert_evidence_saved("done", save_files=False)
        self.assert_evidence_saved("crashes")
        self.assertEqual(cases[2].instances, [])
        cases[1].instances[0].result.assert_not_called()
        self.assert_cleaned_up()

    def test_log_copy_failure_does_not_mask_primary_and_cleanup_runs(self):
        error = RuntimeError("analyzer primary failure")
        case = executable_case("crashes", self.payload, error)
        runner = self.runner([case])
        with mock.patch.object(shutil, "copytree", side_effect=OSError("secondary save failure")) as copy:
            with self.assertLogs(level="ERROR"):
                with self.assertRaises(RuntimeError) as caught:
                    runner.run()
        self.assertIs(caught.exception, error)
        copy.assert_called_once()
        self.assertEqual(read_results(self.output), [None])
        case.instances[0].cleanup.assert_called_once_with()
        case.instances[0].result.assert_not_called()
        self.assert_cleaned_up()

    def test_case_cleanup_failure_does_not_mask_primary_or_skip_temp_cleanup(self):
        error = RuntimeError("analyzer primary failure")
        case = executable_case("crashes", self.payload, error, OSError("secondary cleanup failure"))
        runner = self.runner([case])
        with self.assertLogs(level="ERROR"):
            with self.assertRaises(RuntimeError) as caught:
                runner.run()
        self.assertIs(caught.exception, error)
        self.assert_evidence_saved("crashes")
        self.assertEqual(read_results(self.output), [None])
        case.instances[0].cleanup.assert_called_once_with()
        case.instances[0].result.assert_not_called()
        self.assert_cleaned_up()

    def test_file_not_found_retains_original_failed_verdict_behavior(self):
        case = executable_case("missing", self.payload, FileNotFoundError("missing capture"))
        runner = self.runner([case])
        with self.assertLogs(level="ERROR"):
            self.assertEqual(runner.run(), 1)
        self.assertEqual(read_results(self.output), ["failed"])
        self.assert_evidence_saved("missing")
        case.instances[0].result.assert_called_once_with()
        self.assert_cleaned_up()

    def test_save_failure_without_analyzer_exception_still_propagates(self):
        case = executable_case("done", self.payload)
        runner = self.runner([case])
        error = OSError("ordinary save failure")
        with mock.patch.object(shutil, "copytree", side_effect=error):
            with self.assertRaises(OSError) as caught:
                runner.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(read_results(self.output), [None])
        case.instances[0].result.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
