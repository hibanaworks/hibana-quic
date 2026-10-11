"""Focused, dependency-free tests of the pinned runner's JSON checkpoints.

Only runner orchestration, result export, and case execution are AST-loaded.
The real protocol analyzers, Docker, pyshark, and network are never loaded.
Set RUNNER_SOURCE to exercise another patched copy of interop.py.
"""

import ast
from datetime import datetime
from enum import Enum
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(os.environ.get("RUNNER_SOURCE", Path(__file__).resolve().parents[3] / ".ci-work/runner/interop.py"))


class TestResult(Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class Perspective(Enum):
    SERVER = "server"
    CLIENT = "client"


def load_runner(source):
    tree = ast.parse(source.read_text(), filename=str(source))
    runner = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "InteropRunner"
    )
    wanted = {"run", "_export_results", "_run_test", "_run_testcase"}
    methods = [
        node for node in runner.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {node.name for node in methods} == wanted
    for method in methods:
        # Type annotations reference protocol modules intentionally not imported.
        method.returns = None
        for argument in method.args.args:
            argument.annotation = None
    isolated = ast.Module(
        body=[ast.ClassDef(name="InteropRunner", bases=[], keywords=[],
                           body=methods, decorator_list=[])],
        type_ignores=[],
    )
    namespace = {
        "datetime": datetime, "json": json, "logging": logging, "os": os,
        "tempfile": tempfile, "TestResult": TestResult, "shutil": shutil,
        "subprocess": subprocess, "LogFileFormatter": logging.Formatter,
        "Perspective": Perspective, "QUIC_VERSION": 1,
    }
    exec(compile(ast.fix_missing_locations(isolated), str(source), "exec"), namespace)
    return namespace["InteropRunner"]


def make_case(label):
    # Match the class-level metadata interface used by _export_results.
    return type(label, (), {
        "name": staticmethod(lambda: label),
        "abbreviation": staticmethod(lambda: label),
        "desc": staticmethod(lambda: "mock case " + label),
    })


def make_runner(output, cases=None, measurements=None):
    cases = list(cases or [])
    measurements = list(measurements or [])
    runner = load_runner(SOURCE)()
    runner._output = str(output) if output is not None else ""
    runner._start_time = datetime(2026, 10, 11)
    runner._log_dir = "mock-logs"
    runner._client_server_pairs = [("client", "server")]
    runner._implementations = {
        role: {"image": role + "-fixture", "url": "https://example.invalid/" + role}
        for role in ["client", "server"]
    }
    runner._tests = cases
    runner._measurements = measurements
    runner.test_results = {"server": {"client": {case: {} for case in cases}}}
    runner.measurement_results = {
        "server": {"client": {case: {} for case in measurements}}
    }
    runner._check_impl_is_compliant = mock.Mock(return_value=True)
    runner._run_testcase = mock.Mock()
    runner._run_measurement = mock.Mock()
    runner._postprocess_results = mock.Mock()
    runner._print_results = mock.Mock()
    return runner


def read_results(output):
    return [entry["result"] for entry in json.loads(Path(output).read_text())["results"][0]]


def exercise_unhandled_exception(source, output):
    global SOURCE
    SOURCE = Path(source)
    cases = [make_case(label) for label in ["done", "crashes", "not-run"]]
    runner = make_runner(output, cases)
    runner._run_testcase.side_effect = [TestResult.SUCCEEDED, RuntimeError("analyzer failed")]
    # Deliberately no catch: the caller must observe a nonzero process status.
    runner.run()


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "result.json"
        self.cases = [make_case(label) for label in ["done", "crashes", "not-run"]]

    def assert_exception_checkpoint(self, verdict):
        runner = make_runner(self.output, self.cases)
        error = RuntimeError("analyzer failed")

        def run_case(_server, _client, case):
            if case is self.cases[0]:
                self.assertEqual(read_results(self.output), [None, None, None])
                return verdict
            self.assertIs(case, self.cases[1])
            # The earlier verdict must already be persisted before the next case.
            self.assertEqual(read_results(self.output), [verdict.value, None, None])
            raise error

        runner._run_testcase.side_effect = run_case
        with self.assertRaises(RuntimeError) as caught:
            runner.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(read_results(self.output), [verdict.value, None, None])
        self.assertEqual(runner._run_testcase.call_count, 2)
        self.assertEqual(runner.test_results["server"]["client"][self.cases[1]], {})
        runner._postprocess_results.assert_not_called()
        runner._print_results.assert_not_called()

    def test_success_then_exception_keeps_only_completed_success(self):
        self.assert_exception_checkpoint(TestResult.SUCCEEDED)

    def test_failure_then_exception_stays_failed(self):
        self.assert_exception_checkpoint(TestResult.FAILED)

    def test_unsupported_then_exception_stays_unsupported(self):
        self.assert_exception_checkpoint(TestResult.UNSUPPORTED)

    def test_first_analyzer_exception_leaves_all_cases_null(self):
        runner = make_runner(self.output, self.cases)
        runner._run_testcase.side_effect = RuntimeError("first analyzer failed")
        with self.assertRaisesRegex(RuntimeError, "first analyzer failed"):
            runner.run()
        self.assertEqual(read_results(self.output), [None, None, None])

    def test_normal_run_preserves_verdicts_and_failure_exit_count(self):
        runner = make_runner(self.output, self.cases)
        runner._run_testcase.side_effect = list(TestResult)
        export = runner._export_results
        runner._export_results = mock.Mock(wraps=export)
        self.assertEqual(runner.run(), 1)
        self.assertEqual(read_results(self.output), ["succeeded", "failed", "unsupported"])
        self.assertEqual(runner._export_results.call_count, 5)  # Initial, three cases, final.
        runner._postprocess_results.assert_called_once_with()
        runner._print_results.assert_called_once_with()

    def test_final_export_includes_existing_postprocessing(self):
        runner = make_runner(self.output, self.cases[:1])
        runner._run_testcase.return_value = TestResult.FAILED

        def postprocess():
            # Existing runner behavior can mark a failed case unsupported.
            self.assertEqual(read_results(self.output), ["failed"])
            runner.test_results["server"]["client"][self.cases[0]] = TestResult.UNSUPPORTED

        runner._postprocess_results.side_effect = postprocess
        self.assertEqual(runner.run(), 1)
        self.assertEqual(read_results(self.output), ["unsupported"])

    def test_completed_measurement_persists_before_later_exception(self):
        measurements = [make_case(label) for label in ["measured", "crashes"]]
        runner = make_runner(self.output, measurements=measurements)
        result = SimpleNamespace(result=TestResult.SUCCEEDED, details="123 units")
        runner._run_measurement.side_effect = [result, RuntimeError("measurement failed")]
        with self.assertRaisesRegex(RuntimeError, "measurement failed"):
            runner.run()
        # Preserve the existing schema: unfinished measurements are omitted.
        data = json.loads(self.output.read_text())
        self.assertEqual(data["measurements"], [[{
            "name": "measured", "abbr": "measured", "result": "succeeded",
            "details": "123 units",
        }]])
        self.assertEqual(runner._run_measurement.call_count, 2)

    def test_replacement_is_complete_and_same_directory(self):
        previous = '{"previous": true}'
        self.output.write_text(previous)
        runner = make_runner(self.output, self.cases)
        replace = os.replace

        def inspect_replace(source, target):
            self.assertEqual(Path(source).parent, self.output.parent)
            self.assertEqual(Path(target), self.output)
            self.assertEqual(self.output.read_text(), previous)
            self.assertEqual(json.loads(Path(source).read_text())["results"][0][0]["result"], None)
            replace(source, target)

        with mock.patch.object(os, "replace", side_effect=inspect_replace) as replacement:
            with mock.patch.object(os, "fsync", wraps=os.fsync) as sync:
                runner._export_results()
        replacement.assert_called_once()
        sync.assert_called_once()
        self.assertEqual(read_results(self.output), [None, None, None])
        self.assertEqual(set(self.output.parent.iterdir()), {self.output})

    def test_partial_json_failure_preserves_previous_file_and_cleans_temp(self):
        previous = '{"previous": true}'
        self.output.write_text(previous)
        runner = make_runner(self.output, self.cases)

        def broken_dump(_value, stream):
            stream.write('{"incomplete":')
            raise OSError("simulated serialization/write failure")

        with mock.patch.object(json, "dump", side_effect=broken_dump):
            with self.assertRaisesRegex(OSError, "serialization/write failure"):
                runner._export_results()
        self.assertEqual(self.output.read_text(), previous)
        self.assertEqual(set(self.output.parent.iterdir()), {self.output})

    def test_replace_failure_preserves_previous_file_and_cleans_temp(self):
        previous = '{"previous": true}'
        self.output.write_text(previous)
        runner = make_runner(self.output, self.cases)
        with mock.patch.object(os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                runner._export_results()
        self.assertEqual(self.output.read_text(), previous)
        self.assertEqual(set(self.output.parent.iterdir()), {self.output})

    def test_no_output_option_still_disables_export(self):
        runner = make_runner(None, self.cases)
        runner._run_testcase.side_effect = list(TestResult)
        with mock.patch.object(tempfile, "NamedTemporaryFile") as temporary:
            self.assertEqual(runner.run(), 1)
        temporary.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_unhandled_analyzer_exception_exits_nonzero(self):
        process = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--exercise-exception",
             str(SOURCE.resolve()), str(self.output)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("RuntimeError: analyzer failed", process.stderr)
        self.assertEqual(read_results(self.output), ["succeeded", None, None])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--exercise-exception":
        exercise_unhandled_exception(sys.argv[2], sys.argv[3])
    else:
        unittest.main(verbosity=2)
