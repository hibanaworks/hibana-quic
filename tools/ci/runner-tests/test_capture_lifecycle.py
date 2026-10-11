"""Fail-closed synchronous analyzer ownership; no packets or tools required."""
import ast
import logging
import os
from pathlib import Path
import types
import unittest

SOURCE = Path(os.environ.get('RUNNER_TRACE_SOURCE', Path(__file__).resolve().parents[3] / '.ci-work/runner/trace.py'))

class Lifecycle(unittest.TestCase):
    def invoke(self, iteration_error=None, iterator_error=None, close_error=None):
        self.events = []
        events = self.events
        class Iterator:
            def __iter__(self): return self
            def __next__(self):
                events.append('next')
                if len([v for v in events if v == 'next']) == 1: return {'quic': object()}
                if iteration_error: raise iteration_error
                raise StopIteration
            def close(self):
                events.append('iterator-close')
                if iterator_error: raise iterator_error
        class Capture:
            def __iter__(self): return Iterator()
            def close(self):
                events.append('capture-close')
                if close_error: raise close_error
        tree=ast.parse(SOURCE.read_text())
        method=next(n for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='TraceAnalyzer' for n in c.body if isinstance(n,ast.FunctionDef) and n.name=='_get_packets')
        ns={'List':list,'logging':logging,'pyshark':types.SimpleNamespace(FileCapture=lambda *a,**k:Capture())}
        exec(compile(ast.Module(body=[method],type_ignores=[]),'<trace-method>','exec'),ns)
        return ns['_get_packets'](types.SimpleNamespace(_filename='empty',_keylog_file=None),'quic')
    def test_complete(self):
        self.assertEqual(len(self.invoke()),1)
        self.assertEqual(self.events[-2:],['iterator-close','capture-close'])
    def test_iteration_failure_never_returns_partial(self):
        error=RuntimeError('private iteration detail')
        with self.assertRaises(RuntimeError) as caught:self.invoke(iteration_error=error)
        self.assertIs(caught.exception,error)
        self.assertEqual(self.events[-2:],['iterator-close','capture-close'])
    def test_iterator_close_failure(self):
        with self.assertRaises(ValueError):self.invoke(iterator_error=ValueError('private'))
        self.assertEqual(self.events[-1],'capture-close')
    def test_capture_close_failure(self):
        with self.assertRaises(ValueError):self.invoke(close_error=ValueError('private'))
    def test_primary_survives_both_cleanup_failures(self):
        error=KeyboardInterrupt()
        with self.assertLogs(level='ERROR'):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.invoke(error,ValueError('secondary'),RuntimeError('third'))
        self.assertIs(caught.exception,error)
    def test_first_cleanup_failure_survives_second(self):
        error=ValueError('first')
        with self.assertLogs(level='ERROR'):
            with self.assertRaises(ValueError) as caught:self.invoke(iterator_error=error,close_error=RuntimeError('second'))
        self.assertIs(caught.exception,error)

if __name__=='__main__':unittest.main()
