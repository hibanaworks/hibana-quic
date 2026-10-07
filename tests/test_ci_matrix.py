"""One source commit, exact 44-cell coverage, without reference self-tests."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]
COMMIT = 'a' * 40


class Matrix(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'ci').mkdir()
        self.request = json.loads((SOURCE / 'ci/interop-request.json').read_text())
        (self.root / 'ci/interop-request.json').write_text(json.dumps(self.request))
        pins_text = (SOURCE / 'ci/pins.env').read_text()
        (self.root / 'ci/pins.env').write_text(pins_text)
        self.pins = dict(line.split('=', 1) for line in pins_text.splitlines() if line and not line.startswith('#'))
        with patch.dict(os.environ, {'ROOT': str(self.root)}):
            spec = importlib.util.spec_from_file_location('matrix_runner', SOURCE / 'ci/run_in_tools.py')
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        self.artifacts = self.root / 'artifacts'
        self.artifacts.mkdir()
        for group in self.request['groups']:
            folder = self.folder(group)
            folder.mkdir()
            reference = group['reference_implementation']
            self.put(group, 'environment.json', dict(source_commit=COMMIT, run_id='101', run_attempt='1', interop_group=group['name']))
            pins = dict(self.pins, REFERENCE_IMPLEMENTATION=reference,
                        SIM_IMAGE='martenseemann/quic-network-simulator@sha256:' + 'b' * 64,
                        REFERENCE_IMAGE=('cloudflare/quiche-qns@sha256:' if reference == 'quiche' else 'sha256:') + 'c' * 64)
            self.put(group, 'pins.json', pins)
            phases = ['bounded-client', 'bounded-server']
            for phase, client, server in [(phases[0], 'hibana-quic', reference), (phases[1], reference, 'hibana-quic')]:
                rows = [dict(name=case, abbr=self.module.CASE_ABBREVIATIONS[case], result='succeeded') for case in group['cases']]
                self.put(group, phase + '-verdict.json', dict(phase=phase, client=client, server=server,
                    status='PASSED', exit_code=0, cleanup_exit_code=0, passed=True, results=rows,
                    non_null_case_results=len(rows), unexecuted_case_results=0, original_json_sha256='d' * 64))
            count = len(group['cases']) * 2
            self.put(group, 'summary.json', dict(status='PASSED', reference_self_tests='omitted', interop_group=group['name'],
                reference_implementation=reference, runner_source_unchanged=True, phases=phases,
                selected_cases=sorted(group['cases']), candidate_directions=['client', 'server'],
                case_results=count, non_null_case_results=count, unexecuted_case_results=0))

    def folder(self, group):
        return self.artifacts / ('interop-pilot-101-1-' + group['name'])

    def put(self, group, name, value):
        (self.folder(group) / name).write_text(json.dumps(value))

    def get(self, group, name):
        return json.loads((self.folder(group) / name).read_text())

    def verify(self):
        with redirect_stdout(io.StringIO()):
            return self.module.verify_matrix(self.artifacts, COMMIT, '101', '1')

    def report(self):
        return json.loads((self.root / 'ci-safe-results/summary.json').read_text())

    def test_exact_44_same_commit_without_self_controls(self):
        self.assertEqual(self.verify(), 0)
        result = self.report()
        self.assertEqual((result['candidate_results'], result['candidate_passed'], result['control_results'], result['control_passed']), (44, 44, 0, 0))
        self.assertEqual(result['source_commit'], COMMIT)
        self.assertTrue(result['same_commit_all_44_executed'])
        self.assertTrue(result['full_44_case_direction_matrix'])
        self.assertEqual(sum(cell['reference'] == 'neqo' for cell in result['candidate_cells']), 34)
        self.assertEqual(sum(cell['reference'] == 'quiche' for cell in result['candidate_cells']), 10)

    def test_group_selection_cannot_silently_choose_or_reduce_scope(self):
        group = self.request['groups'][0]
        self.assertEqual(self.module.selected_request(self.request, group['name'])['cases'], group['cases'])
        for name in (None, 'unknown', '../secret'):
            with self.assertRaises(RuntimeError):
                self.module.selected_request(self.request, name)
        for mutation in ('missing', 'duplicate', 'one-direction', 'wrong-peer', 'path-name', 'wrong-count'):
            request = copy.deepcopy(self.request)
            if mutation == 'missing': request['groups'].pop()
            elif mutation == 'duplicate': request['groups'][1]['cases'].append(request['groups'][0]['cases'][0])
            elif mutation == 'one-direction': request['candidate_directions'] = ['client']
            elif mutation == 'wrong-peer': request['groups'][0]['reference_implementation'] = 'unknown'
            elif mutation == 'path-name': request['groups'][0]['name'] = '../secret'
            else: request['candidate_case_direction_results'] = 32
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                self.module.qualification_groups(request)

    def test_diagnostic_subset_runs_only_requested_cases_and_direction(self):
        original = copy.deepcopy(self.request)
        with patch.dict(os.environ, {'INTEROP_DIAGNOSTIC_CASES': 'handshakeloss,connectionmigration',
                                     'INTEROP_DIAGNOSTIC_DIRECTIONS': 'client'}):
            matrix = self.module.pilot_matrix(self.request)
            self.assertEqual(matrix, {'include': [{'group': 'quiche-loss-early'}, {'group': 'neqo-migration'}]})
            for name, case, peer in [('quiche-loss-early', 'handshakeloss', 'quiche'),
                                     ('neqo-migration', 'connectionmigration', 'neqo')]:
                selected = self.module.selected_request(self.request, name)
                self.assertEqual(selected['cases'], [case])
                self.assertEqual(selected['candidate_directions'], ['client'])
                self.assertEqual(selected['reference_implementation'], peer)
            with self.assertRaises(RuntimeError):
                self.module.selected_request(self.request, 'neqo-basic')
        self.assertEqual(self.request, original)

    def test_diagnostic_selection_rejects_unknown_duplicate_and_invalid_direction(self):
        for cases, directions in [('unknown', 'client'), ('handshakeloss,handshakeloss', 'client'),
                                   ('../secret', 'client'), ('handshakeloss', ''),
                                   ('handshakeloss', 'unknown'), ('handshakeloss', 'client,client')]:
            with self.subTest(cases=cases, directions=directions), \
                 patch.dict(os.environ, {'INTEROP_DIAGNOSTIC_CASES': cases,
                                         'INTEROP_DIAGNOSTIC_DIRECTIONS': directions}), \
                 self.assertRaises(RuntimeError):
                self.module.pilot_matrix(self.request)

    def test_diagnostic_selection_cannot_qualify_partial_artifacts(self):
        group = next(group for group in self.request['groups'] if group['name'] == 'quiche-loss-early')
        summary = self.get(group, 'summary.json')
        summary.update(selected_cases=['handshakeloss'], candidate_directions=['client'])
        self.put(group, 'summary.json', summary)
        with patch.dict(os.environ, {'INTEROP_DIAGNOSTIC_CASES': 'handshakeloss',
                                     'INTEROP_DIAGNOSTIC_DIRECTIONS': 'client'}), \
             self.assertRaises(RuntimeError):
            self.verify()
        self.assertEqual(self.report()['status'], 'NOT_PASSED')

    def test_failed_unsupported_or_null_candidate_never_qualifies(self):
        group = next(group for group in self.request['groups'] if group['name'] == 'neqo-ecn')
        original = self.get(group, 'bounded-client-verdict.json')
        original_summary = self.get(group, 'summary.json')
        for outcome in ('failed', 'unsupported', None):
            with self.subTest(outcome=outcome):
                verdict = copy.deepcopy(original)
                verdict['results'][0]['result'] = outcome
                verdict.update(status='FAILED', passed=False, non_null_case_results=int(outcome is not None), unexecuted_case_results=int(outcome is None))
                summary = dict(original_summary, status='NOT_PASSED', non_null_case_results=1 + int(outcome is not None), unexecuted_case_results=int(outcome is None))
                self.put(group, 'bounded-client-verdict.json', verdict)
                self.put(group, 'summary.json', summary)
                self.assertEqual(self.verify(), 1)
                self.assertEqual(self.report()['candidate_passed'], 43)
                self.assertEqual(self.report()['candidate_unexecuted'], int(outcome is None))

    def test_legacy_baseline_phase_cannot_masquerade_as_candidate_only(self):
        group = self.request['groups'][0]
        summary = self.get(group, 'summary.json')
        summary['phases'].insert(0, 'neqo-baseline')
        self.put(group, 'summary.json', summary)
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_source_run_group_reference_and_pins_must_match(self):
        group = self.request['groups'][0]
        cases = [('environment.json', 'source_commit', 'e' * 40), ('environment.json', 'run_id', '102'),
                 ('environment.json', 'run_attempt', '2'), ('environment.json', 'interop_group', 'other'),
                 ('pins.json', 'RUNNER_REVISION', 'e' * 40), ('pins.json', 'REFERENCE_IMPLEMENTATION', 'quiche'),
                 ('pins.json', 'SIM_IMAGE', 'martenseemann/quic-network-simulator@sha256:' + 'e' * 64),
                 ('summary.json', 'runner_source_unchanged', False), ('summary.json', 'candidate_directions', ['client'])]
        for filename, key, value in cases:
            with self.subTest(key=key):
                original = self.get(group, filename)
                self.put(group, filename, dict(original, **{key:value}))
                with self.assertRaises(RuntimeError): self.verify()
                self.assertEqual(self.report()['status'], 'NOT_PASSED')
                self.put(group, filename, original)

    def test_missing_duplicate_wrong_direction_or_wrong_abbreviation_rejected(self):
        group = self.request['groups'][0]
        filename = 'bounded-client-verdict.json'
        original = self.get(group, filename)
        for mutation in ('missing-row', 'duplicate', 'wrong-direction', 'wrong-abbreviation', 'missing-file'):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                if mutation == 'missing-row': value['results'].pop()
                elif mutation == 'duplicate': value['results'].append(value['results'][0])
                elif mutation == 'wrong-direction': value['client'] = 'neqo'
                elif mutation == 'wrong-abbreviation': value['results'][0]['abbr'] = 'FAKE'
                self.put(group, filename, value)
                if mutation == 'missing-file': (self.folder(group) / filename).unlink()
                with self.assertRaises(RuntimeError): self.verify()
                self.assertEqual(self.report()['status'], 'NOT_PASSED')
                self.put(group, filename, original)

    def test_rejected_cleanup_or_boolean_exit_code_never_qualifies(self):
        group = next(group for group in self.request['groups'] if group['name'] == 'neqo-ecn')
        filename = 'bounded-client-verdict.json'
        original = self.get(group, filename)
        for key, value in [('exit_code', 1), ('cleanup_exit_code', 1), ('exit_code', False)]:
            with self.subTest(key=key, value=value):
                self.put(group, filename, dict(original, **{key:value}))
                self.assertEqual(self.verify(), 1)
                self.assertEqual(self.report()['status'], 'NOT_PASSED')

    def test_invalid_second_attempt_does_not_leave_a_stale_pass(self):
        self.assertEqual(self.verify(), 0)
        group = self.request['groups'][0]
        (self.folder(group) / 'environment.json').unlink()
        with self.assertRaises(RuntimeError): self.verify()
        self.assertEqual(self.report()['status'], 'NOT_PASSED')


if __name__ == '__main__':
    unittest.main()
