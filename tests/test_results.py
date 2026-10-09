import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('validator', ROOT / 'tests/interop/validate_results.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
TARGETS = json.loads((ROOT / 'tests/interop/targets.json').read_text())


def fixture():
    names = [c['name'] for c in TARGETS['cases']]
    return {'clients':['hibana-quic'], 'servers':['neqo'], 'quic_version':'0x1',
            'tests':{str(i): {'name':name} for i, name in enumerate(names)},
            'results':[[{'abbr':str(i), 'name':name, 'result':'succeeded'} for i,name in enumerate(names)]]}


class Gate(unittest.TestCase):
    def check(self, data):
        return v.validate(data, 'hibana-quic', 'neqo', TARGETS)

    def test_exact_matrix(self):
        self.assertEqual(self.check(fixture()), 20)
        self.assertEqual(TARGETS['release_attempts'], 3)
        mapping = {x['name']:x for x in TARGETS['cases']}
        self.assertEqual(mapping['keyupdate']['server_testcase'], 'transfer')
        self.assertEqual(mapping['handshakeloss']['client_testcase'], 'multiconnect')

    def test_all_nonpassing_states_rejected(self):
        for state in ['failed','unsupported','skip','NOT_RUN','BLOCKED_ENV','BLOCKED_PEER',127,0,None,True,'PASSED']:
            with self.subTest(state=state):
                data=fixture(); data['results'][0][0]['result']=state
                with self.assertRaises(v.InvalidResult): self.check(data)

    def test_missing_duplicate_or_extra_case(self):
        data=fixture(); data['results'][0].pop()
        with self.assertRaises(v.InvalidResult): self.check(data)
        data=fixture(); data['results'][0].append(copy.deepcopy(data['results'][0][0]))
        with self.assertRaises(v.InvalidResult): self.check(data)
        data=fixture(); data['results'][0][0]['name']='http3'
        with self.assertRaises(v.InvalidResult): self.check(data)

    def test_direction_version_and_schema(self):
        for key,value in [('clients',['neqo']),('servers',['neqo','other']),('quic_version','0x2'),('results',[]),('tests',{})]:
            data=fixture(); data[key]=value
            with self.assertRaises(v.InvalidResult): self.check(data)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input.json'; p.write_text('{"results":[],"results":[1]}')
            with self.assertRaises(v.InvalidResult): v.load(p)


if __name__ == '__main__': unittest.main()
