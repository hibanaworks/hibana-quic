#!/usr/bin/env python3
"""Retain every requested seed, including failures, for one candidate binary."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
fixture = Path(__file__).resolve().parents[2] / 'host/tests/test_direct_parallel_localhost.py'
summary = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
           'scope': 'native self-peer stress; separate from official independent interop',
           'cases': []}
for impairment in ('loss', 'corruption'):
    for seed in range(20261009, 20261014):
        name = f'{impairment}-{seed}'
        result = subprocess.run([sys.executable, str(fixture), '--binary', str(binary),
                                 '--connections', '50', '--impairment', impairment,
                                 '--impairment-model', 'random', '--impairment-seed', str(seed),
                                 '--loss-scope', 'global', '--timeout-seconds', '180',
                                 '--output', str(output / (name + '.json'))])
        summary['cases'].append({'name': name, 'exit_code': result.returncode,
                                 'passed': result.returncode == 0})
        summary['passed'] = all(case['passed'] for case in summary['cases'])
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
sys.exit(0 if summary['passed'] else 1)
