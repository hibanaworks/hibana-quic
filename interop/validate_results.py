#!/usr/bin/env python3
"""Fail-closed reader for runner 740c05a's JSON; never executes endpoints.

This checks runner verdict completeness, not the truth of pcap/file assertions.
Full acceptance additionally requires inspectable evidence and bounded TLS.
"""
import argparse
import json
from pathlib import Path


class InvalidResult(ValueError):
    pass


def validate(document, client, server, targets):
    expected = {case['name'] for case in targets['cases']}
    if len(expected) != 20 or len(targets['cases']) != 20:
        raise InvalidResult('target manifest must contain exactly 20 unique cases')
    if document.get('quic_version') != '0x1':
        raise InvalidResult('runner QUIC version is not 0x1')
    # Separate directional output files prevent ambiguous Cartesian row mapping.
    if document.get('clients') != [client] or document.get('servers') != [server]:
        raise InvalidResult('expected one exact client/server pair in this output')
    rows = document.get('results')
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], list):
        raise InvalidResult('expected one runner result row')
    definitions = document.get('tests')
    if not isinstance(definitions, dict):
        raise InvalidResult('missing runner tests dictionary')
    seen = set()
    failures = []
    for item in rows[0]:
        if not isinstance(item, dict):
            raise InvalidResult('result entry must be an object')
        name, abbr = item.get('name'), item.get('abbr')
        if not isinstance(name, str) or name not in expected or name in seen:
            raise InvalidResult(f'unexpected or duplicate case: {name!r}')
        if not isinstance(abbr, str) or definitions.get(abbr, {}).get('name') != name:
            raise InvalidResult(f'case/abbreviation mismatch: {name}')
        seen.add(name)
        if item.get('result') != 'succeeded':
            failures.append(f'{name}: {item.get("result")!r}')
    if seen != expected:
        raise InvalidResult(f'missing cases: {sorted(expected - seen)}')
    if failures:
        raise InvalidResult('non-passing cases: ' + ', '.join(failures))
    return len(seen)


def load(path):
    # Duplicate JSON keys are a malformed result, not last-key-wins success.
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidResult(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--targets', type=Path, default=Path(__file__).with_name('targets.json'))
    parser.add_argument('--hibana-client', type=Path, required=True)
    parser.add_argument('--hibana-server', type=Path, required=True)
    args = parser.parse_args()
    try:
        target = load(args.targets)
        count = validate(load(args.hibana_client), 'hibana-quic', 'neqo', target)
        count += validate(load(args.hibana_server), 'neqo', 'hibana-quic', target)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        parser.exit(1, f'NOT_PASSED: {exc}\n')
    print(f'Runner verdicts complete: {count}/40. This is not the release gate: verify backend, revisions, files, pcap evidence, all 3 attempts, and Pico separately.')


if __name__ == '__main__':
    main()
