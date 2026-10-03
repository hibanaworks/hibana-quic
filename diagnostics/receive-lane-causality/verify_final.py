#!/usr/bin/env python3
"""Check current Rust aliases with two Python ports; this is not Rust validation."""
import hashlib
import json
from pathlib import Path
from model import Parser, Node, analyze, describe
from marker_port import analyze_markers

root = Path(__file__).resolve().parents[2]
paths = {'prefix': root / 'src/connection/protocol.rs',
         'app': root / 'src/connection/application/protocol.rs'}
p = Parser(paths)
graph = Node('seq', [p.expand('prefix', 'Flow'),
                    Node('seq', [p.expand('app', 'Startup'), p.expand('app', 'Flow')])])
events, lanes, structured, reentry = analyze(graph)
other_structured, other_reentry, markers = analyze_markers(graph, events)
assert structured == other_structured, 'structured analysis implementations disagree'
assert reentry == other_reentry, 'roll-reentry analysis implementations disagree'
result = {
    'source_base': '74280de429eb37f86b9aa2e9f9573735eb65f53b',
    'caveat': 'Executed source-level Python models only. Not Rust compilation, Hibana global validation, runtime, QUIC or interop execution.',
    'source_sha256': {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in paths.values()},
    'events': len(events), 'markers': markers, 'lane_span': lanes,
    'structured_failures': structured, 'roll_reentry_failures': reentry,
    'event_rows': [describe(event, p.names) for event in events],
}
Path(__file__).with_name('implemented_source_result.json').write_text(json.dumps(result, indent=2) + '\n')
print(f'{len(events)} events; {markers} markers; {lanes} lanes; '
      f'{len(structured)} structured failures; {len(reentry)} reentry failures')
assert not structured and not reentry, 'source model found receive-lane causality failures'
