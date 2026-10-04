"""Check complete slot binding and a stream-ID-only mutation counterexample."""
from z3 import And, Ints, Not, Solver, sat, unsat

opened = Ints('opened_connection opened_slot opened_generation opened_stream')
chunk = Ints('chunk_connection chunk_slot chunk_generation chunk_stream')
checked = And(*(a == b for a, b in zip(opened, chunk)))
for name, index in [('connection', 0), ('slot', 1), ('generation', 2), ('stream', 3)]:
    solver = Solver()
    solver.add(checked)
    assert solver.check() == sat, 'acceptance must be reachable'
    solver.add(opened[index] != chunk[index])
    assert solver.check() == unsat
    print(f'accepted slot preserves {name}: UNSAT; acceptance nonvacuous')
solver = Solver()
solver.add(opened[3] == chunk[3], opened[2] != chunk[2])
assert solver.check() == sat
print('stream-ID-only comparison admits a stale generation: SAT', solver.model())
