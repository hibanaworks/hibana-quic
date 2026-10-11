"""Bounded pending-slot coalescing, not a duplicate QUIC protocol FSM."""
from z3 import And, Bool, If, Ints, Not, Solver, sat, unsat

first = Ints('first_table first_connection first_slot first_generation first_stream')
incoming = Ints('incoming_table incoming_connection incoming_slot incoming_generation incoming_stream')
old_error, new_error, retained_error = Ints('old_error new_error retained_error')
has_first, accepted = Bool('has_first'), Bool('accepted')
same = And(*(a == b for a, b in zip(first, incoming)))
rule = [accepted == If(has_first, same, True), retained_error == If(has_first, old_error, new_error)]
checks = [
    ('first error preserved', [has_first, same], retained_error == old_error),
    ('empty slot keeps input', [Not(has_first)], retained_error == new_error),
    ('foreign identity rejected', [has_first, Not(same)], Not(accepted)),
]
for name, premise, conclusion in checks:
    solver = Solver()
    solver.add(*rule, *premise)
    assert solver.check() == sat
    solver.add(Not(conclusion))
    assert solver.check() == unsat
    print(f'{name}: UNSAT; premise nonvacuous')
solver = Solver()
solver.add(has_first, same, old_error != new_error, retained_error == new_error)
assert solver.check() == sat
print('overwrite-first-observation mutation: SAT', solver.model())
