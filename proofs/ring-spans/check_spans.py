#!/usr/bin/env python3
"""Scoped index and bulk-overlap equivalence obligations; no network assumptions."""
from z3 import And, Bool, BitVec, If, Ints, Not, Or, Solver, unsat

c, h, r, n = Ints('capacity head relative delta')
def index(head, relative):
    return If(relative < c - head, head + relative, relative - (c - head))
s = Solver()
s.add(c > 0, h >= 0, h < c, r >= 0, n >= 0, r+n < c,
      index(h, r+n) != index(index(h, r), n))
assert s.check() == unsat

flags = [Bool(f'p{i}') for i in range(32)]
old = [BitVec(f'o{i}', 8) for i in range(32)]
new = [BitVec(f'n{i}', 8) for i in range(32)]
conflict = Or(*[And(p, a != b) for p, a, b in zip(flags, old, new)])
bulk_conflict = And(Or(*flags), Or(*[a != b for a, b in zip(old, new)]), conflict)
s = Solver(); s.add(conflict != bulk_conflict)
assert s.check() == unsat
# Two spans must both validate before any write; failure is not partial success.
first_ok, second_ok, changed = Bool('first_ok'), Bool('second_ok'), Bool('changed')
s = Solver(); s.add(changed == And(first_ok, second_ok), Not(second_ok), changed)
assert s.check() == unsat
print('PASS circular-index, bulk-overlap and validate-before-write obligations (3 UNSAT)')
