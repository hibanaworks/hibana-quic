"""Scoped integer checks for exact ACK-only run compression; no Rust proof claim."""
from z3 import And, Ints, Or, Solver, If, unsat

a, b, c, d, x, floor = Ints("a b c d x floor")
def member(lo, hi):
    return And(lo <= x, x <= hi)

s = Solver()
s.add(a >= 0, b >= a, c >= 0, d >= c, x >= 0)
s.add(a <= d + 1, c <= b + 1)
s.add(member(If(a < c, a, c), If(b > d, b, d)) != Or(member(a, b), member(c, d)))
assert s.check() == unsat

s = Solver()
s.add(a >= 0, b >= a, floor >= 0, x >= floor)
s.add(member(If(a > floor, a, floor), b) != member(a, b))
assert s.check() == unsat
print("PASS exact run union and retained-floor clipping: 2 UNSAT")
