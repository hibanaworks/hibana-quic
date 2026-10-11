from z3 import Int, Solver, If, And, Or, Not, sat, unsat


def prove(name, assumptions, goal):
    solver = Solver()
    solver.add(*assumptions)
    assert solver.check() == sat, name + ' vacuous'
    solver.add(Not(goal))
    assert solver.check() == unsat, name
    print(name + ': UNSAT; preconditions SAT')


floor, dropped, pn, largest = [Int(x) for x in ('floor', 'dropped', 'pn', 'largest')]
after = If(floor > dropped + 1, floor, dropped + 1)
pre = [floor >= 0, dropped >= 0, largest > dropped, floor <= largest, largest < 2**62]
prove('monotone cutoff', pre, after >= floor)
prove('discarded never readmitted', pre + [pn >= 0, pn <= dropped], pn < after)
prove('largest retained', pre, largest >= after)
# Merging overlapping/adjacent authenticated ranges cannot create an ACK hole.
a, b, c, d, x = [Int(v) for v in ('a', 'b', 'c', 'd', 'x')]
lo, hi = If(a < c, a, c), If(b > d, b, d)
prove('merge never fabricates receipt', [0 <= a, a <= b, 0 <= c, c <= d,
       a <= d + 1, c <= b + 1, lo <= x, x <= hi],
      Or(And(a <= x, x <= b), And(c <= x, x <= d)))
# The retained range bound is fixed, including a newly inserted disjoint packet.
count = Int('count')
kept = If(count > 32, 32, count)
prove('range count bounded', [count >= 0, count <= 33], And(kept >= 0, kept <= 32))
s = Solver()
s.add(floor == 0, dropped == 62, pn == dropped, pn >= floor)
assert s.check() == sat
print('prune without raising cutoff permits replay: SAT', s.model())

# In-place insertion shifts only retained rows; a full array first retires one.
n, position, capacity = [Int(v) for v in ('n', 'position', 'capacity')]
prove('in-place insertion destination is bounded',
      [capacity > 0, 0 <= n, n < capacity, 0 <= position, position <= n],
      And(position + 1 + (n - position) <= capacity, n - position >= 0))
prove('bridge merge shift is bounded',
      [capacity > 0, 2 <= n, n <= capacity, 1 <= position, position < n],
      And(position + (n - position - 1) < capacity, n - position - 1 >= 0))
prove('packet successor fits u64', [pn >= 0, pn <= 2**62 - 1], pn + 1 < 2**64)
