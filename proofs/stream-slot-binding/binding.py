"""One-shot issuer, exact scope binding, and a numeric-ID-only mutation."""
from z3 import Bool, Ints, Not, Solver, sat, unsat

available, issued, remaining, second = [Bool(name) for name in
                                      ('available', 'issued', 'remaining', 'second')]
table, token_table, handle, token_handle = Ints('table token_table handle token_handle')
step = [issued == available, Not(remaining), second == remaining,
        token_table == table, token_handle == handle]
for name, goal in [('issuer spent', Not(remaining)), ('no reissue', Not(second)),
                   ('exact table', token_table == table), ('exact handle', token_handle == handle)]:
    solver = Solver()
    solver.add(*step, available)
    assert solver.check() == sat
    solver.add(Not(goal))
    assert solver.check() == unsat
    print(f'{name}: UNSAT; successful issue nonvacuous')
other_table, other_handle = Ints('other_table other_handle')
solver = Solver()
solver.add(token_table == other_table, token_table != other_table)
assert solver.check() == unsat
print('actual-table equality rejects a foreign table: UNSAT')
solver = Solver()
solver.add(token_handle == other_handle, token_table != other_table)
assert solver.check() == sat
print('numeric-handle-only admission accepts a foreign table: SAT', solver.model())
# Idempotent registration preserves spent issuance. A new generation is a
# different handle and is outside this same-registration obligation.
registered, incoming = Ints('registered incoming')
after_registration = Bool('after_registration')
solver = Solver()
solver.add(registered == incoming, Not(remaining), after_registration == remaining)
assert solver.check() == sat
solver.add(after_registration)
assert solver.check() == unsat
print('same registration cannot replenish spent issuance: UNSAT; premise nonvacuous')
