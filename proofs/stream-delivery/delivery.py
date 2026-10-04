"""Scoped payload checks; no model of a parallel QUIC state machine."""
from z3 import And, Bool, Ints, Not, Solver, sat, unsat
remaining, size, table, target, stream, target_stream = Ints('remaining size table target stream target_stream')
terminal, complete = Bool('terminal'), Bool('complete')
rule = [remaining >= 0, size >= 0, complete == And(terminal, remaining == 0)]
for name, premise, conclusion in [
    ('FIN alone is insufficient', [terminal, remaining > 0], Not(complete)),
    ('drained terminal completes', [terminal, remaining == 0], complete),
    ('empty work without terminal is not completion', [Not(terminal), remaining == 0], Not(complete)),
]:
    s = Solver(); s.add(*rule, *premise); assert s.check() == sat
    s.add(Not(conclusion)); assert s.check() == unsat; print(name + ': UNSAT, nonvacuous')
s = Solver(); s.add(table != target, stream == target_stream, And(table == target, stream == target_stream)); assert s.check() == unsat
print('same numeric stream cannot cross actual owner: UNSAT')
s = Solver(); s.add(terminal, remaining > 0, complete == terminal, complete); assert s.check() == sat
print('FIN-only mutation: SAT', s.model())
