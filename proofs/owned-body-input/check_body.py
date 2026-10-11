#!/usr/bin/env python3
"""One input invocation: affine moves and EOF-only normal completion."""
from z3 import Bools, If, And, Or, Not, Solver, unsat, sat
s, q, r, dropped, eof, bad, accepted, fin = Bools('s q r dropped eof bad accepted fin')
state = [s, q, r, dropped, eof, bad, accepted, fin]
def inv(v):
    a,b,c,d,e,f,g,h = v
    return And(sum(If(x, 1, 0) for x in [a,b,c,d]) == 1,
               Not(And(e,f)), Or(Not(g), And(d,e,Not(f))), Or(Not(h), And(g,e,d)))
def changed(**kw):
    names = ['s','q','r','dropped','eof','bad','accepted','fin']
    return [kw.get(n, x) for n,x in zip(names,state)]
steps = [
    (s, changed(s=False,q=True)),
    (q, changed(q=False,r=True)),
    (And(r,Not(eof),Not(bad)), state),
    (And(r,Not(eof),Not(bad)), changed(eof=True)),
    (And(r,Not(eof),Not(bad)), changed(bad=True)),
    (And(r,Or(eof,bad)), changed(r=False,dropped=True)),
    (And(dropped,eof,Not(bad)), changed(accepted=True)),
    (accepted, changed(fin=True)),
]
solver=Solver();solver.add(Not(inv([True,False,False,False,False,False,False,False])))
assert solver.check()==unsat
for guard,nxt in steps:
    solver=Solver();solver.add(inv(state),guard,Not(inv(nxt)))
    assert solver.check()==unsat
# Omitting the actual ownership move permits duplication.
solver=Solver();solver.add(inv(state),s,Not(inv(changed(q=True))))
assert solver.check()==sat
# Transport acceptance is insufficient to fabricate a normal EOF result.
solver=Solver();solver.add(inv(state),q,Not(inv(changed(accepted=True))))
assert solver.check()==sat
print('PASS initial + 8 inductive UNSAT obligations; 2 SAT missing-premise witnesses')
