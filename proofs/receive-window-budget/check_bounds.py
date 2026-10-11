from z3 import Int, If, Solver, unsat
requests=Int('requests')
window=If(requests<=4,1048576,65536)
s=Solver();s.add(requests>=1,requests<=64,requests*window>64*65536)
assert s.check()==unsat
s=Solver();s.add(requests>=1,requests<=64,window<=0)
assert s.check()==unsat
print('PASS requested-slot credit fits original receive pool: 2 UNSAT')
