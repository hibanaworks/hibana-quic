from z3 import Bool, Solver, Not, sat, unsat
connected, keys = Bool('connected'), Bool('keys')
s=Solver();s.add(connected,keys);assert s.check()==sat
print('old rejection retains connected key authority: SAT',s.model())
after_connected,after_keys=Bool('after_connected'),Bool('after_keys')
for name,goal in [('disconnected',Not(after_connected)),('revoked',Not(after_keys))]:
 s=Solver();s.add(Not(after_connected),Not(after_keys));assert s.check()==sat
 s.add(Not(goal));assert s.check()==unsat;print(name+': UNSAT; transition nonvacuous')
