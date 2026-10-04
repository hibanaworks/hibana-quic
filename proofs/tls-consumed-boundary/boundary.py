from z3 import Ints,Solver,Not,sat,unsat
n,e=Ints('verified_consumed end_offset')
s=Solver();s.add(n>0,e>0,e<=n,Not(e<=0));assert s.check()==sat
print('lost_verified_watermark: sat',s.model())
for name,pre,goal in [('duplicate',[n>=0,e>=0,e<=n],e<=n),('new_input',[n>=0,e>n],Not(e<=n))]:
 s=Solver();s.add(*pre);assert s.check()==sat;s.add(Not(goal));assert s.check()==unsat;print(name+': unsat; preconditions sat')
