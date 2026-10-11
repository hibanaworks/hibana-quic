from z3 import Bool, Int, Solver, Not, sat, unsat
claimed, emitted=Bool('claimed'),Bool('emitted')
scope, token_scope=Int('scope'),Int('token_scope')
after, second=Bool('after_claimed'),Bool('second_emission')
step=[emitted==Not(claimed),after,token_scope==scope,second==Not(after)]
for name,goal in [('spent',after),('identity',token_scope==scope),('no_reissue',Not(second))]:
 s=Solver();s.add(*step);assert s.check()==sat
 s.add(Not(goal));assert s.check()==unsat;print(name+': UNSAT; transition nonvacuous')
s=Solver();s.add(Not(claimed),emitted,Not(after),second==Not(after),second);assert s.check()==sat
print('reset-after-constructor-failure mutation: SAT',s.model())
