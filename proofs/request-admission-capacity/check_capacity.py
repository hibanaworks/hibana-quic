from z3 import Ints, Solver, unsat, sat
queued,producing,active,slots=Ints('queued producing active slots')
s=Solver();s.add(queued>=0,producing>=1,active>=0,slots<=64,
    queued+producing+active<=slots,queued>=64);assert s.check()==unsat
s=Solver();s.add(queued==8,producing==1,active==1,slots==40,
    queued+producing+active<=slots,queued>=8);assert s.check()==sat
print('PASS slot-backed request capacity UNSAT; old eight-entry blockage SAT')
