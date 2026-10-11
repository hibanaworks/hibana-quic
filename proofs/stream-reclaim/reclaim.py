"""Abstract payload identities, not a second protocol phase machine."""
from z3 import And, Ints, Or, Solver, unsat
source = Ints('s_owner s_slot s_gen s_id')
input_ = Ints('i_owner i_slot i_gen i_id')
delivery = Ints('d_owner d_slot d_gen d_id')
retained, = Ints('retained')
joined = And(*[a == b for a, b in zip(source, input_)],
             *[a == b for a, b in zip(source, delivery)], retained == 0)
for forbidden in [retained > 0, source[0] != input_[0], source[2] != input_[2],
                  source[3] != delivery[3], Or(*[a != b for a,b in zip(input_,delivery)])]:
    s = Solver(); s.add(joined, forbidden)
    assert s.check() == unsat
print('5 resource-identity/drain counterexamples UNSAT')
