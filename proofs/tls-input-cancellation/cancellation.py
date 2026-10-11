from z3 import Bool, Solver, Not, And, If, sat, unsat
slot, loan = Bool('slot'), Bool('loan')
dirty, committed = Bool('dirty'), Bool('committed')
new_slot,new_loan,new_dirty,new_committed = [Bool('after_'+s) for s in ('slot','loan','dirty','committed')]
def prove(name, pre, step, goal):
    s=Solver();s.add(*pre,*step);assert s.check()==sat, name+' vacuous'
    s.add(Not(goal));assert s.check()==unsat,name
    print(name+': unsat; transition preconditions sat')
old_dirty=If(committed,False,dirty)
s=Solver();s.add(loan,Not(slot),dirty,Not(committed),old_dirty)
assert s.check()==sat;print('old_partial_input_retained: sat '+str(s.model()))
pre=[loan,Not(slot)]
step=[new_slot,Not(new_loan),Not(new_dirty),Not(new_committed)]
prove('erasure',pre,step,Not(new_dirty))
prove('unpublished',pre,step,Not(new_committed))
prove('ownership_restored',pre,step,And(new_slot,Not(new_loan)))
prove('exclusive_owner',[slot != loan],[],Not(And(slot,loan)))
# Taking the unique buffer transfers, rather than duplicates, ownership.
prove('take_preserves_partition',[slot,Not(loan)],[Not(new_slot),new_loan],new_slot != new_loan)
