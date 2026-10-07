#!/usr/bin/env python3
"""Abstract arithmetic of one two-datagram PTO allowance, not Rust refinement."""
import z3
c, r, a = z3.Ints('available reserved accepted')
inv = z3.And(c >= 0, r >= 0, a >= 0, c + r + a == 2)

def check(name, assumptions, violation, expected=z3.unsat):
    s = z3.Solver()
    s.set(timeout=10000)
    s.add(*assumptions)
    assert s.check() == z3.sat, name + ': infeasible preconditions'
    s.add(violation)
    result = s.check()
    assert result == expected, (name, result)
    print(name + ': ' + str(result))

def conserved(x, y, z):
    return z3.And(x >= 0, y >= 0, z >= 0, x + y + z == 2)

check('reserve_conserves_allowance', [inv, c > 0], z3.Not(conserved(c-1, r+1, a)))
check('accepted_conserves_allowance', [inv, r > 0], z3.Not(conserved(c, r-1, a+1)))
check('cancel_conserves_allowance', [inv, r > 0], z3.Not(conserved(c+1, r-1, a)))
check('no_third_accepted_probe', [inv], a > 2)
# The production selector changes only existing probe_space/probe_minimum,
# after real Handshake acceptance, when no publication remains pending.
check('second_space_keeps_exactly_one_credit', [inv, c == 1, r == 0], a != 1)
old_epoch, current_epoch = z3.Ints('old_epoch current_epoch')
refund = z3.If(old_epoch == current_epoch, 1, 0)
check('stale_cancel_cannot_refund_new_epoch', [old_epoch >= 0, current_epoch > old_epoch], refund != 0)
check('mutant_space_switch_mints_credit', [inv, c == 1, r == 0],
      z3.Not(conserved(c+1, r, a)), z3.sat)
check('mutant_cancel_refunds_accepted_probe', [inv, a > 0],
      z3.Not(conserved(c+1, r, a)), z3.sat)
print('6 safety queries UNSAT; 2 deliberate mutations SAT')
