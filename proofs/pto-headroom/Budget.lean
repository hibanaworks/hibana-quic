import Std

namespace HibanaQuic.PtoHeadroom

theorem ordinary_leaves_recovery_records (ordinary : Nat) (h : ordinary ≤ 48) :
    16 ≤ 64 - ordinary := by omega

theorem each_backed_probe_has_a_slot (ordinary probes : Nat)
    (ho : ordinary ≤ 48) (hp : probes < 16) : ordinary + probes < 64 := by omega

theorem eight_two_packet_rounds_fit (ordinary rounds : Nat)
    (ho : ordinary ≤ 48) (hr : rounds ≤ 8) : ordinary + 2 * rounds ≤ 64 := by omega

theorem full_ledger_cannot_authorize_one_more (used : Nat) (h : used = 64) :
    ¬ used + 1 ≤ 64 := by omega

#print axioms ordinary_leaves_recovery_records
#print axioms each_backed_probe_has_a_slot
#print axioms eight_two_packet_rounds_fit
#print axioms full_ledger_cannot_authorize_one_more
end HibanaQuic.PtoHeadroom
