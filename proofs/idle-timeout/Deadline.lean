import Std
namespace HibanaQuic.IdleTimeout

def duration (milliseconds pto : Nat) : Nat := max (1000 * milliseconds) (3 * pto)
def deadline (base milliseconds pto : Nat) : Nat := base + duration milliseconds pto

theorem pto_floor (base milliseconds pto : Nat) : base + 3 * pto ≤ deadline base milliseconds pto := by
  simp only [deadline, duration]
  omega

theorem negotiated_floor (base milliseconds pto : Nat) : base + 1000 * milliseconds ≤ deadline base milliseconds pto := by
  simp only [deadline, duration]
  omega

theorem not_before_deadline (now base milliseconds pto : Nat)
    (h : now < deadline base milliseconds pto) : ¬ deadline base milliseconds pto ≤ now := by omega

theorem checked_add_has_no_wrap (base interval limit : Nat)
    (h : base + interval ≤ limit) : base ≤ base + interval ∧ base + interval ≤ limit := by omega

theorem later_probe_cannot_replace_first (first later : Nat) (h : first ≤ later) : min first later = first := by omega

#print axioms pto_floor
#print axioms negotiated_floor
#print axioms not_before_deadline
#print axioms checked_add_has_no_wrap
#print axioms later_probe_cannot_replace_first
end HibanaQuic.IdleTimeout
