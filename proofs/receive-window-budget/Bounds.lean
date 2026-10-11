import Std
namespace ReceiveWindowBudget

def window (requests : Nat) : Nat :=
  if requests ≤ 4 then 1048576 else 65536

theorem advertised_credit_is_backed (requests : Nat)
    (positive : 1 ≤ requests) (bounded : requests ≤ 64) :
    requests * window requests ≤ 64 * 65536 := by
  unfold window
  split <;> omega

theorem each_window_is_positive (requests : Nat) : 0 < window requests := by
  unfold window
  split <;> decide
end ReceiveWindowBudget
