namespace TlsConsumedBoundary
def admitted (verifiedConsumed endOffset : Nat) : Prop := endOffset ≤ verifiedConsumed
theorem verified_duplicate (n e : Nat) (h:e≤n) : admitted n e := h
theorem new_input_rejected (n e : Nat) (h:n<e) : ¬ admitted n e := Nat.not_le_of_gt h
theorem zero_floor_loses_verified_input : admitted 100 50 ∧ ¬ admitted 0 50 := by decide
#print axioms verified_duplicate
#print axioms new_input_rejected
#print axioms zero_floor_loses_verified_input
end TlsConsumedBoundary
