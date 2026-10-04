-- One-shot construction model, independent of the packet-arena facade.
structure Installation where
  claimed : Bool
  scope : Nat
  deriving DecidableEq

def claim (i : Installation) : Installation × Option Nat :=
  if i.claimed then (i, none) else (⟨true, i.scope⟩, some i.scope)

theorem actual_scope (id : Nat) : (claim ⟨false,id⟩).2 = some id := rfl
theorem claim_spent (i : Installation) : (claim i).1.claimed = true := by
  cases i with | mk claimed scope => cases claimed <;> rfl

theorem cannot_reissue (i : Installation) : (claim (claim i).1).2 = none := by
  cases i with | mk claimed scope => cases claimed <;> rfl
-- Discard, constructor rejection and success all consume the returned affine
-- Rust token. None of these paths writes the originating installation flag.
