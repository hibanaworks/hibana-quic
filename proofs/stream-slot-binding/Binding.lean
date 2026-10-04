-- Boundary model only: Hibana governs message order; Rust equality binds the
-- private owned slot to the stream opened by this production fragment.
structure Identity where
  connection : Nat
  slot : Nat
  generation : Nat
  stream : Nat
  deriving DecidableEq

def admit (opened chunk : Identity) : Option Identity :=
  if opened = chunk then some chunk else none

theorem matching_admitted (opened : Identity) : admit opened opened = some opened := by
  simp [admit]

theorem admitted_is_opened (opened chunk actual : Identity)
    (h : admit opened chunk = some actual) : actual = opened := by
  unfold admit at h
  split at h
  next same => cases same; cases h; rfl
  next _ => contradiction

theorem wrong_generation_rejected (opened chunk : Identity)
    (h : opened.generation ≠ chunk.generation) : admit opened chunk = none := by
  have different : opened ≠ chunk := by
    intro same
    exact h (congrArg Identity.generation same)
  simp [admit, different]

theorem wrong_connection_rejected (opened chunk : Identity)
    (h : opened.connection ≠ chunk.connection) : admit opened chunk = none := by
  have different : opened ≠ chunk := by
    intro same
    exact h (congrArg Identity.connection same)
  simp [admit, different]
