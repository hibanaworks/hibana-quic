-- Resource identity/drain obligations; Hibana owns message ordering.
structure Origin where
  table : Nat
  slot : Nat
  generation : Nat
  stream : Nat
  deriving DecidableEq

def reclaimable (source input delivery : Origin) (retained : Nat) : Prop :=
  source = input ∧ source = delivery ∧ retained = 0

theorem retained_storage_prevents_reclaim (s i d : Origin) (n : Nat) (h : n ≠ 0) :
    ¬ reclaimable s i d n := by simp [reclaimable, h]

theorem a_join_preserves_actual_identity (s i d : Origin) (n : Nat)
    (h : reclaimable s i d n) : s = i ∧ i = d := by
  exact ⟨h.1, h.1.symm.trans h.2.1⟩

theorem different_table_cannot_join (s i d : Origin) (n : Nat)
    (h : s.table ≠ i.table) : ¬ reclaimable s i d n := by
  intro hr
  exact h (congrArg Origin.table hr.1)

theorem reused_slot_cannot_accept_old_generation (s i d : Origin) (n : Nat)
    (h : s.generation ≠ i.generation) : ¬ reclaimable s i d n := by
  intro hr
  exact h (congrArg Origin.generation hr.1)
