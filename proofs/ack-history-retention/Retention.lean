import Std

def cutoff (floor discarded : Nat) := max floor (discarded + 1)
def admissible (floor pn : Nat) := floor ≤ pn

theorem cutoff_monotone (floor discarded : Nat) : floor ≤ cutoff floor discarded := by
  exact Nat.le_max_left _ _

theorem discarded_never_readmitted (floor discarded pn : Nat) (h : pn ≤ discarded) :
    ¬ admissible (cutoff floor discarded) pn := by
  unfold admissible cutoff
  omega

theorem largest_remains_admissible (floor discarded largest : Nat)
    (hf : floor ≤ largest) (hd : discarded < largest) :
    admissible (cutoff floor discarded) largest := by
  unfold admissible cutoff
  omega

theorem bounded_ranges (ranges : List Nat) (capacity : Nat) :
    (ranges.take capacity).length ≤ capacity := by
  simp only [List.length_take]
  exact Nat.min_le_left _ _

theorem retained_not_fabricated (ranges : List Nat) (capacity pn : Nat)
    (h : pn ∈ ranges.take capacity) : pn ∈ ranges := by
  exact List.mem_of_mem_take h

 theorem insert_shift_fits (capacity count position : Nat)
     (hc : count < capacity) (hp : position ≤ count) :
     position + 1 + (count - position) ≤ capacity := by
   omega

 theorem merge_shift_fits (capacity count position : Nat)
     (hc : count ≤ capacity) (hp : position < count) :
     position + (count - position - 1) < capacity := by
   omega
