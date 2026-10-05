import Std
namespace AckHistory

def member (lo hi x : Nat) : Prop := lo ≤ x ∧ x ≤ hi

theorem adjacent_union (a b c d x : Nat) (_ab : a ≤ b) (_cd : c ≤ d)
    (left : a ≤ d + 1) (right : c ≤ b + 1) :
    member (min a c) (max b d) x ↔ member a b x ∨ member c d x := by
  unfold member
  omega

theorem clipping_preserves_retained_members (a b floor x : Nat) (kept : floor ≤ x) :
    member (max a floor) b x ↔ member a b x := by
  unfold member
  omega

theorem disjoint_evidence_preserves_validation (live old compressed : Nat → Prop)
    (exact : ∀ pn, old pn ↔ compressed pn) (pn : Nat) :
    (live pn ∨ old pn) ↔ (live pn ∨ compressed pn) := by
  rw [exact pn]
end AckHistory
