import Std

namespace HibanaQuic.OwnedBodyInput

inductive Completion where
  | eof | failed | stopped
  deriving DecidableEq

def grantsNormalFin : Completion → Bool
  | .eof => true
  | .failed | .stopped => false

theorem normal_fin_requires_eof (r : Completion)
    (h : grantsNormalFin r = true) : r = .eof := by
  cases r <;> simp_all [grantsNormalFin]

theorem failure_cannot_be_eof : grantsNormalFin .failed = false := rfl
theorem stopped_cannot_be_eof : grantsNormalFin .stopped = false := rfl

-- Transfer moves one owner, rather than minting another. This is an abstract
-- ownership obligation; Rust moves and the actual-endpoint drop tests provide
-- the implementation correspondence.
theorem transfer_preserves_one_owner (source slot receiver dropped : Nat)
    (owns : source = 1) (unique : source + slot + receiver + dropped = 1) :
    0 + (slot + 1) + receiver + dropped = 1 := by omega

theorem receive_preserves_one_owner (source slot receiver dropped : Nat)
    (owns : slot = 1) (unique : source + slot + receiver + dropped = 1) :
    source + 0 + (receiver + 1) + dropped = 1 := by omega

theorem release_preserves_one_owner (source slot receiver dropped : Nat)
    (owns : receiver = 1) (unique : source + slot + receiver + dropped = 1) :
    source + slot + 0 + (dropped + 1) = 1 := by omega

end HibanaQuic.OwnedBodyInput
