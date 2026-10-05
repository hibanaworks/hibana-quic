import Std
namespace HibanaQuic.HandshakeAckDelay

def adjusted (latest minimum delay : Nat) : Nat :=
  if minimum + delay ≤ latest then latest - delay else latest

theorem adjustment_respects_minimum (latest minimum delay : Nat)
    (h : minimum ≤ latest) : minimum ≤ adjusted latest minimum delay := by
  simp only [adjusted]
  split <;> omega

theorem buffered_delay_is_removed (path delay minimum : Nat)
    (h : minimum ≤ path) : adjusted (path + delay) minimum delay = path := by
  simp only [adjusted]
  split <;> omega

theorem impossible_delay_cannot_reduce_sample (latest minimum delay : Nat)
    (h : latest < minimum + delay) : adjusted latest minimum delay = latest := by
  simp only [adjusted]
  split <;> omega

theorem confirmed_delay_is_bounded (reported maximum : Nat) :
    min reported maximum ≤ maximum := by omega

#print axioms adjustment_respects_minimum
#print axioms buffered_delay_is_removed
#print axioms impossible_delay_cannot_reduce_sample
#print axioms confirmed_delay_is_bounded
end HibanaQuic.HandshakeAckDelay
