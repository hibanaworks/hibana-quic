-- Payload arithmetic only. Hibana checks the actual message ordering.
def completedSize (remaining : Nat) (terminalSize : Option Nat) : Option Nat :=
  if remaining = 0 then terminalSize else none

theorem fin_ack_is_not_all_data (remaining size : Nat) (h : remaining ≠ 0) :
    completedSize remaining (some size) = none := by simp [completedSize, h]
theorem no_terminal_no_completion (remaining : Nat) :
    completedSize remaining none = none := by simp [completedSize]
theorem drained_preserves_actual_size (size : Nat) :
    completedSize 0 (some size) = some size := by simp [completedSize]

def sameOwner (actualTable actualStream targetTable targetStream : Nat) : Prop :=
  actualTable = targetTable ∧ actualStream = targetStream

theorem identical_stream_is_not_identical_table (a b stream : Nat) (h : a ≠ b) :
    ¬ sameOwner a stream b stream := by simp [sameOwner, h]
