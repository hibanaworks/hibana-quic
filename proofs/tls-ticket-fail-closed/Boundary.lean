-- Scoped model: synchronous ticket-boundary rejection must revoke key access.
structure Health where
  connected : Bool
  keys : Bool
  deriving DecidableEq

def rejected (_ : Health) : Health := ⟨false, false⟩
def oldRejected (h : Health) : Health := h

theorem rejects_disconnect (h : Health) : (rejected h).connected = false := rfl
theorem rejects_revoke (h : Health) : (rejected h).keys = false := rfl
theorem old_keeps_keys : (oldRejected ⟨true, true⟩).keys = true := rfl
