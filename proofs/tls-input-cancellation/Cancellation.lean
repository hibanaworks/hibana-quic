namespace TlsInputCancellation
inductive Location where | slot | loan deriving DecidableEq
structure Buffer where
  location : Location
  dirty : Bool
  committed : Bool
  deriving DecidableEq
-- The old clear used only the committed message length. Partial input had none.
def oldCancel (b : Buffer) : Buffer :=
  if b.committed then {b with dirty := false, committed := false} else b
def loanReturn (b : Buffer) : Buffer :=
  {location := .slot, dirty := false, committed := false}
def beginRead (b : Buffer) : Buffer := {b with location := .loan}
def partialRead (b : Buffer) : Buffer := {b with dirty := true}
theorem partial_old_retained :
  (oldCancel {location := .loan, dirty := true, committed := false}).dirty = true := rfl
theorem cancelled_partial_erased (b : Buffer) :
  (loanReturn (partialRead (beginRead b))).dirty = false := rfl
theorem cancelled_input_unpublished (b : Buffer) :
  (loanReturn b).committed = false := rfl
theorem returned_to_slot (b : Buffer) :
  (loanReturn b).location = .slot := rfl
theorem return_idempotent (b : Buffer) : loanReturn (loanReturn b) = loanReturn b := rfl
#print axioms partial_old_retained
#print axioms cancelled_partial_erased
#print axioms cancelled_input_unpublished
#print axioms returned_to_slot
#print axioms return_idempotent
end TlsInputCancellation
