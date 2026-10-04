-- Owned-observation payload model; publication ordering is checked by Hibana.
structure Identity where
  table : Nat
  connection : Nat
  slot : Nat
  generation : Nat
  stream : Nat
  deriving DecidableEq
structure Observation where
  identity : Identity
  errorCode : Nat
  deriving DecidableEq

def retain (pending : Option Observation) (incoming : Observation) : Except Unit Observation :=
  match pending with
  | none => .ok incoming
  | some first => if first.identity = incoming.identity then .ok first else .error ()

theorem empty_keeps_actual_input (incoming : Observation) :
    retain none incoming = .ok incoming := rfl

theorem repeated_stop_keeps_first (first incoming : Observation)
    (h : first.identity = incoming.identity) : retain (some first) incoming = .ok first := by
  simp [retain, h]

theorem foreign_identity_rejected (first incoming : Observation)
    (h : first.identity ≠ incoming.identity) : retain (some first) incoming = .error () := by
  simp [retain, h]

def cancel (_pending : Option Observation) : Option Observation := none

theorem retirement_does_not_apply (pending : Option Observation) : cancel pending = none := rfl
