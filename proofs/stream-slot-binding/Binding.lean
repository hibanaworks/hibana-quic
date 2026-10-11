-- Scoped model of the production lease issuer and actual-table admission gate.
-- Message order is enforced separately by the real Hibana source choreography.
structure Identity where
  connection : Nat
  slot : Nat
  generation : Nat
  stream : Nat
  deriving DecidableEq

structure Lease where
  table : Nat
  stream : Identity
  deriving DecidableEq

def claim (table : Nat) (pending : Option Identity) : Option Identity × Option Lease :=
  (none, pending.map fun stream => ⟨table, stream⟩)

theorem exact_stream_and_table (table : Nat) (stream : Identity) :
    (claim table (some stream)).2 = some ⟨table, stream⟩ := rfl

theorem issuance_spent (table : Nat) (pending : Option Identity) :
    (claim table pending).1 = none := rfl

theorem cannot_reissue (table : Nat) (pending : Option Identity) :
    (claim table (claim table pending).1).2 = none := rfl

-- Dropping, abandoning or completing a lease never restores its issuer slot.
-- The Rust lease is neither Copy nor Clone and borrows its table identity.
def admits (table : Nat) (lease : Lease) : Bool := decide (table = lease.table)

theorem wrong_table_rejected (table : Nat) (lease : Lease)
    (h : table ≠ lease.table) : admits table lease = false := by
  simp [admits, h]

theorem admitted_table_matches (table : Nat) (lease : Lease)
    (h : admits table lease = true) : table = lease.table := by
  simpa [admits] using h

-- The registered handle includes connection, slot, generation and stream ID.
def register (current incoming : Identity) (pending : Option Identity) : Option Identity :=
  if current = incoming then pending else some incoming

theorem same_registration_does_not_refill (table : Nat) (stream : Identity)
    (pending : Option Identity) : register stream stream (claim table pending).1 = none := by
  simp [register, claim]
