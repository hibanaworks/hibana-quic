import Std.Tactic

/-!
Models of the new accounting.rs kernels, not a Rust refinement proof.
See ../ACCOUNTING-MODEL.md for the exact correspondence and assumptions.
No Hibana core theorem or implementation is changed by this model.
-/

namespace HibanaQuic.Accounting

def maxU64 : Nat := 18446744073709551615

structure Path where
  received : Nat
  accepted : Nat
  reserved : Nat
  validated : Bool
  deriving DecidableEq

def PathInv (p : Path) : Prop :=
  p.received ≤ maxU64 ∧ p.accepted + p.reserved ≤ maxU64 ∧
  (p.validated = false → p.accepted + p.reserved ≤ 3 * p.received)

def ReserveAllowed (p : Path) (bytes : Nat) : Prop :=
  p.accepted + p.reserved + bytes ≤ maxU64 ∧
  (p.validated = false → p.accepted + p.reserved + bytes ≤ 3 * p.received)

def reserve (p : Path) (bytes : Nat) : Path :=
  { p with reserved := p.reserved + bytes }

def cancel (p : Path) (bytes : Nat) : Path :=
  { p with reserved := p.reserved - bytes }

def commit (p : Path) (bytes : Nat) : Path :=
  { p with accepted := p.accepted + bytes, reserved := p.reserved - bytes }

def receive (p : Path) (bytes : Nat) : Path :=
  { p with received := p.received + bytes }

def validate (p : Path) : Path := { p with validated := true }

theorem empty_path_valid : PathInv ⟨0, 0, 0, false⟩ := by
  simp [PathInv, maxU64]

theorem reserve_preserves (p : Path) (bytes : Nat)
    (inv : PathInv p) (allowed : ReserveAllowed p bytes) :
    PathInv (reserve p bytes) := by
  rcases inv with ⟨received, _, _⟩
  rcases allowed with ⟨bounded, amp⟩
  simp only [PathInv, reserve]
  constructor
  · exact received
  constructor
  · omega
  · intro unvalidated
    have h := amp unvalidated
    omega

theorem cancellation_preserves (p : Path) (bytes : Nat)
    (inv : PathInv p) (owned : bytes ≤ p.reserved) :
    PathInv (cancel p bytes) := by
  rcases inv with ⟨received, bounded, amp⟩
  simp only [PathInv, cancel]
  constructor
  · exact received
  constructor
  · omega
  · intro unvalidated
    have h := amp unvalidated
    omega

theorem commit_conserves_total (p : Path) (bytes : Nat)
    (owned : bytes ≤ p.reserved) :
    (commit p bytes).accepted + (commit p bytes).reserved =
      p.accepted + p.reserved := by
  simp only [commit]
  omega

theorem commit_preserves (p : Path) (bytes : Nat)
    (inv : PathInv p) (owned : bytes ≤ p.reserved) :
    PathInv (commit p bytes) := by
  rcases inv with ⟨received, bounded, amp⟩
  have conserved := commit_conserves_total p bytes owned
  simp only [PathInv, commit]
  constructor
  · exact received
  constructor
  · omega
  · intro unvalidated
    have h := amp unvalidated
    omega

theorem cancellation_never_refunds_accepted (p : Path) (bytes : Nat) :
    (cancel p bytes).accepted = p.accepted := rfl

theorem receive_preserves (p : Path) (bytes : Nat)
    (inv : PathInv p) (bounded : p.received + bytes ≤ maxU64) :
    PathInv (receive p bytes) := by
  rcases inv with ⟨_, total, amp⟩
  simp only [PathInv, receive]
  constructor
  · exact bounded
  constructor
  · exact total
  · intro unvalidated
    have h := amp unvalidated
    omega

theorem validation_preserves (p : Path) (inv : PathInv p) :
    PathInv (validate p) := by
  rcases inv with ⟨received, total, _⟩
  simp only [PathInv, validate, Bool.true_eq_false, false_implies, and_true]
  exact ⟨received, total⟩

/- One tracked descriptor and the sum of all other pending reservations. The
   pending flag abstracts exact successful lookup in reservations[slot]. -/
structure TicketState where
  path : Path
  pending : Bool
  deriving DecidableEq

def TicketInv (otherPending bytes : Nat) (t : TicketState) : Prop :=
  PathInv t.path ∧
  t.path.reserved = otherPending + (if t.pending then bytes else 0)

def commitTicket (bytes : Nat) (t : TicketState) : TicketState :=
  if t.pending then { path := commit t.path bytes, pending := false } else t

def cancelTicket (bytes : Nat) (t : TicketState) : TicketState :=
  if t.pending then { path := cancel t.path bytes, pending := false } else t

theorem ticket_commit_preserves (otherPending bytes : Nat) (t : TicketState)
    (inv : TicketInv otherPending bytes t) :
    TicketInv otherPending bytes (commitTicket bytes t) := by
  rcases inv with ⟨pathInv, ledger⟩
  cases h : t.pending
  · simpa [commitTicket, TicketInv, h] using And.intro pathInv ledger
  · have owned : bytes ≤ t.path.reserved := by simp [h] at ledger; omega
    have preserved := commit_preserves t.path bytes pathInv owned
    simp only [TicketInv, commitTicket, h, ↓reduceIte]
    constructor
    · exact preserved
    · simp only [commit, Bool.false_eq_true, ↓reduceIte, Nat.add_zero]
      simp [h] at ledger
      omega

theorem ticket_cancel_preserves (otherPending bytes : Nat) (t : TicketState)
    (inv : TicketInv otherPending bytes t) :
    TicketInv otherPending bytes (cancelTicket bytes t) := by
  rcases inv with ⟨pathInv, ledger⟩
  cases h : t.pending
  · simpa [cancelTicket, TicketInv, h] using And.intro pathInv ledger
  · have owned : bytes ≤ t.path.reserved := by simp [h] at ledger; omega
    have preserved := cancellation_preserves t.path bytes pathInv owned
    simp only [TicketInv, cancelTicket, h, ↓reduceIte]
    constructor
    · exact preserved
    · simp only [cancel, Bool.false_eq_true, ↓reduceIte, Nat.add_zero]
      simp [h] at ledger
      omega

theorem duplicate_ticket_commit_no_effect (bytes : Nat) (t : TicketState) :
    commitTicket bytes (commitTicket bytes t) = commitTicket bytes t := by
  cases h : t.pending <;> simp [commitTicket, h]

theorem duplicate_ticket_cancel_no_effect (bytes : Nat) (t : TicketState) :
    cancelTicket bytes (cancelTicket bytes t) = cancelTicket bytes t := by
  cases h : t.pending <;> simp [cancelTicket, h]

theorem accepted_ticket_cannot_refund (bytes : Nat) (t : TicketState) :
    cancelTicket bytes (commitTicket bytes t) = commitTicket bytes t := by
  cases h : t.pending <;> simp [cancelTicket, commitTicket, h]

theorem cancelled_ticket_cannot_commit (bytes : Nat) (t : TicketState) :
    commitTicket bytes (cancelTicket bytes t) = cancelTicket bytes t := by
  cases h : t.pending <;> simp [cancelTicket, commitTicket, h]

inductive Phase where
  | reserved | sent | lost | acknowledged | cancelled
  deriving DecidableEq

structure Recovery where
  phase : Phase
  flight : Nat
  pending : Nat
  deriving DecidableEq

/- `weight` is the record's bytes when in_flight is true, otherwise zero.
   `otherFlight` / `otherPending` are the sums contributed by all other records.
   Error returns are modeled as unchanged states. -/
def RecoveryInv (otherFlight otherPending weight : Nat) (s : Recovery) : Prop :=
  s.flight = otherFlight + (if s.phase = .sent then weight else 0) ∧
  s.pending = otherPending + (if s.phase = .reserved then weight else 0) ∧
  s.flight + s.pending ≤ maxU64

def acceptPacket (weight : Nat) (s : Recovery) : Recovery :=
  match s.phase with
  | .reserved => { phase := .sent, flight := s.flight + weight, pending := s.pending - weight }
  | _ => s

def cancelPacket (weight : Nat) (s : Recovery) : Recovery :=
  match s.phase with
  | .reserved => { s with phase := .cancelled, pending := s.pending - weight }
  | _ => s

def losePacket (weight : Nat) (s : Recovery) : Recovery :=
  match s.phase with
  | .sent => { s with phase := .lost, flight := s.flight - weight }
  | _ => s

def ackPacket (weight : Nat) (s : Recovery) : Recovery :=
  match s.phase with
  | .sent => { s with phase := .acknowledged, flight := s.flight - weight }
  | .lost => { s with phase := .acknowledged }
  | _ => s

theorem acceptance_preserves (otherFlight otherPending weight : Nat) (s : Recovery)
    (inv : RecoveryInv otherFlight otherPending weight s) :
    RecoveryInv otherFlight otherPending weight (acceptPacket weight s) := by
  cases h : s.phase <;> simp_all [acceptPacket, RecoveryInv] <;> omega

theorem packet_cancellation_preserves (otherFlight otherPending weight : Nat) (s : Recovery)
    (inv : RecoveryInv otherFlight otherPending weight s) :
    RecoveryInv otherFlight otherPending weight (cancelPacket weight s) := by
  cases h : s.phase <;> simp_all [cancelPacket, RecoveryInv] <;> omega

theorem loss_preserves (otherFlight otherPending weight : Nat) (s : Recovery)
    (inv : RecoveryInv otherFlight otherPending weight s) :
    RecoveryInv otherFlight otherPending weight (losePacket weight s) := by
  cases h : s.phase <;> simp_all [losePacket, RecoveryInv] <;> omega

theorem ack_preserves (otherFlight otherPending weight : Nat) (s : Recovery)
    (inv : RecoveryInv otherFlight otherPending weight s) :
    RecoveryInv otherFlight otherPending weight (ackPacket weight s) := by
  cases h : s.phase <;> simp_all [ackPacket, RecoveryInv] <;> omega

theorem duplicate_loss_no_effect (weight : Nat) (s : Recovery) :
    losePacket weight (losePacket weight s) = losePacket weight s := by
  cases h : s.phase <;> simp [losePacket, h]

theorem duplicate_ack_no_effect (weight : Nat) (s : Recovery) :
    ackPacket weight (ackPacket weight s) = ackPacket weight s := by
  cases h : s.phase <;> simp [ackPacket, h]

theorem loss_then_ack_equals_ack (weight : Nat) (s : Recovery) :
    ackPacket weight (losePacket weight s) = ackPacket weight s := by
  cases h : s.phase <;> simp [losePacket, ackPacket, h]

theorem ack_then_loss_equals_ack (weight : Nat) (s : Recovery) :
    losePacket weight (ackPacket weight s) = ackPacket weight s := by
  cases h : s.phase <;> simp [losePacket, ackPacket, h]

theorem accepted_packet_cannot_cancel (weight : Nat) (s : Recovery) :
    cancelPacket weight (acceptPacket weight s) = acceptPacket weight s := by
  cases h : s.phase <;> simp [cancelPacket, acceptPacket, h]

/- ACKs can include old, forgotten prefixes. Clamping removes no retained
   packet from a valid range; the retained suffix must still be processed. -/
theorem retained_ack_membership (floor start finish packet : Nat)
    (retained : floor ≤ packet) :
    (max start floor ≤ packet ∧ packet ≤ finish) ↔
      (start ≤ packet ∧ packet ≤ finish) := by
  omega

theorem completely_old_range_has_no_retained_packet (floor start finish packet : Nat)
    (old : finish < floor) (retained : floor ≤ packet) :
    ¬ (start ≤ packet ∧ packet ≤ finish) := by
  omega

#print axioms empty_path_valid
#print axioms reserve_preserves
#print axioms cancellation_preserves
#print axioms commit_conserves_total
#print axioms commit_preserves
#print axioms cancellation_never_refunds_accepted
#print axioms receive_preserves
#print axioms validation_preserves
#print axioms ticket_commit_preserves
#print axioms ticket_cancel_preserves
#print axioms duplicate_ticket_commit_no_effect
#print axioms duplicate_ticket_cancel_no_effect
#print axioms accepted_ticket_cannot_refund
#print axioms cancelled_ticket_cannot_commit
#print axioms acceptance_preserves
#print axioms packet_cancellation_preserves
#print axioms loss_preserves
#print axioms ack_preserves
#print axioms duplicate_loss_no_effect
#print axioms duplicate_ack_no_effect
#print axioms loss_then_ack_equals_ack
#print axioms ack_then_loss_equals_ack
#print axioms accepted_packet_cannot_cancel
#print axioms retained_ack_membership
#print axioms completely_old_range_has_no_retained_packet

end HibanaQuic.Accounting
