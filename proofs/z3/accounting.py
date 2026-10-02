#!/usr/bin/env python3
"""Independent SMT models for accounting.rs; not Rust source refinement.

Each positive query seeks a violating transition and MUST return unsat. Two
deliberately broken transitions MUST produce counterexamples (sat), so an
inconsistent precondition cannot make the complete suite pass vacuously.
See ../ACCOUNTING-MODEL.md for scope, source mapping, and assumptions.
"""

from typing import NamedTuple

import z3


MAX = (1 << 64) - 1
PROVED = 0
MUTATIONS = 0


def prove(name, assumptions, violation):
    global PROVED
    solver = z3.Solver()
    solver.set(timeout=30_000)
    solver.add(*assumptions)
    # Every proof checks that its preconditions themselves are satisfiable.
    feasible = solver.check()
    if feasible != z3.sat:
        raise AssertionError(f"{name}: preconditions are {feasible}")
    solver.add(violation)
    result = solver.check()
    print(f"{name}: {result} (negated property; preconditions sat)")
    if result != z3.unsat:
        detail = solver.model() if result == z3.sat else solver.reason_unknown()
        raise AssertionError(f"{name}: {result}: {detail}")
    PROVED += 1


def detect_mutation(name, assumptions, violation, witness):
    global MUTATIONS
    solver = z3.Solver()
    solver.set(timeout=30_000)
    solver.add(*assumptions, violation)
    result = solver.check()
    if result != z3.sat:
        raise AssertionError(f"{name}: mutation was not detected: {result}")
    model = solver.model()
    values = ", ".join(f"{key}={model.eval(value)}" for key, value in witness.items())
    print(f"{name}: sat (expected mutation counterexample: {values})")
    MUTATIONS += 1


class Path(NamedTuple):
    received: object
    accepted: object
    reserved: object
    validated: object


def path_inv(p):
    return z3.And(
        0 <= p.received, p.received <= MAX,
        0 <= p.accepted, 0 <= p.reserved,
        p.accepted + p.reserved <= MAX,
        z3.Implies(z3.Not(p.validated), p.accepted + p.reserved <= 3 * p.received),
    )


def reserve(p, amount):
    return p._replace(reserved=p.reserved + amount)


def commit(p, amount):
    return p._replace(accepted=p.accepted + amount, reserved=p.reserved - amount)


def cancel(p, amount):
    return p._replace(reserved=p.reserved - amount)


received, accepted, reserved, amount = z3.Ints("received accepted reserved amount")
validated = z3.Bool("validated")
p = Path(received, accepted, reserved, validated)
base = [path_inv(p), 0 <= amount, amount <= MAX]
limit = z3.If(validated, MAX, z3.If(3 * received > MAX, MAX, 3 * received))
reserve_guard = accepted + reserved + amount <= limit
prove("path_reservation_preserves", base + [reserve_guard], z3.Not(path_inv(reserve(p, amount))))
prove("path_cancel_preserves", base + [amount <= reserved], z3.Not(path_inv(cancel(p, amount))))
prove("path_commit_preserves", base + [amount <= reserved], z3.Not(path_inv(commit(p, amount))))
prove("path_commit_conserves_total", base + [amount <= reserved],
      commit(p, amount).accepted + commit(p, amount).reserved != accepted + reserved)
prove("path_cancel_cannot_refund_accepted", base + [amount <= reserved],
      cancel(p, amount).accepted != accepted)
prove("path_receive_preserves", base + [received + amount <= MAX],
      z3.Not(path_inv(p._replace(received=received + amount))))
prove("path_validation_preserves", base,
      z3.Not(path_inv(p._replace(validated=z3.BoolVal(True)))))


class Ticket(NamedTuple):
    path: Path
    pending: object


def path_choice(condition, yes, no):
    return Path(*(z3.If(condition, a, b) for a, b in zip(yes, no)))


def ticket_commit(ticket):
    return Ticket(path_choice(ticket.pending, commit(ticket.path, amount), ticket.path),
                  z3.BoolVal(False))


def ticket_cancel(ticket):
    return Ticket(path_choice(ticket.pending, cancel(ticket.path, amount), ticket.path),
                  z3.BoolVal(False))


def ticket_different(left, right):
    return z3.Or(left.pending != right.pending,
                 *(a != b for a, b in zip(left.path, right.path)))


pending = z3.Bool("ticket_pending")
other_reserved = z3.Int("other_reserved")
ticket = Ticket(p, pending)


def ticket_inv(t):
    return z3.And(path_inv(t.path), other_reserved >= 0,
                  t.path.reserved == other_reserved + z3.If(t.pending, amount, 0))


ticket_base = [ticket_inv(ticket), 0 <= amount, amount <= MAX]
prove("ticket_commit_preserves", ticket_base, z3.Not(ticket_inv(ticket_commit(ticket))))
prove("ticket_cancel_preserves", ticket_base, z3.Not(ticket_inv(ticket_cancel(ticket))))
prove("ticket_commit_idempotent", ticket_base,
      ticket_different(ticket_commit(ticket_commit(ticket)), ticket_commit(ticket)))
prove("ticket_cancel_idempotent", ticket_base,
      ticket_different(ticket_cancel(ticket_cancel(ticket)), ticket_cancel(ticket)))
prove("accepted_ticket_cannot_cancel", ticket_base,
      ticket_different(ticket_cancel(ticket_commit(ticket)), ticket_commit(ticket)))
prove("cancelled_ticket_cannot_commit", ticket_base,
      ticket_different(ticket_commit(ticket_cancel(ticket)), ticket_cancel(ticket)))


Phase, (RESERVED, SENT, LOST, ACKED, CANCELLED) = z3.EnumSort(
    "Phase", ["RESERVED", "SENT", "LOST", "ACKED", "CANCELLED"]
)


class Recovery(NamedTuple):
    phase: object
    flight: object
    pending: object


phase = z3.Const("phase", Phase)
flight, pending_bytes, other_flight, other_pending, packet_bytes = z3.Ints(
    "flight pending_bytes other_flight other_pending packet_bytes"
)
counts_in_flight = z3.Bool("counts_in_flight")
weight = z3.If(counts_in_flight, packet_bytes, 0)
recovery = Recovery(phase, flight, pending_bytes)


def recovery_inv(s):
    return z3.And(
        other_flight >= 0, other_pending >= 0,
        0 <= packet_bytes, packet_bytes <= MAX,
        s.flight == other_flight + z3.If(s.phase == SENT, weight, 0),
        s.pending == other_pending + z3.If(s.phase == RESERVED, weight, 0),
        s.flight + s.pending <= MAX,
    )


def accept_packet(s):
    allowed = s.phase == RESERVED
    return Recovery(z3.If(allowed, SENT, s.phase),
                    z3.If(allowed, s.flight + weight, s.flight),
                    z3.If(allowed, s.pending - weight, s.pending))


def cancel_packet(s):
    allowed = s.phase == RESERVED
    return Recovery(z3.If(allowed, CANCELLED, s.phase), s.flight,
                    z3.If(allowed, s.pending - weight, s.pending))


def lose_packet(s):
    allowed = s.phase == SENT
    return Recovery(z3.If(allowed, LOST, s.phase),
                    z3.If(allowed, s.flight - weight, s.flight), s.pending)


def ack_packet(s):
    return Recovery(z3.If(z3.Or(s.phase == SENT, s.phase == LOST), ACKED, s.phase),
                    z3.If(s.phase == SENT, s.flight - weight, s.flight), s.pending)


def recovery_different(left, right):
    return z3.Or(*(a != b for a, b in zip(left, right)))


for name, transition in [
    ("accept", accept_packet), ("cancel", cancel_packet),
    ("loss", lose_packet), ("ack", ack_packet),
]:
    prove(f"packet_{name}_preserves", [recovery_inv(recovery)],
          z3.Not(recovery_inv(transition(recovery))))

for name, left, right in [
    ("duplicate_loss_no_effect", lose_packet(lose_packet(recovery)), lose_packet(recovery)),
    ("duplicate_ack_no_effect", ack_packet(ack_packet(recovery)), ack_packet(recovery)),
    ("loss_then_ack_equals_ack", ack_packet(lose_packet(recovery)), ack_packet(recovery)),
    ("ack_then_loss_equals_ack", lose_packet(ack_packet(recovery)), ack_packet(recovery)),
    ("accepted_packet_cannot_cancel", cancel_packet(accept_packet(recovery)), accept_packet(recovery)),
]:
    prove(name, [recovery_inv(recovery)], recovery_different(left, right))

# Machine arithmetic checks: pending bytes share the same checked u64 total
# with accepted/flight bytes. Thus a valid completion cannot overflow or wrap
# either of the un-checked additions/subtractions in the Rust completion path.
actual_bv, pending_bv, amount_bv = z3.BitVecs("actual64 pending64 amount64", 64)
machine_base = [z3.BVAddNoOverflow(actual_bv, pending_bv, False),
                z3.ULE(amount_bv, pending_bv)]
prove("u64_completion_add_cannot_wrap", machine_base,
      z3.Not(z3.BVAddNoOverflow(actual_bv, amount_bv, False)))
prove("u64_completion_subtract_cannot_wrap", machine_base,
      z3.UGT(pending_bv - amount_bv, pending_bv))
prove("u64_completion_conserves_total", machine_base,
      (actual_bv + amount_bv) + (pending_bv - amount_bv) != actual_bv + pending_bv)

# Retained ACK suffixes must not be lost when an ACK starts below the floor.
floor, start, end, number = z3.Ints("floor ack_start ack_end packet_number")
ack_base = [0 <= floor, floor <= (1 << 62), 0 <= start, start <= end,
            end < (1 << 62), floor <= number, number < (1 << 62)]
clamped_start = z3.If(start < floor, floor, start)
original_contains = z3.And(start <= number, number <= end)
clipped_contains = z3.And(end >= floor, clamped_start <= number, number <= end)
prove("retained_ack_suffix_membership", ack_base,
      original_contains != clipped_contains)
prove("wholly_old_ack_has_no_retained_packet", ack_base + [end < floor],
      original_contains)

# Mutation checks are intentionally vulnerable models, not changes to Rust.
detect_mutation(
    "mutation_ignore_other_reservations",
    base + [z3.Not(validated), accepted + amount <= 3 * received,
            accepted + reserved + amount <= MAX, amount > 0],
    z3.Not(path_inv(reserve(p, amount))),
    {"received": received, "accepted": accepted, "reserved": reserved, "new_bytes": amount},
)
detect_mutation(
    "mutation_subtract_again_after_loss",
    [recovery_inv(recovery), phase == LOST, weight > 0, flight >= weight],
    z3.Not(recovery_inv(recovery._replace(flight=flight - weight))),
    {"other_flight": other_flight, "weight": weight, "flight_before_duplicate": flight},
)
detect_mutation(
    "mutation_drop_entire_mixed_old_new_ack",
    ack_base + [start < floor],
    z3.And(original_contains, z3.Not(z3.And(start >= floor, original_contains))),
    {"floor": floor, "start": start, "end": end, "retained_packet": number},
)

print(f"PASS: {PROVED} non-vacuous unsat checks; {MUTATIONS} expected sat mutation checks")
