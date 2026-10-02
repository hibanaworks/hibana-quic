# Accounting kernel evidence and refinement boundary

## Status

These are models of the new `src/accounting.rs` implementation. They are **not
source-level Rust refinement proofs**, complete QUIC proofs, or changes to Hibana
core. The model files are `lean/Accounting.lean` and `z3/accounting.py`.

The verified run and exact source hashes are recorded in
`../artifacts/accounting-kernels/verification.log`:

- Lean 4.30.0 checks 25 theorems, with no `sorry` or custom axioms. Its printed
  axiom audit uses the standard Lean axioms `propext`, `Quot.sound`, and, for the
  maximum/range lemma, `Classical.choice`.
- Z3 5.1.0 reports UNSAT for 27 negated properties. Every query separately
  requires satisfiable preconditions; `unknown`, timeout, or an unsatisfiable
  precondition fails the script.
- Three deliberately faulty models produce expected SAT counterexamples:
  ignoring outstanding amplification reservations, subtracting a lost packet
  twice, and dropping an entire ACK when only its prefix was forgotten. These
  mutations are confined to the proof script and are not applied to Rust.
- Direct Rust tests cover 20 accounting and 5 storage cases. Two cases exhaust
  all 4,096 length-six event sequences over their respective four operations.
- A wrapper containing only these two modules compiles for host and
  `thumbv6m-none-eabi` with `#![no_std]`, `#![forbid(unsafe_code)]`, and warnings
  denied. This is not a completed-firmware link or a whole-project allocation
  audit.

## Path correspondence

| Model | Rust location or field | Meaning |
|---|---|---|
| `Path.received` | `PathBudget.received` | Credited UDP datagram bytes on one path |
| `Path.accepted` | `PathBudget.accepted` | Irreversible adapter-accepted datagram bytes |
| `Path.reserved` | `PathBudget.reserved` | Sum of all still-pending reservations |
| `Path.validated` | `PathBudget.validated` | Result supplied by the address-validation owner |
| `reserve` | `PathBudget::reserve` successful branch | Add the new datagram size to pending bytes |
| `cancel` | `PathBudget::cancel` after exact handle lookup | Subtract only pending bytes; accepted is unchanged |
| `commit` | `PathBudget::adapter_accepted` | Move bytes from pending to accepted |
| `receive` | `PathBudget::record_received` | Add credited input subject to checked u64 addition |
| `validate` | `PathBudget::mark_validated` | Remove the amplification limit, retaining u64 bounds |
| `TicketState.pending` | Exact live reservation at `reservations[slot]` | One tracked descriptor is still eligible for completion |

`PathInv` states that received bytes fit in u64, accepted plus reserved bytes fit
in u64, and an unvalidated path's accepted plus reserved bytes are at most three
times received bytes. Lean proves preservation by actual state updates,
including subtraction and transfer of pending credit. Commit conserves the
combined total. Cancellation never refunds accepted bytes.

The Rust reserve guard uses `received.saturating_mul(3)`. The Lean representation
uses mathematical `3 * received` together with an independent u64 total bound;
the two conditions together equal a `min(u64::MAX, 3 * received)` bound. Z3
explicitly encodes that minimum. Saturation is conservative when received bytes
exceed `u64::MAX / 3`; it does not grant extra credit.

`TicketInv` also states that pending bytes equal the other reservations' sum plus
the tracked descriptor's bytes if that descriptor is live. Both models prove
successful commit/cancel consumes eligibility, repetitions have no effect, a
committed descriptor cannot subsequently refund credit, and a cancelled
descriptor cannot subsequently commit it.

The descriptor abstraction assumes exact lookup implements the pending flag.
The models do not establish the concrete array traversal, tuple comparisons,
serial/generation uniqueness, or equality of the array sum and numeric counter.
Those are implementation obligations exercised by unit tests, not proved by
these abstractions.

## Sent-packet correspondence

| Model | Rust location or field | Meaning |
|---|---|---|
| `Phase` | `PacketState` | Reserved, Sent, Lost, Acknowledged, Cancelled |
| `Recovery.flight` | `SentLedger.bytes_in_flight` | Aggregate bytes currently in flight |
| `Recovery.pending` | `SentLedger.reserved_in_flight` | Aggregate in-flight bytes reserved for future acceptance |
| `weight` | `if record.in_flight { record.bytes } else { 0 }` | One packet's congestion-accounted size |
| `otherFlight` / `otherPending` | Sums of contributions from all other records | Fixed during the modeled single-record update |
| `acceptPacket` | `SentLedger::adapter_accepted` | Reserved → Sent, with pending → flight transfer |
| `cancelPacket` | `SentLedger::cancel` | Reserved → Cancelled; other phases unchanged on error |
| `losePacket` | `SentLedger::declare_lost` | Sent → Lost with exactly one flight subtraction |
| `ackPacket` | Per-record transition in `SentLedger::acknowledge` | Sent → Acknowledged with subtraction; Lost → Acknowledged without subtraction |

`RecoveryInv` specifies the exact contribution of the tracked packet in every
phase and bounds combined flight plus pending bytes by u64::MAX. Each transition
preserves that invariant. The models prove:

- Duplicate loss and duplicate ACK leave counters and packet state unchanged
- Loss followed by ACK reaches the same accounting state as ACK directly
- ACK followed by loss reaches the same accounting state as ACK directly
- Cancellation after adapter acceptance has no effect

Lean uses natural numbers and models rejected operations as unchanged states.
Z3 uses integer state models, including nonnegative counters and u64 bounds, and
adds independent unsigned 64-bit bit-vector checks that successful completion's
unchecked add/subtract cannot wrap under the reserve/ownership premises.
Rust's actual `Err` versus `AlreadyHandled` return values are not represented by
the state-only model. In particular, a model no-op is not a successful operation
claim.

The ACK loop batches multiple per-record transitions and subtracts their sum
once. The abstract single-record proof supports the intended decomposition but
does not prove that implementation loop, aggregate sum, exact record matching,
or frame-wide atomic prevalidation correct. Tests explicitly cover invalid
ranges, cancelled/never-sent numbers, duplicate ranges, enormous numeric ranges,
and a later invalid range preventing all earlier accounting changes.

## Forgotten ACK prefixes

`SentLedger::forget_before` reclaims terminal records only. `acknowledge` ignores
wholly old ranges and validates the suffix beginning at `max(start, floor)` for
a crossing range. It does not require the caller to inspect an inaccessible
floor or discard the entire ACK frame.

Lean and Z3 prove clipping preserves membership for every packet at or above
the floor, and a wholly old range contains no retained packet. The Rust
regression `mixed_old_and_new_ack_processes_retained_suffix_atomically` verifies
that `[0, 1]` acknowledges sent PN 1 after PN 0 is reclaimed. Adding cancelled
PN 2 or never-allocated PN 3 rejects the frame without removing PN 1's bytes.
ACKed old numbers are ignored rather than certified as previously sent; their
sent/cancelled history is no longer known. `HistoryUnavailable` remains a local
status for explicit loss queries below the floor and is not peer misconduct.

`reclaim_completed_prefix(space)` additionally provides automatic reclamation
based only on local history. It scans a contiguous prefix and stops at any
Reserved record, in-flight Sent record, or missing PN. It may reclaim Sent
non-in-flight records only because the caller's classification means accepted
ACK-only/non-retransmittable contents without an outstanding packet-level
delivery obligation. It returns the new exclusive floor and never resets the
allocator. An old outstanding data packet therefore prevents reclamation of
all later records, even if those later records have completed. Capacity pressure
in that situation remains honest backpressure.

The models do not prove `forget_before` or `reclaim_completed_prefix` array
reclamation or their guards. Runtime tests cover pending-data blocking,
space-isolated reclamation, retirement failure atomicity, and 128 locally
cancelled plus 128 accepted ACK-only sends through a one-slot ledger with
strictly increasing PNs. The manual `forget_before` remains conservative and
rejects every Sent record; automatic reclamation additionally recognizes the
accepted non-in-flight case described above.

## Assumptions and excluded claims

1. One owner mutates each ledger sequentially. No public numeric fields can
   directly mutate Rust's private record state.
2. Caller-issued connection/path/pool generations are not reused while stale
   descriptors can arrive. The no-wrap runtime checks and generation-tagged
   storage API are tested but not formally modeled here.
3. ACK input has passed packet authentication and correct packet-number-space
   selection. Both 0-RTT and 1-RTT use the same Application Data allocator.
   Authentication, TLS, PN allocation, key lifecycle, and Retry processing are
   outside these formal models.
4. The caller classifies in-flight packets correctly, credits received bytes to
   the correct path, and supplies truthful irreversible adapter acceptance.
   An application future's cancellation does not establish adapter rejection.
5. Path validation is a protocol fact supplied by the path owner. These models
   do not validate PATH_CHALLENGE/RESPONSE, tokens, peer addresses, or migration.
6. Capacity/identity validation failures leave Rust state unchanged. Capacity
   selection, history reclamation, and stale-completion lookup are not source
   refinement proved.
7. Packet loss does not release stream retransmission buffers. Stream ownership,
   congestion control, RTT/PTO/loss detection, ECN, wire parsing, liveness,
   network reliability, and full QUIC correctness are outside this evidence.
8. `src/storage.rs` is covered by its runtime tests and target compilation only;
   no formal claim about that concrete pool follows from the accounting models.

## Reproduction

From the `hibana-quic` directory, using an installed Lean 4.30.0 and a Python
environment with z3-solver 5.1.0:

```sh
lean -DwarningAsError=true proofs/lean/Accounting.lean
python proofs/z3/accounting.py
rustc --edition 2024 --test -D warnings src/accounting.rs -o /tmp/accounting-tests
/tmp/accounting-tests
rustc --edition 2024 --test -D warnings src/storage.rs -o /tmp/storage-tests
/tmp/storage-tests
```

Every command must exit zero. The evidence log records the exact commands and
available tool locations used in this environment. No unavailable tool or
skipped test is counted as a pass.
