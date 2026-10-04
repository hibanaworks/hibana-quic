# Ticket rejection must fail closed

The migrated async transcript regression first completes and authenticates both
peers, then submits a ticket at the wrong role/level or with malformed fields.
The first migrated run exposed an integration regression: the new ticket-only
`Provider::receive` returned InvalidInput without retiring still-live keys.
`receive` now calls the existing failure/zeroization path at that boundary.
The original exact assertion was retained; separate assertions account for a
failed provider returning Handshake rather than the healthy discarded-key error.

Lean proves three small model facts; Z3 retains a satisfiable old-key-authority
witness and two nonvacuous fail-closed obligations. This is a scoped model, not a
proof that Rust zeroization executes. The actual async regression validates role,
level, malformed ticket fields, provider health and key availability.

Commands: `lean Boundary.lean`, `python boundary.py`, and
`cargo test --manifest-path reference-tls/Cargo.toml --test bounded_tls`.
