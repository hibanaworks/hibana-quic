# Owned-slot binding at the stream production boundary

The actual source choreography and direct locals now have a finite FIN/abandon
boundary outside the rolled data exchange. The production integration tests use
real projected endpoints and a capacity-one carrier: data reentry, duplicate FIN,
and repeated abandon are rejected after that boundary. Those ordering checks are
Hibana's responsibility, not a replacement state machine in this model.

Hibana messages currently carry correlation values; the owned chunk is transferred
through a private slot. Hibana does not prove that a slot's resource matches its
announced stream. `io.rs` binds the opened handle and compares the complete chunk
handle before admission. `StreamHandle` equality includes connection, slot,
generation and stream ID. The lower table independently validates live handles.

Lean proves matching acceptance, exact identity preservation, and rejection of
wrong generations/connections for this equality gate. Z3 checks every identity
component with a satisfiable acceptance premise and finds a counterexample when
comparison is weakened to stream ID alone. These are scoped models of the explicit
check, not verified compilation of Rust, a proof of the entire slot mailbox, or a
claim that all stream lifecycle control has moved into Hibana. In particular,
lower FIN/RESET/ACK permission fields remain to be replaced.

The two negative/positive runtime tests are in `tests/stream_production.rs` and
measure zero allocations while actual endpoint operations execute. Empty streams,
multiple chunks, rejection and abandonment are included. The connected-application
suite tests the same fragment inside encrypted client/server connections.
