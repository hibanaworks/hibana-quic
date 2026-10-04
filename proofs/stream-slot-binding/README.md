# One-shot stream production and the actual-table boundary

The source choreography has a finite FIN/abandon outside its rolled data exchange.
Real projected endpoints reject data reentry, repeated FIN and repeated abandon
after that boundary. The lower `send_final` permission field has been deleted.

A non-Copy, non-Clone `Production` lease is issued once per registered live stream.
It borrows the actual table identity and moves through `SourceOpen`'s private slot
to ingress. Ingress retains it for exactly this finite production fragment.
Ordinary chunks cannot name a stream anymore. The source cannot acquire another
lease for the same registration after FIN or abandonment; a repeated registration
of the same handle does not replenish issuance. Numeric queue admission requires
the lease and actual-table pointer equality. A copied numeric StreamHandle alone
is no longer a public queue-enqueue authority. Retransmission keeps independent
retained chunk/packet references and does not consume another production lease.

Hibana establishes message order; Rust borrowing/affinity and the explicit issuer
and table-identity checks establish the resource binding. Neither correlation IDs
nor a private slot automatically acquire this guarantee from Hibana alone.

Lean proves exact issuance, spent issuance, non-reissuance, and actual-table
admission. Z3 checks the corresponding obligations with a satisfiable issuance
premise, and finds a foreign-table counterexample when the equality gate is
weakened to numeric handles. These are scoped models, not verified compilation,
complete mailbox verification, or a proof of the whole stream lifecycle.

Actual Rust tests check non-reissuance after drop and repeated registration, and
reject a lease from a different table with identical numeric handles. The tests
measure zero allocations. `tests/stream_production.rs` checks real endpoint order;
the eight connected-application cases include encrypted empty and multi-chunk
responses and loss. RESET/ACK control migration is still unfinished.
