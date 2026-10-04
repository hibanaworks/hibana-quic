# Stream storage reclamation

The connected choreography runs source, input and delivery receipt exchanges on
independent `g::par` lanes. Each local actor spells out its send/recv/offer calls.
Those exchanges transfer distinct non-Copy resources. The bounded collector
stores resources by actual table/slot/generation/stream identity; it does not
store an independent stream-phase enum or infer protocol completion from flags.

Joining three matching owned resources and checking retained-chunk arithmetic
produces one `Joined` value. The publication choreography's explicit
ReclaimStream / StreamReclaimed / ReclaimSettled exchange is exclusive with an
unsettled datagram. The adapter consumes Joined before numeric storage reuse.
Late closed-stream frames do not reopen an ID; wrong unidirectional frame
classes still fail. Final-size history is not retained after reclamation (RFC
9000 section 4.5 permits this bounded choice).

Lean and Z3 check only identity matching and zero-retained-storage obligations.
They do not prove Rust pointer identity, all QUIC behavior, or the entire runtime.
Actual endpoint tests check settlement ordering. Encrypted connection tests use
four requests with only two client slots, both clean and with a lost packet.
The existing total request bound remains 16; dynamic MAX_STREAMS credit
replenishment and encrypted peer-STOP interoperability are not qualified here.
