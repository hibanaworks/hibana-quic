# Current implementation

Start with [architecture](ARCHITECTURE.md), [guarantee boundaries](GUARANTEES.md),
[qualification](QUALIFICATION.md), and [running HTTP/3](GETTING-STARTED.md).

The old cumulative qualification and reconstruction log is preserved under
[history](history/qualification-through-c586.md). It is not current status.

The current cleanup changes module placement and exposes host IO/buffer
construction. It does not yet provide the planned complete, easy-to-embed
Hibana application transport over network QUIC streams. That is an explicit
remaining deliverable, not something supplied by the internal descriptor carrier.
