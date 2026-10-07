# Guarantee boundaries

Hibana globals and projected endpoints own communication order, choices,
parallel role coordination and explicit joins. Direct locals perform the real
operations and exchange their actual receipts. A standalone phase enum,
completion flag or opaque communication helper is not a substitute.

Rust ownership and private capabilities prevent copying/moving resources outside
the intended owners. Physical adapters must report actual acceptance and failure;
Hibana cannot automatically prove arbitrary Rust side effects or hardware behavior.

Pure parsers, bounds, packet-number arithmetic, quotas and cryptographic kernels
remain ordinary code. Scoped Lean/Z3 models are appropriate for mathematical
obligations outside projection, with feasible assumptions and negative controls.
They are not a claim that the Rust implementation or external crypto is proved.

Stored facts such as authenticated ACK history, a remaining numeric quota,
actual peer settings or observed failure must be distinguished from duplicated
protocol-progress control. Audit the latter against each global; don't erase
necessary wire/accounting evidence merely to remove every boolean.

`Accepted` is not peer application completion. QUIC ACK is not an application
reply. Failure/cancellation paths retain their own results and retire actual
owned effects before joins. No mock outcome substitutes for a physical receipt.
