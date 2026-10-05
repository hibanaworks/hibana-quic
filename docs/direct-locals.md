# Direct local continuations

The design criterion is a direct local spelling of the Hibana global contract.
Do not replace progression flags with renamed state or communication wrappers.
Numerical/cryptographic/I/O operations may be separate components; they do not
choose a hidden alternative protocol continuation.

## Current prefix rewrite

- Remove `Schedule.stop_timer` and `Schedule.transmit_done`.
- The wire owner explicitly sends StopReceive / receives ReceiveStopped before
  StopTimer / TimerStopped and adapter retirement. The global contract declares both.
- The timer local consumes the stop while clock work is parked, completes any
  already-started expiry exchange, then explicitly retires and acknowledges.
- The receive-stop role is polled independently from the start of TLS input.
  If stop arrives first, the actual stop receipt is retained and the in-flight
  TLS exchange is still completed. It is not abandoned or replaced by a flag.
- Remove the local communication helpers `send`, `transmit_phase`,
  `settle_phase`, `publish_phase`, `publish_result`, `output_before_key`,
  `output_until_connected` and `output`. Concrete send/recv/offer branches are
  written in the TX, UDP and TLS-source local bodies.
- Packet construction/recovery selection is synchronous and contains no
  endpoint operation. Prepared bytes move to existing owned storage before
  the local awaits, keeping large preparation temporaries out of suspended
  role frames.

A capacity-one regression exposed why merely replacing the flag with a send
was insufficient: an unpolled stop role retained the only carrier slot and
blocked the TLS completion needed before that role was started. Starting that
independent receive immediately fixes the scheduling mismatch. Carrier capacity
and protocol success conditions were not relaxed.

The initial expanded candidate also overflowed the default debug-test stack.
A larger stack was used only to diagnose it, not as the accepted fix. Shortening
large packet temporary lifetimes allowed the real connection test to pass again
with the default stack. The temporary expanded-stack run is not qualification.

## Remaining scope

This checkpoint does not certify the entire application layer as fully migrated.
Application source/sink helper composition and cross-role completion readiness
still need the same direct-local review. Do not call the whole migration complete
or infer a Hibana core bug merely from the unfinished consumer rewrite.

## Qualification of the prefix checkpoint

The native forty-file client 0-RTT regression exposed an overly late finite-RX
handoff: keeping finite RX alive through unrelated timer/adapter retirement
could consume post-handshake input before the application receiver owned it.
The global completion sequence now stops and joins finite RX at the recovery
transfer boundary, before those other retirement exchanges. Already-owned
coalesced packet bytes are still processed. No completion flag, arbitrary
delay, larger queue or permanent RX backpressure was added.

Local verification on 2026-10-05: the full core test suite (421 unit tests plus
integration and documentation groups) passed with the default test stack;
selected host library/binary strict Clippy and thumbv6m compilation passed.
The native Neqo diagnostic passed 1999 distinct files in both directions with
real candidate retirement, and client 0-RTT passed forty files with 39 early
packets and both connections retired. These diagnostics are not official
runner verdicts. The new exact-head runner request covers multiplexing,
0-RTT, handshake loss and handshake corruption in both directions.
