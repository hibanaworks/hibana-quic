# Early-data qualification boundary

The current direct connection does not implement an end-to-end 0-RTT stream
workflow. The standalone legacy early-send journal and deferred control store,
including their private state machines and stream-import entry points, have been
deleted. They were not connected to the current endpoint.

The bounded TLS provider still has tested early-data cryptographic negotiation,
ticket handling and rejection behavior. The asynchronous reference suites test
those TLS boundaries. This is not evidence that the current host sends, receives,
quarantines, or replays 0-RTT application streams correctly.

A future implementation must express acceptance/rejection, Finished-gated release,
and replay ownership in Hibana global choreography and its direct async locals.
Do not restore the deleted journal/phase dispatcher as a compatibility path.
The official `zerortt` cells remain unrun; see [qualification](../interop/qualification.json).
