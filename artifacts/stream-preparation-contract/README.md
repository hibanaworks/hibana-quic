# Historical evidence for a removed actor implementation

This actor and its obsolete test source have been removed. The original source remains in Git history at b31e4f90e64fe2d6a592aadaf9b390ae50f641c8; these observations do not qualify the current connection.

# Stream preparation contract correction

The frozen production Stream choreography is unchanged: SHA-256 `b268e912106d2897feb2f50b51026df88d9c54e411d99d2dde24bc56b74e5a1b` (191 sends, 95 routes, 10 rolls). No core/vendor source or production label changed.

## Historical assertion and its exact replacement

The former `projected_preparation_cannot_escape_without_owner_settlement_suffix` test asserted that every raw `send::<Inspect>()` must fail after `FramePrepared/ResultTaken`. Its source is available in that Git revision; hashes and historical failure logs are retained under `historical/`.

That label-only assertion conflated two obligations:

1. The current incomplete early-work occurrence must not skip its reservation/completion suffix
2. The real Stream local continuation must not publish an unrelated application command while holding that suffix

The full graph also contains an older, completed bootstrap roll with its own Inspect occurrence. The language permits resetting that older roll. A successful label52 send alone therefore cannot identify which occurrence was taken or establish that the current suffix was discharged.

The finalized source-linked evidence is in `../external-stream-diagnostic/REPORT.md`. Its full 191-event executable checks retain the negatives for current early Inspect88, incomplete early roll6 reset, and zero reservation/completion attempts. They also admit completed bootstrap roll0 reentry through Inspect7 and subsequent real cancellation. The compact `formal/MinimalPreparation.lean` proofs separately establish those distinctions. These artifacts remain evidence of the occurrence-aware obligation; this correction does not replace them with label-only guesses.

## Scoped graph control

`hibana-quic/tests/stream_elastic_reentry.rs` is explicitly a scoped elastic-reentry fixture. It retains the real labels/directions, completed bootstrap roll, current early roll, real result receipts, and one-or-more reservation attempts. It has no production State and makes no full actor or connection claim.

The positive case permits and completes the older Inspect exchange, then still performs CancelPrepared and expects SelectionCancelled. The negative case rejects SelectionCancelled when no reservation/cancellation attempt has occurred. No production label was renamed to make an occurrence distinguishable.

One current-core run compiled in 1.44 seconds. Overall result: **1 passed, 1 failed**. The older Inspect send, receive, result and receipt all completed. The positive case then failed at `owner.offer(CancelPrepared)` with `PhaseInvariant`. The zero-attempt negative passed. The failing offer remains an assertion failure; it was not replaced by typed receive or skipped.

Full measured invocation: 2.00 seconds, peak waited-child RSS 213,216 KiB, no resource guard triggered. See `current/elastic-reentry.log` and `current/elastic-reentry-metrics.json`.

## Actual local continuation security tests

`hibana-quic/src/roles/stream_owner/preparation_boundary.rs` projects the exact production `PrepareFlow<28,29,Prepare>` inside its existing reentry scope. It invokes the actual `client_prepare` and `owner_prepare` functions. The fixture starts at a disclosed component phase entry using real Stream State, real table/send-queue kernels, and an actual Finished-derived AppReady grant. It does not fabricate an admission capability or claim to run the full bootstrap/early choreography.

Four tests cover:

- Ordinary Inspect after a genuine PreparedFrame: service must terminate with UnexpectedCommand before descriptor advancement or Exchange publication; no Inspected result may reach the caller
- The same denial after a genuine Reserve result enters the completion continuation
- Dropping the actually published Inspect request while Prepared and while Reserved: client admission must close and the service must terminate
- A positive Reserved→CancelTransmission→PublicationSettled control, followed by a new genuine preparation and CancelPrepared; retained bytes remain queued and the new preparation identity differs

Negative cases assert unchanged last reply snapshot, empty Exchange/mailboxes, zero packet-authority live effects/packets, real State destruction, and Closed for later reserve/cancel/inspect calls using the retained ID. The observer drops the actual State; it does not implement substitute close logic. The allocator guard surrounds the actual local scope execution after fixture/waker construction.

The positive cancellation token comes from separate cfg(test) Path/Recovery child fixtures. They create actual bounded ledger/path reservations, invoke `datagram::cancel_before_publication`, settle Path and Recovery, and return its affine StreamCancellation. No test constructor creates an accepted boolean or permission token. This is a numerical domain fixture, not network/whole-connection qualification.

The existing stale-cancel component test and other full Stream tests remain intact. Only the overclaimed raw-label test moved out of the full target.

## Verification limit

The four private component tests are **unexecuted**. A metadata-only libtest attempt emitted no source/type errors before entering aggregate const lowering; it was stopped manually on observing that behavior (confirmed exit 130, approximately 45 seconds). Metadata emission did not avoid const lowering. No peak-memory measurement was captured for that attempt. The initial command duplicated Cargo's already supplied `--test` flag and failed immediately; both logs are retained in `current/`.

No repeated aggregate build was launched and no unrelated cfg/test modules were removed. The final allocator/count assertions were added after the stopped metadata attempt and have source evidence only. These tests must run against a legitimate complete test build before the local-boundary obligations can be marked runtime-qualified. Existing full-graph setup failures remain explicit in the preserved evidence and unchanged tests.

## Performance-only vendor rerun

After the parent installed exact published `a9371bea437bbc1f4303ceeb3fc833f605efe730`, the unchanged small target ran once more. Result remains **1 passed, 1 failed** at the same `owner.offer(CancelPrepared)` PhaseInvariant after the older Inspect exchange. Compilation took 10.43 seconds; the measured invocation took 11.02 seconds with 676,532 KiB peak waited-child RSS. No guard fired. This invocation rebuilt the changed core dependency, so timing/RSS is not an isolated before/after performance comparison. The performance-only vendor change supplied no rolled-route correctness repair. Separate binary, log, metrics and hashes are in `a937/`; the old binary and evidence remain intact. No private aggregate test build was repeated.
