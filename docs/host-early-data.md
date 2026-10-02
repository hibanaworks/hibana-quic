# Explicit early GET workflow

The development HQ adapter has an opt-in two-connection early-data profile. The first connection authenticates the certificate, transfers one file, receives an authenticated ticket and closes. The next connection uses a fresh generation and can send up to four caller-authorized complete HTTP/0.9 GET requests before Finished. This is a bounded host workflow, not a general HTTP/3 service or the complete external interoperability runner.

Ordinary HQ mode remains disabled for early data and keeps its original limits. The early-capable server profile advertises four bidirectional request streams, 1024 bytes of initial credit per request and 4096 bytes of aggregate request credit. Its ordinary receive storage remains 4096 bytes per stream. The ticket binds this profile; changing it requires a full authenticated fallback under the current exact binding policy.

## Caller policy

Client `--early-data replay-safe-get` explicitly authorizes both sending the selected GET requests early and resending those same owned request bytes under new authenticated limits if early data is rejected. A GET method by itself is not a replay-safety guarantee: callers must choose requests for which that authorization is appropriate. The adapter serves static files and implements no arbitrary early application callback.

The flag requires `--connections 2`. Optional `--expect-early accepted|rejected|either` defaults to `either`; it never invents an acceptance result. An accepted expectation requires verified TLS acceptance and actual early packet output. Missing or expired cached tickets do not silently become early success.

Server `--early-data buffered-get` requires `--max-connections 2` and an explicit `--early-age-skew-ms` value from 0 through 60000. This is separate from ordinary resumption's `--ticket-age-skew-ms` setting. The server retains one fresh random ticket key and a bounded, nonrefundable early replay ledger across both connection lifetimes. `--reject-early-second true` tests rejection without changing the ticket or transport profile.

The server retains authenticated early bytes in caller-owned quarantine until verified Finished and typed release authority. Client intent stays in the early journal until checked ordinary stream import. The host then adopts those exact stream IDs; it does not open replacement requests alongside retained intent. Download files are created only after the authenticated handshake/import boundary.

## Example

Use an isolated certificate/key and an explicit CA file. The binary paths below are supplied by the caller; test evidence uses copied binaries with recorded hashes.

```sh
HQ=/path/to/hq
"$HQ" server --listen 127.0.0.1:4433 --cert server.pem --key server.key \
  --www ./www --max-requests 2 --max-connections 2 \
  --early-data buffered-get --early-age-skew-ms 1000

"$HQ" client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem \
  --downloads ./new-downloads --request /warm.bin --request /body.bin \
  --connections 2 --early-data replay-safe-get --expect-early accepted \
  --resumption-delay-ms 1500
```

For rejection, add `--reject-early-second true` to the server and use `--expect-early rejected` on the client. The rejected GET remains owned and is sent over ordinary 1-RTT under the new limits. File hashes and close/drain completion are still required.

This listener processes connection lifetimes sequentially. In the initial zero-delay localhost experiment, a second-connection retry produced a measured server/reported ticket-age difference of 1002ms, correctly exceeding the explicit 1000ms early window while ordinary PSK resumption remained valid. An explicit 1500ms interconnection delay reduced the observed difference to 4ms and allowed real early admission. The preserved evidence records both outcomes; no freshness setting was silently widened. This delay is a test/profile constraint, not a general network timing guarantee.

## Reports and evidence

Per-connection `early_data` reports the configured mode, offer/decision, successful early UDP packet submissions, actual authenticated/admitted early packet count, and queued request count/bytes. `zero_rtt` is true only after Accepted plus real output or admission. Admitted packets exclude duplicates, corrupt/rejected packets and capacity drops; they can include controls or an early close, so the count alone is not proof of application delivery. Exact response hashes, stream completion and lifecycle closure are separate assertions.

The implementation-owner evidence includes:

- `artifacts/early-data-kernels/metrics-frozen/`: 974 immutable source inputs, seventeen actual wire groups, four provider groups, seven resumption groups, strict fixture Clippy and thumb checks. Managed CID/path admission, Finished-gated control effects, capacity/ACK behavior and the admission counter are covered
- `artifacts/host-early/`: immutable candidate binary/hash, the failed zero-delay freshness observation, and successful explicit-delay self UDP acceptance, rejection/requeue, disabled-client and ChaCha acceptance. Each successful self run compares nine files including a 5MiB body and exercises more requests than the four early journal slots
- The separate certificate-verifying Neqo library wrapper uses the unchanged pinned Neqo engine, explicit initial CA/hostname verification and inherited authenticated-token binding. Its early acceptance/rejection records must include actual early output and the server's admission observation; it is not the official Neqo CLI

Final independent review of the expanded profile has not completed. Earlier independent findings and evidence remain preserved. These results do not establish distributed exactly-once semantics, unrestricted concurrent listener capacity, full runner qualification, or Pico RAM/stack/flash execution.
