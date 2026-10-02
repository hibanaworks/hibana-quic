# Remaining capability and release-gate ledger

Updated 2026-10-02 09:26 UTC. This tracks implementation evidence, not runner results.
All forty runner cells remain NOT_RUN/NOT_PASSED until the pinned runner executes
both directions with required files/traces and three complete attempts.

| PLAN case | Current implemented evidence | Remaining acceptance work |
|---|---|---|
| handshake | Authenticated bounded TLS/QUIC both roles; X25519/P256; nine-cert chain; direct Neqo | Full runner trace gate; full embedded stack qualification |
| transfer | Exact5MiB direct both directions; bounded streaming/loss/key-update allocation tests | Full runner transfer/trace evidence |
| longrtt | Forward 500 ms-RTT direct 64 KiB verified; corrected reverse host reaches Closed under delay and late-packet loss | Runner long-RTT scenario; historical failures retained in completed-close evidence |
| chacha20 | Packet vectors and real TLS/key-update interoperability for1303 | Strict singleton CLI and IPv6 direct cases passed; runner case remains |
| multiplexing |1999 stream-slot reuse test;11-file single-connection transfer | Runner workload and three-attempt evidence |
| retry | Bounded wire/token tests; official Neqo --retry5MiB with exact token echo and freshPN | Bounded host server dispatcher and direct reverse verified; runner trace remains |
| resumption | Ticket/cache primitives, actual two TLS connections and raw Rustls both directions | Persistent two-connection host loop/direct Neqo/age boundary gates verified; runner remains |
| zerortt | Real opt-in bounded early TLS and encrypted endpoint acceptance/rejection, Finished quarantine, independent freshness and PN-preserving replay | Encrypted early wire 13/13, TLS 4/4 and resumption 7/7 pass; managed early CID/path coverage, final independent review, direct host/Neqo and runner remain |
| blackhole | PTO/retransmission retained ownership and loss accounting | Direct temporary3s blackhole10MiB both directions passed; permanent outage fails cleanly; runner remains |
| keyupdate | Direct Neqo5MiB both initiating roles; authenticated phase evidence; wrap/old-key negatives | Runner private keylog/pcap assertions and repeated matrix |
| ecn | RealIPv4/IPv6 ancillary I/O, direct Neqo and relay CE/bleaching tests | Retired-history fallback regression verified; runner scenario remains |
| amplificationlimit | Exact pending/sent path budget; real nine-cert bounded UDP handshake | Runner amplification accounting/trace assertions |
| handshakeloss | Encrypted Initial loss/PTO and Retry retransmission tests | Multi-connection host mode and runner loss scenario |
| transferloss | Exact lost-PN retransmission;5MiB bounded recovery test | Runner stochastic loss workload |
| handshakecorruption | Auth-failure discard/key integrity accounting | Multi-connection host mode and runner corruption workload |
| transfercorruption | Real encrypted corruption/recovery and byte checks | Runner corruption workload |
| ipv6 | Actual authenticated IPv6 transfer/default+strictChaCha/auth-negative suites passed | Runner IPv6 scenario remains |
| rebind-port | Actual encrypted port rebinding, challenge/response and full-MTU validation pass with zero allocations | Managed stream and real HQ-to-HQ UDP 5 MiB rebinding/Closed passed; direct Neqo and runner remain |
| rebind-addr | Exact-path RTT/congestion isolation tested against delayed old-path ACK | Encrypted bounded and real HQ-to-HQ UDP 5 MiB IP-rebinding passed; direct Neqo and runner remain |
| connectionmigration | Actual accepted EncryptedExtensions authorizes preferred CID; encrypted preferred-tuple validation passes with zero allocations | Concrete/wildcard preferred-address HQ-to-HQ UDP 5 MiB/Closed passed; direct Neqo, final CID lifecycle review and runner remain |

## Other concrete gaps

- Explicit encrypted CONNECTION_CLOSE and closing/draining deadlines are integrated
  and allocation-tested. Idle timeout is integrated with silent pending-output
  expiry and real encrypted/no-allocation tests. Automatic fatal-error wire-close
  mapping, stateless reset and full multi-path CID retention remain incomplete
- Version Negotiation: bounded listener/client policies, real encrypted endpoint
  and IPv4/IPv6 UDP gates passed. V1-only policy never restarts to an unsupported
  version and never treats VN as authenticated (not one of the20 cases)
- RSA verification: 1,224 signature cases, strict certificate integration, real
  RSA TLS handshakes and independent review pass. RSA server signing is absent;
  complete embedded stack/latency qualification remains open
- Complete recovery policy: persistent-congestion and pacing kernels need final
  endpoint integration/evidence; newly integrated per-path state needs full stream/host qualification
- An isolated caller-buffer qlog JSON-SEQ writer has allocation/target tests.
  Actual endpoint instrumentation, private TLS keylog emission and required
  runner pcap assertions remain pending. No placeholder or synthetic success files are generated
- Full lifecycle/0RTT/resumption allocation closure and final target layout/link
  must be rerun after remaining features; partial measurements are not final fit

## Infrastructure and hardware blockers

- NETLINK_ROUTE sockets return EPERM in this cloud, including new user/network
  namespaces. The normal network-simulator topology cannot run here. A prepared
  QNS Dockerfile/command adapter is unexecuted; no host security workaround used
- No Pico board, driver/entropy source selection or HIL device is supplied.
  Component links/layout snapshots are not bootable firmware, measured peak
  stack, full RAM/flash use, timing, or hardware validation
- Original Hibana CI and the published selector-fix branch fail unchanged Kani
  inventory ordering and Miri expected-count gates. Relevant tests/proofs passed,
  but complete upstream CI is not green; no unrelated gate weakening was made

## Evidence checkpoints

- `artifacts/network-impairment/completed-close-README.md` records the corrected
  frozen HQ e458ccf5 direct suite: 11/11 focused outcomes with strict Closed gates.
  Earlier failed reports remain unchanged; these results are not runner cells
- Live early-control and managed-path changes are newer than that frozen host
  checkpoint and require their own final source-bound regression run
- Public GitHub Actions pilot preparation is underway as an authorized alternative
  to the local network restriction. Pilot run 36988665314 is in progress for frozen source f586d9a; no result exists yet
