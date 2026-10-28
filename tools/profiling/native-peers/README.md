# Native server comparison

This host tool uses one Neqo client implementation against the Hibana and Neqo
HTTP/0.9 servers over IPv4 loopback UDP. It measures connection creation through
receipt of the complete response. NSS initialization, client socket binding,
server spawning and connection shutdown are outside the measured interval.
Timing starts after the server has bound its UDP port. Any server setup that
continues after binding can overlap this interval.
The tool requires `lsof` to observe that socket in the server process. Readiness
checks never bind the server's address. Socket inspection is outside timing.

Both servers use the same P-256 certificate and return 1,537 zero bytes. The
client pins that certificate, verifies every response byte, and checks TLS 1.3,
X25519, AES-128-GCM, `hq-interop`, and the absence of resumption and early data.
It sends `GET /hello` to Hibana and `GET /01537` to Neqo. The paths differ because
Neqo's example server takes a numeric response length. Request lengths match.

Each trial starts a fresh server process. Two warmup trials per server are excluded. The
tool balances server order and position, prints every measurement, and reports minimum,
median and maximum times. Packet counts help identify differences in the flights.
The packet records on stderr give direction, elapsed nanoseconds and UDP payload
size after each socket send or receive. Logging takes place after timing ends.
Receive times include the client's scheduling delay. Close packets are excluded.
On macOS, `server_cpu_ns` reports the server process's user and system CPU time
between the start of the client request and response FIN, before connection
shutdown. The tool reads `proc_pid_rusage` and converts Mach ticks with
`mach_timebase_info`. All server work overlapping this interval is included,
including any remaining setup after UDP binding. CPU time is reported as
unavailable on other systems.
These results describe the two complete
server implementations, including their TLS libraries and I/O adapters.

Build `hq-server` from `examples/Cargo.toml` with `--features hq --release` and
build `neqo-server --release` at the revision pinned in this tool's manifest.
NSS development libraries and `pkg-config` are required by Neqo.

Prepare a temporary directory containing a test identity and response:

```sh
umask 077
mkdir -p peer-input/nssdb
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout peer-input/key.pem -out peer-input/cert.pem -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:FALSE \
  -addext keyUsage=critical,digitalSignature -addext extendedKeyUsage=serverAuth
openssl x509 -in peer-input/cert.pem -outform DER -out peer-input/cert.der
openssl pkcs12 -export -in peer-input/cert.pem -inkey peer-input/key.pem \
  -name benchmark -out peer-input/identity.p12 -passout pass:
certutil -N -d sql:peer-input/nssdb --empty-password
pk12util -i peer-input/identity.p12 -d sql:peer-input/nssdb -W '' -K ''
dd if=/dev/zero of=peer-input/body bs=1537 count=1
```

Run under the workspace memory guard, with an independent target directory:

```sh
cargo +stable run --locked --release --manifest-path tools/profiling/native-peers/Cargo.toml -- \
  /absolute/path/to/hq-server /absolute/path/to/neqo-server \
  /absolute/path/to/peer-input 9
```

Retain source revisions, compiler details, binary hashes and raw measurements
with the result. Delete the temporary test identity after use.

To measure a core change, add the earlier Hibana server binary as a fifth
argument. Build both binaries with the same compiler and settings in separate
target directories:

```sh
cargo +stable run --locked --release --manifest-path tools/profiling/native-peers/Cargo.toml -- \
  /absolute/path/to/hq-server-after /absolute/path/to/neqo-server \
  /absolute/path/to/peer-input 120 /absolute/path/to/hq-server-before
```

Each iteration measures all three servers. Six consecutive iterations cover
all six orders, so use a multiple of six samples after warmup. The report also
gives the after/before time ratio for matched iterations, including its median,
10th and 90th percentiles, and the number of faster trials. These percentiles
describe the observed pairs. Preserve a failed batch separately and repeat the
whole batch rather than silently retrying or discarding individual trials.

On macOS, set `HIBANA_NATIVE_STACKS` to an output directory to attach `sample`
before each Hibana request. This records server stacks through process exit,
including connection shutdown. Use the caller stacks to distinguish request
processing from shutdown. Sampled durations must not be used for timing
comparisons. Leave this variable unset when collecting performance results.

For server call counts before connection shutdown, build `hq-server` with
`RUSTFLAGS='-C instrument-coverage'` and set `HIBANA_NATIVE_COVERAGE` to a fresh
directory. This macOS diagnostic uses LLVM continuous profiles. It pauses the
owned server briefly to copy counters after UDP readiness and after the client
has checked the response FIN, then resumes it on every exit path. Subtract the
first snapshot from the second. The second snapshot precedes connection close
and can include work scheduled between FIN receipt and the pause. It is not a
cycle-level measurement. Missing profiles and decreasing counters are errors.
Do not use these durations for performance comparisons or combine this mode
with a baseline server or stack sampling. `../count-native.sh` builds the
instrumented server, runs this diagnostic, and exports the counter differences.
The script aligns LLVM's counter, bitmap, data and name sections to the host
page size. Rust's coverage option alone does not provide the alignment required
by macOS continuous profiles. It rejects LLVM mapping errors and empty response
counters. A successful file copy alone does not qualify a profile.

The continuous-profile filename syntax is documented in
[LLVM's coverage guide](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html).
