# Profiling

## Complete connection

Run real TLS, encrypted application data, recovery and connection retirement
with the complete connection protocol:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo +stable test --locked --release --test connected_application \
  full_connection_runtime_profile -- --ignored --exact --nocapture --test-threads=1
```

`HIBANA_RUNTIME_SAMPLES` sets the positive sample count (default 5). Each sample
creates two peers and completes one request, four concurrent streams, or one
request with a lost server 1-RTT packet. The allocation check remains active
through TLS, endpoint operations and resource destruction.

The report gives minimum and median wall time for a complete sample. It also
reports medians for preparation, attachment, execution and cleanup. Preparation
includes host buffers and a separate TLS exchange used to inspect loss cases.
Attachment sets up the actual TLS peers and endpoints. Execution polls both peers
through the handshake, application transfer and connection shutdown. Cleanup
checks the results and drops the protocol resources. These medians are computed
separately and need not add up to the median total.

The complete sample includes fixture setup, cryptography and the simulated
network, so it is not the cost of one endpoint operation. Use macOS `sample` or
Linux `perf` during a separate run to locate costly calls. Collect timing
comparisons without stack sampling.

The [native server comparison](native-peers/README.md) uses one client against
both servers with a matching response, certificate and TLS configuration. Its
measurement covers connection creation through response completion over UDP.

For a Neqo reference on the same machine and compiler, its official benchmarks
provide two different measurements:

```sh
cargo +stable bench --locked -p neqo-http3 --features bench --bench streams_walltime -- \
  'streams/walltime/1-streams/each-1000-bytes'
cargo +stable bench --locked -p neqo-bin --features bench --bench main -- 'aka. HPS'
```

Run these in a pinned [Neqo checkout](https://github.com/mozilla/neqo), with its
required NSS library. The stream benchmark times a 1,000-byte upload after the
handshake over a simulated network. HPS times a fresh connection and a one-byte
response over local UDP, excluding server setup and full connection shutdown.
These measure different work from the complete Hibana fixture. Compare matching
setup, handshake, request, body and shutdown boundaries before reporting a ratio.

## Call and loop counts

Install Rust's `llvm-tools-preview` component and `jq`, then run under the
workspace memory guard with a separate target directory:

```sh
bash tools/profiling/count-runtime.sh /absolute/output/directory --locked
```

Additional arguments are passed to Cargo, including `--config` for a local core
patch. The script runs one complete GET and checks the response and shutdown.
LLVM records function entries and source-region counts in an instrumented
release build. `function-counts.tsv` ranks the calls; `admission-counts.json`
includes loop-region counts for the protocol checks. Use the ordinary profiler
above for timing. Instrumented timing includes counter overhead.

## Source projection

Measure the projection passes for the complete connection choreography:

```sh
RUSTFLAGS='--cfg hibana_profile' CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
  cargo +stable test --locked --features hq --test projection_profile -- \
  --nocapture --test-threads=1
```

Use a separate `CARGO_TARGET_DIR` for profiling. To measure an unpublished core,
add `--config 'patch."https://github.com/hibanaworks/hibana".hibana.path="../hibana"'`
before `--`. Run local builds under the workspace memory guard.

Each test repeats the compiler's existing function natively. Inputs listed as
cached are prepared by const evaluation before timing starts.

| Test | Measured work | Cached inputs |
| --- | --- | --- |
| `full_connection` | Receive-lane assignment and its counters | Source events and actor bindings |
| `connection_actor_image` | Actor bindings and ownership checks | Typed protocol |
| `connection_scope_facts` | Shared scope information | Source events |
| `connection_source_emission` | Source events and structural markers | Actor bindings |
| `connection_role_plan` | Local image planning | Source, scope information and actor rows |
| `connection_image_emission` | Writing the local image | Source, scope information, actor rows and plan |
| `connection_resident_validation` | Event and ownership validation | Compiled image |
| `connection_operation_order` | Source-order validation | Compiled image |

The local passes report RX, SOURCE, RECEIVE and SINK separately. The source
report includes row, event and ownership-decision counts, lane assignments, inspections and
recolorings. `dependency_workspace_bytes` is the dependency scan's scratch size
on the profiling target. Each test reports minimum and median elapsed time.
`HIBANA_PROJECTION_SAMPLES` sets a positive count, defaulting to 100 for lane
assignment and 10 for the other passes. Filter by one test name and use 1000 or
more samples when collecting stacks with macOS `sample` or Linux `perf`.
Capture stacks separately from timing comparisons.

These are native pass times. They exclude other compiler work and should not
be added together as a Rust build time. Build `connected_application` normally
to measure the complete const projection with `long_running_const_eval`
forbidden. `hibana_profile` enables these entry points only in diagnostic builds.
