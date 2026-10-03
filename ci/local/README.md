# Local official interop

Run in Linux with Rust **1.95.0**, Python 3, Docker Engine API **>=1.49**,
and Compose supporting `interface_name`. Read `ci/pins.env` for all source and
image pins. Do not set `GITHUB_ACTIONS` or `PUBLIC_REPOSITORY` locally.
`ci/compile-recovery.sh` / `ci/test-recovery.sh` are separate compilation
diagnostics; `run-local-interop.py` always invokes the official runner.

Keep all work, private certificates, TLS secrets, packet captures, generated
binaries and Cargo targets **outside** the source checkout. The source audit
also checks ignored paths. Use a fresh output directory for each build.

```bash
source ci/pins.env
LOCAL_WORK=/workspace/interop
LOCAL_CA=/etc/ssl/certs/ca-certificates.crt
mkdir -p "$LOCAL_WORK"
git clone https://github.com/quic-interop/quic-interop-runner "$LOCAL_WORK/runner"
git -C "$LOCAL_WORK/runner" checkout --detach "$RUNNER_REVISION"
git clone https://github.com/mozilla/neqo "$LOCAL_WORK/neqo"
git -C "$LOCAL_WORK/neqo" checkout --detach "$NEQO_REVISION"
docker pull "$SIMULATOR_TAG"
docker image inspect "$SIMULATOR_TAG" --format '{{index .RepoDigests 0}}' > "$LOCAL_WORK/simulator-image.txt"
```

Resolve the simulator once, retain that digest for baseline and every candidate
attempt, and retain image IDs and build logs. CA trust below is a BuildKit secret
or runtime mount, never a baked session certificate. Keep certificate validation
enabled. On an ordinary network the unchanged upstream Dockerfiles can also be
built directly; the adapter below supplies trust for managed proxy environments.

```bash
python3 ci/local/docker-trust.py ci/runner-tools.Dockerfile "$LOCAL_WORK/tools.Dockerfile"
docker build --secret id=system_ca,src="$LOCAL_CA" \
  --build-arg UBUNTU_IMAGE="$UBUNTU_IMAGE" --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" \
  -f "$LOCAL_WORK/tools.Dockerfile" -t hibana-local-interop-tools "$LOCAL_WORK/runner"
```

For Neqo, the unchanged upstream multi-stage `qns/Dockerfile` is the reference.
On a small disk with Docker's `vfs` storage driver, repeated compiler layers can
exhaust storage. The following single builder uses that file's exact chef base,
NSS digest and build flags, then packages only its outputs. The chef image's Rust
version is recorded by the builder; QUIC development/tests use Rust 1.95.0.

```bash
LOCAL_CHEF=$(sed -n 's/^FROM \([^ ]*\) AS chef$/\1/p' "$LOCAL_WORK/neqo/qns/Dockerfile")
mkdir -p "$LOCAL_WORK/neqo-artifacts"
docker run --name hibana-local-neqo-builder \
  -v "$LOCAL_WORK/neqo:/source:ro" -v "$PWD/ci/local/build-neqo.sh:/build-neqo.sh:ro" \
  -v "$LOCAL_CA:/run/system-ca.pem:ro" -v "$LOCAL_WORK/neqo-artifacts:/output" \
  "$LOCAL_CHEF" bash /build-neqo.sh
docker build --build-arg ENDPOINT_IMAGE="$ENDPOINT_IMAGE" \
  -f ci/local/neqo.Dockerfile -t hibana-local-neqo "$LOCAL_WORK/neqo-artifacts"
docker run --rm --entrypoint /bin/sh hibana-local-neqo \
  -c 'test -s /neqo/interop.sh; sha256sum /neqo/interop.sh; /neqo/bin/neqo-client --version'
docker rm hibana-local-neqo-builder
```

Record the builder exit code before cleanup. Compare the entrypoint hash with
the pinned source. Ensure every artifact is readable by the Docker build client;
an unreadable entrypoint can become an empty image file. Do not package it.

Build the candidate at a **clean committed SHA**, using the same local Rust
environment used for tests. The runtime smoke checks host ABI compatibility
with the pinned endpoint base. Alternatively build the original
`interop/qns/Dockerfile` with the pinned Rust image and ephemeral trust adapter.

```bash
export CARGO_TARGET_DIR="$LOCAL_WORK/quic-target"
rustc --version   # must be 1.95.0
cargo build --locked --release --manifest-path adapters/host/Cargo.toml --bin hq
mkdir -p "$LOCAL_WORK/candidate-artifacts"
cp "$CARGO_TARGET_DIR/release/hq" "$LOCAL_WORK/candidate-artifacts/hq"
cp interop/qns/endpoint.py "$LOCAL_WORK/candidate-artifacts/endpoint.py"
docker build --secret id=system_ca,src="$LOCAL_CA" \
  --build-arg ENDPOINT_IMAGE="$ENDPOINT_IMAGE" --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  -f ci/local/candidate.Dockerfile -t hibana-local-quic "$LOCAL_WORK/candidate-artifacts"
docker run --rm --entrypoint /usr/local/bin/hibana-quic-hq hibana-local-quic --help
python3 ci/run-local-interop.py --work-root "$LOCAL_WORK" \
  --sim-image "$(cat "$LOCAL_WORK/simulator-image.txt")" --mode matrix --repetitions 3
```

The wrapper checks source pins, clean runner/candidate checkouts, the image's
source SHA, Docker/Compose and tshark. It runs Neqo/Neqo first, then the two
handshake/transfer directions. Only a successful pilot permits the 20-case,
two-direction, three-repetition matrix. These 20 are the pinned upstream QUIC
cases excluding **http3** and **v2**; no HTTP/3 result is claimed. The upstream
test logic, topology, timeouts, verdicts and file comparison remain unchanged.
Only implementation registration and the immutable simulator image are supplied
in a separate work directory. `/tmp` and absolute paths are shared with the
tools container because the official runner uses host bind mounts.

Each attempt saves commands, exit codes, raw runner JSON, captures, logs and a
safe summary. `executed` counts succeeded/failed tests; `unsupported` counts
upstream's unsupported verdict separately; `not_run` includes cells blocked by
baseline/pilot. The matrix exit code is nonzero unless **all selected cells**
succeed. A runner process exiting zero with null results is never a pass.

If baseline fails, repair the environment before attributing failure to QUIC.
Do not change tests, disable comparisons, inject passing results, or promote a
TLS exchange to transfer success. This environment initially lacked the legacy
IPv6 iptables kernel support; switching to the available nft backend also
required Docker's standard IPv6 chain initialization. Such host setup is an
explicit environment repair, not part of this wrapper or an endpoint fallback.
