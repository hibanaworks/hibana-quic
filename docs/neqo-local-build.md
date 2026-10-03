# Neqo development peer

Built successfully in the assistant cloud environment on 2026-10-02; not a container-runner result.

- Mozilla source: https://github.com/mozilla/neqo/commit/ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95
- Neqo version: 0.32.0; source is pinned main, not claimed to be the release tag
- Locked nss-rs revision: ba8a3f6acffc7e25749054969ccbbb3ca615df7f
- NSS 3.126 + NSPR 4.39 archive: https://archive.mozilla.org/pub/security/nss/releases/NSS_3_126_RTM/src/nss-3.126-with-nspr-4.39.tar.gz
- Archive SHA256 verified: c95a4cf93d6939000642254422d71dffccb5c017d0f40733d3e2be18aa93f1be
- Build dependencies installed from PyPI: gyp-next 0.22.3, ninja 1.13.2, mercurial 7.2.4
- Compiler: Rust 1.95.0; host GCC 14 and libclang 19

Workspace base: `/workspace/scratch/0915e8fbff81`.

Build environment:

```sh
PATH=/tmp/hibana-rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:/tmp/hibana-quic-proof-venv/bin:$PATH
CARGO_HOME=/tmp/hibana-cargo
CARGO_BUILD_JOBS=2
NSS_DIR=/workspace/scratch/0915e8fbff81/tools/neqo/nss-3.126/nss
LIBCLANG_PATH=/usr/lib/x86_64-linux-gnu
BINDGEN_EXTRA_CLANG_ARGS='-isystem /usr/lib/gcc/x86_64-linux-gnu/14/include'
# NSS_PREBUILT=1 only after initial NSS build has succeeded
cargo build --locked --bin neqo-client --bin neqo-server
```

Run binaries from `tools/neqo/source/target/debug` with `LD_LIBRARY_PATH=/workspace/scratch/0915e8fbff81/tools/neqo/nss-3.126/dist/Release/lib`.
NSS certutil/pk12util are under `tools/neqo/nss-3.126/dist/Release/bin`.
Build logs: `tools/neqo/build.log` (initial missing stddef header), `tools/neqo/build-retry.log` (successful corrected include environment). No Neqo or NSS source modifications.

## Container feasibility boundary

No Docker daemon/socket or CLI initially present. A bounded ephemeral `unshare --user --map-root-user --net /usr/bin/true` check succeeded. Thus absence of host capabilities alone does not establish rootless impossibility. Subordinate UID/GID ranges exist, but `newuidmap` and `newgidmap` are absent. The official Docker rootless route requires those privileged host helpers: https://docs.docker.com/engine/security/rootless/ . No host privilege, sysctl or security configuration was changed. Full runner capability remains unestablished; direct UDP peer results must not be called runner matrix passes.
