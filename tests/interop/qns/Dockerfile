# Build context: output of tools/ci/stage-paired-source.py, not QUIC alone.
ARG RUST_IMAGE
ARG ENDPOINT_IMAGE
FROM ${RUST_IMAGE} AS builder
WORKDIR /source/hibana-quic
ENV CARGO_TARGET_DIR=/build
COPY hibana-quic /source/hibana-quic
COPY hibana-tls /source/hibana-tls
RUN cargo build --locked --release --manifest-path pal/Cargo.toml --bin hq
FROM ${ENDPOINT_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/release/hq /usr/local/bin/hibana-quic-hq
COPY hibana-quic/LICENSE-MIT hibana-quic/LICENSE-APACHE /usr/share/doc/hibana-quic/
COPY hibana-quic/tests/interop/qns/endpoint.py /usr/local/bin/hibana-quic-endpoint.py
ENTRYPOINT ["python3", "/usr/local/bin/hibana-quic-endpoint.py"]
