# Build context: repository root. Supply independently verified immutable images.
ARG RUST_IMAGE
ARG ENDPOINT_IMAGE
FROM ${RUST_IMAGE} AS builder
WORKDIR /source
COPY . .
RUN cargo build --locked --release --manifest-path adapters/host/Cargo.toml --bin hq
FROM ${ENDPOINT_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /source/adapters/host/target/release/hq /usr/local/bin/hibana-quic-hq
COPY LICENSE-MIT LICENSE-APACHE THIRD_PARTY_NOTICES.md /usr/share/doc/hibana-quic/
COPY interop/qns/endpoint.py /usr/local/bin/hibana-quic-endpoint.py
ENTRYPOINT ["python3", "/usr/local/bin/hibana-quic-endpoint.py"]
