# The host-built hq must be freshly compiled by Rust 1.95.0 at SOURCE_REVISION.
# Build context contains hq and endpoint.py only; never copy cached TLS material.
ARG ENDPOINT_IMAGE
FROM ${ENDPOINT_IMAGE}
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION}
RUN --mount=type=secret,id=system_ca,required=true apt-get -o Acquire::https::CaInfo=/run/secrets/system_ca update && apt-get -o Acquire::https::CaInfo=/run/secrets/system_ca install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY hq /usr/local/bin/hibana-quic-hq
COPY endpoint.py /usr/local/bin/hibana-quic-endpoint.py
ENTRYPOINT ["python3", "/usr/local/bin/hibana-quic-endpoint.py"]
