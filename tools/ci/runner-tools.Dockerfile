ARG UBUNTU_IMAGE
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE} AS python-runtime
FROM ${UBUNTU_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tshark openssl git libbz2-1.0 libffi8 liblzma5 \
    libreadline8t64 libsqlite3-0 libssl3t64 zlib1g libexpat1 libncursesw6 libgdbm6t64 \
    docker.io docker-compose-v2 iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=python-runtime /usr/local /usr/local
ENV PATH=/usr/local/bin:$PATH
RUN ldconfig
COPY requirements.txt /opt/runner-requirements.txt
RUN python3 -m venv /opt/runner-venv && /opt/runner-venv/bin/pip install --no-cache-dir -r /opt/runner-requirements.txt
ENV PATH=/opt/runner-venv/bin:$PATH
RUN python3 -c 'import re,subprocess; s=subprocess.check_output(["tshark","--version"],text=True); v=tuple(map(int,re.search(r"(\d+)\.(\d+)\.\d+",s).groups())); assert v >= (4,5), s'
# Exercise the same synchronous capture lifecycle as the patched pinned runner.
# This synthetic empty capture contains no traffic, keys, or peer data.
COPY trace.py /opt/runner-trace.py
RUN python3 - <<'PYSMOKE'
import importlib.util, pathlib, struct, tempfile, sys
assert sys.version_info[:2] == (3, 12)
spec = importlib.util.spec_from_file_location("runner_trace", "/opt/runner-trace.py")
runner_trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner_trace)
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'empty.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for _ in range(3):
        assert runner_trace.TraceAnalyzer(str(path))._get_packets("quic") == []
print('runner synchronous empty-pcap smoke PASSED on Python', sys.version.split()[0])
PYSMOKE
