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
# Exercise the exact unmodified pyshark + interpreter + tshark subprocess path.
# This is a synthetic empty capture, with no traffic, keys or peer data.
RUN python3 - <<'PYSMOKE'
import pathlib, struct, tempfile, sys, pyshark
assert sys.version_info[:2] == (3, 12)
with tempfile.TemporaryDirectory() as directory:
    path = pathlib.Path(directory) / 'empty.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    capture = pyshark.FileCapture(str(path), keep_packets=False)
    assert list(capture) == []
    capture.close()
print('pyshark empty-pcap parsing smoke PASSED on Python', sys.version.split()[0])
PYSMOKE
