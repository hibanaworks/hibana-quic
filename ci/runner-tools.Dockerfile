ARG UBUNTU_IMAGE
FROM ${UBUNTU_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-venv python3-pip tshark openssl git \
    docker.io docker-compose-v2 iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/runner-requirements.txt
RUN python3 -m venv /opt/runner-venv && /opt/runner-venv/bin/pip install --no-cache-dir -r /opt/runner-requirements.txt
ENV PATH=/opt/runner-venv/bin:$PATH
RUN python3 -c 'import re,subprocess; s=subprocess.check_output(["tshark","--version"],text=True); v=tuple(map(int,re.search(r"(\d+)\.(\d+)\.\d+",s).groups())); assert v >= (4,5), s'
