#!/usr/bin/env python3
"""Add ephemeral CA trust to Docker build commands without changing sources.

Usage: python3 ci/local/docker-trust.py INPUT_DOCKERFILE EXTERNAL_OUTPUT
Pass --secret id=system_ca,src=/path/to/combined-ca.pem to docker build.
"""
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
root = Path(__file__).resolve().parents[2]
assert root not in destination.resolve().parents, 'generated Dockerfile must be outside checkout'
trust = ('--mount=type=secret,id=system_ca,required=true '
         'export SSL_CERT_FILE=/run/secrets/system_ca CURL_CA_BUNDLE=/run/secrets/system_ca '
         'CARGO_HTTP_CAINFO=/run/secrets/system_ca REQUESTS_CA_BUNDLE=/run/secrets/system_ca '
         'PIP_CERT=/run/secrets/system_ca; ')
lines = ['# syntax=docker/dockerfile:1\n']
for line in source.read_text().splitlines(keepends=True):
    if line.startswith('RUN '):
        line = 'RUN ' + trust + line[4:]
    line = line.replace('apt-get ', 'apt-get -o Acquire::https::CaInfo=/run/secrets/system_ca ')
    lines.append(line)
destination.write_text(''.join(lines))
