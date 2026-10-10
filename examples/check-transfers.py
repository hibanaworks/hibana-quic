#!/usr/bin/env python3
"""Run both finite application examples over authenticated loopback UDP."""
import argparse
from pathlib import Path
import re
import selectors
import subprocess
import tempfile


def exchange(binaries, protocol, certificate, key, ca, files=None):
    server = subprocess.Popen(
        [str(binaries / f'{protocol}-server'), '127.0.0.1:0', certificate, key]
        + ([str(files[0])] if files else []),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(server.stderr, selectors.EVENT_READ)
            if not ready.select(10):
                raise RuntimeError(f'{protocol}: listener did not become ready')
            line = server.stderr.readline()
        address = re.fullmatch(r'listening on (127\.0\.0\.1:\d+)\n', line)
        if address is None:
            raise RuntimeError(f'{protocol}: listener failed: {line}')
        client = subprocess.run(
            [str(binaries / f'{protocol}-client'), address[1], ca]
            + ([str(files[1])] if files else []),
            capture_output=True, text=True, timeout=40,
        )
        output, errors = server.communicate(timeout=40)
        if client.returncode or server.returncode:
            raise RuntimeError(
                f'{protocol}: client exit={client.returncode}, server exit={server.returncode}\n'
                f'{client.stderr}{errors}{output}'
            )
        if files:
            if client.stdout != 'received response\n' or output != 'served response\n':
                raise RuntimeError('hq: missing response completion')
            if files[0].read_bytes() != files[1].read_bytes():
                raise RuntimeError('hq: response content mismatch')
        elif client.stdout != '42 squared = 1764\n7 squared = 49\n':
            raise RuntimeError(f'{protocol}: response mismatch')
        print(f'{protocol}: authenticated response, normal close and resource retirement passed', flush=True)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binaries', type=Path)
    parser.add_argument('certificate')
    parser.add_argument('key')
    parser.add_argument('ca')
    parser.add_argument('--hq', action='store_true', help='also check the explicitly built HQ examples')
    args = parser.parse_args()
    for protocol in ('quic', 'http3'):
        exchange(args.binaries.resolve(), protocol, args.certificate, args.key, args.ca)

    if args.hq:
        with tempfile.TemporaryDirectory(prefix='hibana-hq-example-') as tmp:
            root = Path(tmp)
            for size in (0, 1, 16385, 1048576):
                source = root / 'content'
                source.write_bytes(bytes((i * 73 + 19) % 256 for i in range(size)))
                destination = root / f'output-{size}'
                exchange(args.binaries.resolve(), 'hq', args.certificate, args.key, args.ca,
                         (source, destination))
