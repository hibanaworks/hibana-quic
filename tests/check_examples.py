#!/usr/bin/env python3
"""Run both finite application examples over authenticated loopback UDP."""
import argparse
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time


def exchange(binaries, protocol, certificate, key, ca, files=None, http=None):
    started = time.monotonic()
    if protocol == 'http3' and http is None:
        http = ('POST', '/echo', 'hello from Hibana\n', 200, 'hello from Hibana\n')
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
        env = os.environ.copy()
        if http:
            method, path, body, status, expected = http
            env.update(HTTP_METHOD=method, HTTP_PATH=path, HTTP_BODY=body)
        client = subprocess.run(
            [str(binaries / f'{protocol}-client'), address[1], ca]
            + ([str(files[1])] if files else []),
            capture_output=True, text=True, timeout=40, env=env,
        )
        output, errors = server.communicate(timeout=40)
        if client.returncode or server.returncode:
            progress = ''
            if files:
                received = files[1].stat().st_size if files[1].is_file() else 'missing'
                progress = f', expected_bytes={files[0].stat().st_size}, received_bytes={received}'
            raise RuntimeError(
                f'{protocol}: client exit={client.returncode}, server exit={server.returncode}, '
                f'elapsed_seconds={time.monotonic()-started:.3f}{progress}\n'
                f'{client.stderr}{errors}{output}'
            )
        if files:
            if client.stdout != 'received response\n' or output != 'served response\n':
                raise RuntimeError('hq: missing response completion')
            if files[0].read_bytes() != files[1].read_bytes():
                raise RuntimeError('hq: response content mismatch')
        elif protocol == 'http3':
            if client.stdout != expected or f'HTTP/3 {status}\n' not in client.stderr or output != 'served HTTP/3 request\n':
                raise RuntimeError('http3: response content or completion mismatch')
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
    parser.add_argument('--hq-size', type=int, choices=(0, 1, 16385, 1048576),
                        help='run only this HQ transfer size')
    args = parser.parse_args()
    if args.hq_size is None:
        exchange(args.binaries.resolve(), 'quic', args.certificate, args.key, args.ca)
        for case in (
            ('GET', '/hello', '', 200, 'hello from Hibana\n'),
            ('HEAD', '/hello', '', 200, ''),
            ('POST', '/echo', 'hello from Hibana\n', 200, 'hello from Hibana\n'),
            ('POST', '/echo', 'x' * 8193, 200, 'x' * 8193),
            ('GET', '/missing', '', 404, 'not found\n'),
            ('HEAD', '/missing', '', 404, ''),
        ):
            exchange(args.binaries.resolve(), 'http3', args.certificate, args.key, args.ca, http=case)

    if args.hq or args.hq_size is not None:
        with tempfile.TemporaryDirectory(prefix='hibana-hq-example-') as tmp:
            root = Path(tmp)
            for size in ((args.hq_size,) if args.hq_size is not None else (0, 1, 16385, 1048576)):
                source = root / 'content'
                source.write_bytes(bytes((i * 73 + 19) % 256 for i in range(size)))
                destination = root / f'output-{size}'
                exchange(args.binaries.resolve(), 'hq', args.certificate, args.key, args.ca,
                         (source, destination))
