#!/usr/bin/env python3
"""Actual stateless VN response followed by authenticated v1 on the same server.

This is native evidence, not an official runner qualification. Ephemeral keys
remain in a temporary directory; only structural packet facts are exported.
"""
import argparse
import json
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile

from test_direct_handshake_localhost import credentials


def envelope(version, destination, source):
    return (b'\xc0' + version.to_bytes(4, 'big') + bytes([len(destination)])
            + destination + bytes([len(source)]) + source + bytes(32))


def inspect(reply, destination, source):
    assert len(reply) >= 11 and reply[0] & 0x80 and reply[1:5] == bytes(4)
    at = 5
    n = reply[at]; at += 1
    assert reply[at:at+n] == source
    at += n
    n = reply[at]; at += 1
    assert reply[at:at+n] == destination
    at += n
    assert (len(reply)-at) % 4 == 0
    versions = [int.from_bytes(reply[i:i+4], 'big') for i in range(at, len(reply), 4)]
    assert versions == [1], versions
    return versions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hq', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    hq = args.hq.resolve(strict=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='hibana-vn-') as temporary:
        root = Path(temporary)
        credentials(root)
        server = subprocess.Popen([str(hq), 'server', '--listen', '127.0.0.1:0',
            '--cert', str(root/'server.pem'), '--key', str(root/'server.key'),
            '--timeout-seconds', '10'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(server.stderr, selectors.EVENT_READ)
                assert selector.select(5), 'server readiness timeout'
                ready = server.stderr.readline().strip()
            prefix = 'direct Hibana server listening on '
            assert ready.startswith(prefix), ready
            address = ready[len(prefix):]
            host, port = address.rsplit(':', 1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                for destination, source in [(b'dest-001', b'src--001'), (b'd'*20, b's'*20), (b'', b'')]:
                    probe = envelope(0xfaceb00c, destination, source)
                    client.sendto(probe, (host, int(port)))
                    reply, peer = client.recvfrom(2048)
                    assert peer == (host, int(port))
                    versions = inspect(reply, destination, source)
                    assert len(reply) <= 3 * len(probe)
                    results.append({'dcid_bytes':len(destination), 'scid_bytes':len(source),
                        'request_bytes':len(probe), 'response_bytes':len(reply), 'versions':versions})
                # No VN loop and no envelope beyond the CID profile.
                client.settimeout(0.1)
                for probe in [envelope(0, b'dest-001', b'src--001'), envelope(0xfaceb00c, b'd'*21, b's')]:
                    client.sendto(probe, (host, int(port)))
                    try:
                        client.recvfrom(2048)
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError('invalid/VN input elicited another response')
            valid = subprocess.run([str(hq), 'client', '--connect', address,
                '--server-name', 'localhost', '--ca', str(root/'ca.pem'),
                '--timeout-seconds', '5'], capture_output=True, text=True, timeout=8)
            out, error = server.communicate(timeout=8)
            assert valid.returncode == server.returncode == 0, (valid.stderr, error)
            for line in (valid.stdout, out):
                report = json.loads(line)
                assert report['tls_finished_authenticated'] and report['owned_application_continuations']
            args.output.write_text(json.dumps({'scope':'native server version negotiation',
                'probes':results, 'invalid_inputs_ignored':2, 'subsequent_authenticated_v1':True}, indent=2)+'\n')
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()
    print('native VN CID reversal, v1 offer, amplification bound, invalid-input rejection and subsequent handshake passed')


if __name__ == '__main__':
    main()
