#!/usr/bin/env python3
"""Native long-chain, lost-client-datagram anti-amplification diagnostic.

Use the unchanged pinned runner's certificate generator. This controlled local
wire observation is not the official ns-3 or decrypted packet-trace verdict.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import selectors
import socket
import ssl
import subprocess
import tempfile

from udp_impairment import UdpProxy, EarlyWireProbe


class AmplificationProbe(UdpProxy):
    def __init__(self, server):
        super().__init__(server)
        self.client_datagrams = 0
        self.received_before_validation = 0
        self.sent_before_validation = 0
        self.validation_observed = False
        self.checkpoints = []

    def _enqueue(self, direction, data):
        if direction == 'to_server':
            self.client_datagrams += 1
            if 2 <= self.client_datagrams <= 7:
                self.stats['selected_client_datagrams_dropped'] += 1
                return
            kinds = [kind for kind, _ in EarlyWireProbe.packet_lengths(data)]
            if 'handshake' in kinds:
                self.validation_observed = True
            if not self.validation_observed:
                assert 'initial' in kinds, kinds
                self.received_before_validation += len(data)
        elif not self.validation_observed:
            self.sent_before_validation += len(data)
            assert self.sent_before_validation <= self.received_before_validation * 3, (
                self.received_before_validation, self.sent_before_validation)
            self.checkpoints.append([self.received_before_validation, self.sent_before_validation])
        super()._enqueue(direction, data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hq', type=Path, required=True)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-log-dir', type=Path)
    args = parser.parse_args()
    hq, runner = args.hq.resolve(strict=True), args.runner.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='hibana-amp-') as temporary:
        root = Path(temporary)
        certs = root/'certs'
        subprocess.run(['bash', str(runner/'certs.sh'), str(certs), '9'], cwd=runner,
                       check=True, capture_output=True, timeout=30)
        pem = (certs/'cert.pem').read_text()
        certificates = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
        chain_bytes = sum(len(ssl.PEM_cert_to_DER_cert(cert)) for cert in certificates)
        assert len(certificates) == 9 and chain_bytes >= 7500
        www, downloads = root/'www', root/'downloads'
        www.mkdir(); downloads.mkdir()
        body = bytes(range(256))*20
        (www/'test').write_bytes(body)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as port:
            port.bind(('127.0.0.1', 0)); address = port.getsockname()
        server = subprocess.Popen([str(hq), 'server', '--listen', f'{address[0]}:{address[1]}',
            '--cert', str(certs/'cert.pem'), '--key', str(certs/'priv.key'),
            '--www', str(www), '--max-requests', '1', '--timeout-seconds', '120'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr, client = '', '', None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(server.stderr, selectors.EVENT_READ)
                assert selector.select(5), 'server readiness timeout'
                ready = server.stderr.readline()
            assert 'listening on' in ready, ready
            with AmplificationProbe(address) as proxy:
                client = subprocess.run([str(hq), 'client', '--connect', f'{proxy.address[0]}:{proxy.address[1]}',
                    '--server-name', 'server', '--ca', str(certs/'ca.pem'), '--request', '/test',
                    '--downloads', str(downloads), '--timeout-seconds', '120'],
                    capture_output=True, text=True, timeout=125)
                stdout, stderr = server.communicate(timeout=5)
                result = {'scope':'native amplification diagnostic', 'official_interop_pass':False,
                    'chain_certificates':len(certificates), 'chain_der_bytes':chain_bytes,
                    'client_exit':client.returncode, 'server_exit':server.returncode,
                    'dropped_client_datagrams':proxy.stats['selected_client_datagrams_dropped'],
                    'validation_observed':proxy.validation_observed,
                    'received_before_validation':proxy.received_before_validation,
                    'sent_before_validation':proxy.sent_before_validation,
                    'checkpoints':proxy.checkpoints,
                    'file_sha256':hashlib.sha256((downloads/'test').read_bytes()).hexdigest() if (downloads/'test').exists() else None,
                    'expected_sha256':hashlib.sha256(body).hexdigest()}
                args.output.write_text(json.dumps(result, indent=2)+'\n')
                assert client.returncode == server.returncode == 0, (client.stderr, stderr)
                assert result['dropped_client_datagrams'] == 6 and result['validation_observed']
                assert result['file_sha256'] == result['expected_sha256']
                for raw in (client.stdout, stdout):
                    report = json.loads(raw)
                    assert report['tls_finished_authenticated'] and report['lifecycle_closed']
                print(json.dumps(result, indent=2))
        finally:
            if server.poll() is None:
                server.kill()
                stdout, stderr = server.communicate()
            if args.private_log_dir:
                args.private_log_dir.mkdir(parents=True, exist_ok=True)
                (args.private_log_dir/'server.log').write_text(stdout+'\n'+stderr)
                if client is not None:
                    (args.private_log_dir/'client.log').write_text(client.stdout+'\n'+client.stderr)


if __name__ == '__main__':
    main()
