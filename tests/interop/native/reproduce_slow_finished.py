"""Finite 2.2-second RTT and three Finished losses; not an interop cell."""
import json
from pathlib import Path
import sys

import test_direct_parallel_localhost as fixture
from udp_impairment import MultiEndpointProxy


class SlowFinishedProxy(MultiEndpointProxy):
    def __init__(self, server, **options):
        for name in ('drop_every', 'corrupt_every', 'drop_rate', 'corrupt_rate'):
            options.pop(name, None)
        options['delay'] = 1.1
        super().__init__(server, **options)
        self.finished_datagrams = 0

    def _enqueue(self, direction, data):
        drop = False
        # Only this fixture's v1 long-header shape is inspected. Payloads and
        # secrets remain opaque; ACK-only Handshake datagrams are forwarded.
        if (direction == 'to_server' and len(data) > 60
                and data[0] & 0x80 and (data[0] >> 4) & 3 == 2):
            self.finished_datagrams += 1
            drop = self.finished_datagrams <= 3
        if drop:
            self.stats['finite_dropped_client_finished'] += 1
        self.drop_every = 1 if drop else 0
        super()._enqueue(direction, data)
        self.drop_every = 0


if __name__ == '__main__':
    fixture.MultiEndpointProxy = SlowFinishedProxy
    output = Path(sys.argv[sys.argv.index('--output') + 1])
    try:
        fixture.main()
    finally:
        if output.exists():
            report = json.loads(output.read_text())
            report['impairment_model'] = 'finite three client Finished-shaped losses, 1100 ms each direction; not QNS'
            report['finite_fault_recovery_passed'] = (
                report['client_exit'] == report['server_exit'] == 0
                and all(f['expected_sha256'] == f['received_sha256'] for f in report['files'])
                and report['proxy'].get('finite_dropped_client_finished') == 3)
            output.write_text(json.dumps(report, indent=2) + '\n')
            assert report['finite_fault_recovery_passed'], 'finite slow Finished recovery/injection failed'
