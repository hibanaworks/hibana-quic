"""Diagnostic-only finite fault schedule. Not an interop qualification cell."""
from pathlib import Path
import sys, time, json
import test_direct_parallel_localhost as fixture
from udp_impairment import MultiEndpointProxy

class DelayedFinishedProxy(MultiEndpointProxy):
    def __init__(self, server, **options):
        options.pop('drop_every', None); options.pop('corrupt_every', None)
        options.pop('drop_rate', None); options.pop('corrupt_rate', None)
        super().__init__(server, **options)
        self.dropped_handshakes = 0
        self.forwarded_handshake_at = None
        self.dropped_application = 0
    def _enqueue(self, direction, data):
        drop = False
        # This test client's generated v1 Finished datagram has a Handshake
        # long header and >60 bytes. No payload or keys are read or logged.
        if direction == 'to_server' and len(data)>60 and data[0]&0x80 and (data[0]>>4)&3 == 2:
            if self.dropped_handshakes < 7:
                self.dropped_handshakes += 1
                self.stats['diagnostic_handshake_datagrams_dropped'] += 1
                drop = True
            elif self.forwarded_handshake_at is None:
                self.forwarded_handshake_at = time.monotonic()
        elif (direction == 'to_server' and data and not data[0]&0x80
              and self.forwarded_handshake_at is not None
              and len(data) in (33,49,50) and self.dropped_application < APPLICATION_DROPS):
            self.dropped_application += 1
            self.stats['diagnostic_application_datagrams_dropped'] += 1
            drop = True
        self.drop_every = 1 if drop else 0
        super()._enqueue(direction, data)
        self.drop_every = 0

APPLICATION_DROPS=int(sys.argv.pop(1))
fixture.MultiEndpointProxy=DelayedFinishedProxy
output=Path(sys.argv[sys.argv.index('--output')+1])
try:
    fixture.main()
finally:
    if output.exists():
        report=json.loads(output.read_text())
        report['impairment_model']='diagnostic finite: first seven client Handshake datagrams over 60B, then selected short datagrams; not periodic/random/QNS'
        report['diagnostic_requested_application_drops']=APPLICATION_DROPS
        report['finite_fault_recovery_passed'] = (
            report['client_exit'] == report['server_exit'] == 0
            and all(f['expected_sha256'] == f['received_sha256'] for f in report['files'])
            and report['proxy'].get('diagnostic_handshake_datagrams_dropped') == 7
            and report['proxy'].get('diagnostic_application_datagrams_dropped', 0) == APPLICATION_DROPS)
        output.write_text(json.dumps(report,indent=2)+'\n')
        assert report['finite_fault_recovery_passed'], 'finite key-wait loss recovery/injection failed'
