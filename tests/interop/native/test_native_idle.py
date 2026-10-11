#!/usr/bin/env python3
"""Real idle retirement after dropping late client feedback, not a runner verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from test_native_neqo_transfer import fixture, unused_port, wait_ready, stop
from udp_impairment import UdpProxy

class MissingFeedback(UdpProxy):
    def __init__(self, server):
        super().__init__(server)
        self.short_packets = 0
    def _enqueue(self, direction, data):
        if direction == 'to_server' and data and not data[0] & 0x80:
            self.short_packets += 1
            if self.short_packets > 2:
                self.stats['feedback_dropped'] += 1
                return
        super()._enqueue(direction, data)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--hq', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args(); hq=args.hq.resolve()
    report={'scope':'native idle-retirement fault test', 'official_interop_pass':False}
    try:
        with tempfile.TemporaryDirectory(prefix='hibana-native-idle-') as tmp:
            root=Path(tmp); fixture.credentials(root)
            www=root/'www'; www.mkdir(); (www/'body').write_bytes(bytes(range(256))*16)
            downloads=root/'downloads'; downloads.mkdir(); port=unused_port(False)
            log=root/'server.log'
            with log.open('w') as stream:
                server=subprocess.Popen([str(hq),'server','--listen',f'127.0.0.1:{port}','--cert',str(root/'server.pem'),'--key',str(root/'server.key'),'--www',str(www),'--timeout-seconds','75'],stdout=stream,stderr=stream,text=True)
                client=None
                try:
                    wait_ready(server,log)
                    with MissingFeedback(('127.0.0.1',port)) as proxy:
                        client=subprocess.Popen([str(hq),'client','--connect',f'127.0.0.1:{proxy.address[1]}','--server-name','localhost','--ca',str(root/'ca.pem'),'--downloads',str(downloads),'--request','/body','--timeout-seconds','65'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                        server.wait(timeout=50)
                        records=[json.loads(line) for line in log.read_text().splitlines() if line.startswith('{')]
                        report.update(server_exit=server.returncode,records=records,feedback_dropped=proxy.stats['feedback_dropped'])
                        assert server.returncode == 0, log.read_text()
                        assert records, log.read_text()
                        actual=records[-1]
                        assert actual['status'] == 'idle-expired' and actual['scope'] == 'connection-retirement', actual
                        assert actual['resources_retired'] and actual['idle_expired_connections'] == 1, actual
                        assert not actual['lifecycle_closed'] and not actual['http_transfer_complete'], actual
                        assert proxy.stats['feedback_dropped'] > 0
                        report['idle_retirement_verified']=True
                finally:
                    if client is not None: stop(client)
                    stop(server)
    finally:
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
if __name__=='__main__': main()
