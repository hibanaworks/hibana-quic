#!/usr/bin/env python3
"""All selected catalog scenarios against two owned native peers.

Each pair yields two role observations, not two independent interoperability
verdicts. The pinned reference matrix remains a separate unexecuted gate.
"""
import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile
import time
from test_direct_handshake_localhost import credentials
from udp_impairment import UdpProxy, VersionWireProbe, RebindingWireProbe

ROOT = Path(__file__).resolve().parents[3]

class HandshakeFault(UdpProxy):
    def __init__(self, server, corruption=False):
        super().__init__(server, delay=0.015)
        self.corruption = corruption
    def _enqueue(self, direction, data):
        if data and data[0] & 0x80 and self.stats[direction+'_selected_handshake_faults'] < 3:
            self.stats[direction+'_selected_handshake_faults'] += 1
            if not self.corruption:
                return
            altered = bytearray(data); altered[-1] ^= 1; data = bytes(altered)
        super()._enqueue(direction, data)

def run_case(binary, case, output):
    result = {'case':case, 'scope':'native same-implementation scenario', 'official_pass':None,
              'client':None,'server':None,'passed':False}
    if case == 'amplificationlimit':
        result['blocked'] = 'Unchanged runner nine-certificate generator and pinned independent peer are absent; existing recovery/amplification Rust tests are only partial evidence.'
        output.write_text(json.dumps(result,indent=2)+'\n'); return result
    with tempfile.TemporaryDirectory(prefix='hibana-catalog-') as temporary:
        root=Path(temporary);credentials(root);(root/'www').mkdir()
        sizes = [4096,0]
        if case in ('transfer','http3'): sizes=[2<<20,3<<20,5<<20]
        if case in ('longrtt','handshake','retry','v2','ipv6','ecn'):sizes=[1024]
        if case in ('transferloss','transfercorruption','chacha20','keyupdate'):sizes=[3<<20]
        if case in ('blackhole','rebind-port','rebind-addr'):sizes=[10<<20]
        if case=='connectionmigration':sizes=[2<<20]
        if case=='multiplexing':sizes=[32]*1999
        if case in ('resumption','zerortt'):sizes=[32,33]
        names=[f'body-{i}.bin' for i in range(len(sizes))]
        for i,(name,size) in enumerate(zip(names,sizes)):
            (root/'www'/name).write_bytes(bytes([i%251])*size)
        timeout=180
        server_args=[str(binary),'server','--listen','[::1]:0' if case=='ipv6' else '127.0.0.1:0','--cert',str(root/'server.pem'),'--key',str(root/'server.key'),'--www',str(root/'www'),'--timeout-seconds',str(timeout)]
        client_extra=[]
        if case not in ('resumption','zerortt'):server_args+=['--max-requests',str(len(names))]
        if case=='chacha20':server_args+=['--cipher','chacha20'];client_extra+=['--cipher','chacha20']
        if case=='http3':server_args+=['--http','3'];client_extra+=['--http','3']
        if case in ('resumption','zerortt'):server_args+=['--session','resume'];client_extra+=['--session','resume']
        if case=='zerortt':server_args+=['--early','buffered'];client_extra+=['--early','replay-safe']
        if case=='keyupdate':client_extra+=['--key-update','once']
        if case=='retry':server_args+=['--retry','required']
        if case=='v2':server_args+=['--version','2'];client_extra+=['--version','2']
        if case=='connectionmigration':
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:
                reserve.bind(('127.0.0.1',0));preferred=reserve.getsockname()[1]
            server_args+=['--preferred-port',str(preferred)]
        log=(root/'server.stderr').open('w+')
        server=subprocess.Popen(server_args,stdout=subprocess.PIPE,stderr=log,text=True)
        try:
            deadline=time.monotonic()+5;ready=''
            while time.monotonic()<deadline:
                ready=(root/'server.stderr').read_text().splitlines()
                if ready:break
                time.sleep(0.01)
            assert ready and ready[0].startswith('direct Hibana server listening on '),ready
            address=ready[0].split(' on ',1)[1];host,port=address.rsplit(':',1);host=host.strip('[]');port=int(port)
            peer=(host,port)
            proxy=None
            if case=='longrtt':proxy=UdpProxy(peer,delay=0.75)
            elif case=='transferloss':proxy=UdpProxy(peer,delay=0.015,drop_every=10,burst=3)
            elif case=='transfercorruption':proxy=UdpProxy(peer,delay=0.015,corrupt_every=10,burst=3)
            elif case in ('handshakeloss','handshakecorruption'):proxy=HandshakeFault(peer,case=='handshakecorruption')
            elif case=='blackhole':proxy=UdpProxy(peer,blackhole_after_bytes=4<<20,blackhole_seconds=2)
            elif case in ('retry','v2'):proxy=VersionWireProbe(peer)
            elif case in ('rebind-port','rebind-addr'):proxy=RebindingWireProbe(peer,change_address=case=='rebind-addr')
            with proxy if proxy else nullcontext():
                if proxy:address=f'{proxy.address[0]}:{proxy.address[1]}'
                command=[str(binary),'client','--connect',address,'--server-name','localhost','--ca',str(root/'ca.pem'),'--downloads',str(root/'downloads'),'--timeout-seconds',str(timeout),*client_extra]
                for name in names:command+=['--request','/'+name]
                result['server_command']=server_args;result['client_command']=command
                client=subprocess.run(command,capture_output=True,text=True,timeout=timeout+5)
                stdout,_=server.communicate(timeout=timeout+5)
                result.update(client_exit=client.returncode,server_exit=server.returncode,client_stderr=client.stderr,server_stderr=(root/'server.stderr').read_text(),proxy=dict(proxy.stats) if proxy else None)
                for label,raw in [('client',client.stdout),('server',stdout)]:
                    try:result[label]=json.loads(raw)
                    except ValueError:result[label+'_stdout']=raw
                result['files']=[{'name':n,'expected_sha256':hashlib.sha256((root/'www'/n).read_bytes()).hexdigest(),'received_sha256':hashlib.sha256((root/'downloads'/n).read_bytes()).hexdigest() if (root/'downloads'/n).exists() else None} for n in names]
                assert client.returncode==server.returncode==0,'nonzero process exit'
                assert all(x['expected_sha256']==x['received_sha256'] for x in result['files']),'file mismatch'
                for label in ('client','server'):
                    endpoint=result[label]
                    assert endpoint['tls_finished_authenticated'] and endpoint['http_transfer_complete'] and endpoint['lifecycle_closed'] and endpoint['resources_retired'] and endpoint['idle_expired_connections']==0,(label,'incomplete lifecycle')
                    assert endpoint['files_completed']==len(names),(label,'file count')
                if case in ('resumption','zerortt'):assert all(result[x]['resumed'] and result[x]['connections']==2 for x in ('client','server'))
                if case=='zerortt':assert result['server']['early_accepted_packets']>0 and result['server']['early_finished_streams']>0,'no actual early request'
                if case=='keyupdate':assert all(result[x]['key_generation']>=1 for x in ('client','server')),'no observed key update'
                if case=='retry':assert proxy.stats['to_client_v1_type3']>0,'no Retry'
                if case=='v2':assert proxy.stats['to_client_v6b3343cf_type0']>0 and proxy.stats['to_server_v6b3343cf_type2']>0,'no actual v2 negotiation'
                if case in ('handshakeloss','handshakecorruption'):assert all(proxy.stats[x+'_selected_handshake_faults']==3 for x in ('to_server','to_client'))
                if case=='blackhole':assert sum(v for k,v in proxy.stats.items() if k.endswith('_blackhole_dropped'))>0,'blackhole not exercised'
                if case in ('rebind-port','rebind-addr'):assert proxy.stats['actual_rebindings']==2 and result['server']['different_path_datagrams_observed']>0,'rebinding not observed'
                if case=='connectionmigration':assert result['client']['preferred_address_used'] and result['client']['validated_paths']>=1,'preferred path not validated'
                if case=='ecn':assert all(result[x]['ecn_received_packets']>0 and result[x]['ecn_validated_packets']>0 for x in ('client','server')),'ECN not actually validated'
                result['passed']=True
        except Exception as error:result['error']=repr(error)
        finally:
            if server.poll() is None:server.kill();server.communicate()
            log.close()
    output.write_text(json.dumps(result,indent=2)+'\n');return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--case');a=p.parse_args()
    catalog=json.loads((ROOT/'tools/ci/interop-request.json').read_text());cases=[c for g in catalog['groups'] for c in g['cases']]
    if a.case:
        assert a.case in cases;cases=[a.case]
    a.output.mkdir(parents=True,exist_ok=True);binary=a.binary.resolve(strict=True)
    summary={'scope':'local same-implementation analogues; official reference directions unexecuted','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'catalog_scenarios':22,'official_cells':44,'official_passed':0,'cases':[]}
    for case in cases:
        start=time.monotonic();r=run_case(binary,case,a.output/(case+'.json'))
        summary['cases'].append({'case':case,'passed':r['passed'],'blocked':r.get('blocked'),'error':r.get('error'),'elapsed_seconds':time.monotonic()-start,'observed_roles':[x for x in ('client','server') if r.get(x) is not None]})
        (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(case,'PASS' if r['passed'] else 'BLOCKED' if r.get('blocked') else 'FAIL',flush=True)
    return 0 if all(x['passed'] for x in summary['cases']) else 1
if __name__=='__main__':raise SystemExit(main())
