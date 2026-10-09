#!/usr/bin/env python3
"""Independent direct owners with real file hashes and retirement, not interop."""
import argparse
from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
from udp_impairment import MultiEndpointProxy
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fixture', HERE / 'test_direct_handshake_localhost.py')
HELP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELP)
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--connections', type=int, default=50)
    parser.add_argument('--impairment', choices=('none','loss','corruption'), default='none')
    parser.add_argument('--timeout-seconds', type=int, default=120)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-log-dir', type=Path)
    parser.add_argument('--trace-routes', action='store_true')
    parser.add_argument('--impairment-model', choices=('periodic','random'), default='periodic')
    parser.add_argument('--impairment-seed', type=int, default=20261009)
    parser.add_argument('--loss-scope', choices=('global','per-connection'), default='global')
    args = parser.parse_args()
    if not 1 <= args.connections <= 64: parser.error('connections must be 1..64')
    if args.impairment_model == 'random' and args.loss_scope != 'global': parser.error('random QNS model is global per direction')
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='hibana-parallel-direct-') as tmp:
        root = Path(tmp); HELP.credentials(root); (root/'www').mkdir()
        names = [f'body-{i}.bin' for i in range(args.connections)]
        for i,name in enumerate(names): (root/'www'/name).write_bytes(bytes([i % 251])*1024)
        command = [str(binary),'server','--listen','127.0.0.1:0','--cert',str(root/'server.pem'),'--key',str(root/'server.key'),'--www',str(root/'www'),'--max-requests','1','--session','multi','--connections',str(args.connections),'--timeout-seconds',str(args.timeout_seconds)]
        server_log = (root/'server.stderr').open('w+')
        server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=server_log, text=True)
        try:
            deadline=time.monotonic()+5
            ready=''
            while not ready and time.monotonic()<deadline:
                with (root/'server.stderr').open() as reader: ready=reader.readline().strip()
                if not ready: time.sleep(0.01)
            assert ready,'server startup timeout' 
            prefix='direct Hibana server listening on '
            assert ready.startswith(prefix),ready
            host,port=ready[len(prefix):].rsplit(':',1)
            options={'loss_scope':args.loss_scope,'trace_routes':args.trace_routes,'client_endpoints':args.connections,'delay':0.015,('drop_every' if args.impairment=='loss' else 'corrupt_every'):10,'burst':3}
            if args.impairment_model == 'random':
                options.pop('drop_every' if args.impairment=='loss' else 'corrupt_every')
                options['drop_rate' if args.impairment=='loss' else 'corrupt_rate']=30
                options['impairment_seed']=args.impairment_seed
            context=MultiEndpointProxy((host,int(port)),**options) if args.impairment!='none' else nullcontext(None)
            with context as proxy:
                address=proxy.address if proxy else (host,int(port))
                command=[str(binary),'client','--connect',f'{address[0]}:{address[1]}','--server-name','localhost','--ca',str(root/'ca.pem'),'--downloads',str(root/'downloads'),'--session','multi','--timeout-seconds',str(args.timeout_seconds)]
                for name in names: command += ['--request',f'https://localhost:{address[1]}/{name}']
                started=time.monotonic()
                client=subprocess.run(command,capture_output=True,text=True,timeout=args.timeout_seconds+5)
                client_elapsed=time.monotonic()-started
                server_out,_=server.communicate(timeout=args.timeout_seconds+5)
                server_err=(root/'server.stderr').read_text()
                elapsed=time.monotonic()-started
            if args.private_log_dir:
                args.private_log_dir.mkdir(parents=True, exist_ok=False)
                for name, data in [('client.stdout', client.stdout),
                                   ('client.stderr', client.stderr),
                                   ('server.stdout', server_out),
                                   ('server.stderr', server_err)]:
                    (args.private_log_dir/name).write_text(data)
            files=[]
            for name in names:
                source=root/'www'/name;dest=root/'downloads'/name
                files.append({'bytes':source.stat().st_size,'expected_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'received_sha256':hashlib.sha256(dest.read_bytes()).hexdigest() if dest.exists() else None})
            report={'scope':'direct-native-independent-connections','official_interop_pass':False,'connections':args.connections,'impairment':args.impairment,'loss_scope':args.loss_scope,'impairment_model':args.impairment_model,'impairment_seed':args.impairment_seed,'client_exit':client.returncode,'server_exit':server.returncode,'client_seconds':client_elapsed,'all_retired_seconds':elapsed,'files':files,'proxy':dict(proxy.stats) if proxy else None}
            if proxy is not None and args.trace_routes: report['route_trace'] = proxy.route_trace
            for label,raw in [('client',client.stdout),('server',server_out)]:
                try: report[label]=json.loads(raw)
                except ValueError: report[label]=None
            args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
            assert client.returncode==server.returncode==0,(client.stderr,server_err)
            assert all(f['expected_sha256']==f['received_sha256'] for f in files)
            for label in ['client','server']:
                result=report[label]
                assert result['connections']==args.connections and result['resources_retired'] and result['http_transfer_complete'],result
                assert result['lifecycle_closed'] and result['idle_expired_connections']==0,result
            assert not list((root/'downloads').rglob('.hibana-*.part'))
            print(json.dumps({'connections':args.connections,'impairment':args.impairment,'client_seconds':client_elapsed,'all_retired_seconds':elapsed,'passed':True}))
        finally:
            if server.poll() is None: server.kill();server.communicate()
            server_log.close()
if __name__=='__main__':main()
