#!/usr/bin/env python3
"""Real, unmodified native quiche peer. Never an official ns-3 verdict."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from test_direct_handshake_localhost import credentials
from test_native_amplification import AmplificationProbe
from udp_impairment import MultiEndpointProxy, EarlyWireProbe

def main():
 p=argparse.ArgumentParser()
 for n in ('hq','quiche-client','quiche-server','runner','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--direction',choices=['forward','reverse'],required=True)
 p.add_argument('--scenario',choices=['clean','handshakeloss','handshakecorruption','multiplexing','zerortt','amplificationlimit'],required=True)
 p.add_argument('--private-log-dir',type=Path)
 p.add_argument('--diagnostics',action='store_true')
 p.add_argument('--impairment-seed',type=int,default=20261009)
 p.add_argument('--parallel-clients',action='store_true',help='extra stress only; official quiche multiconnect invokes clients sequentially')
 a=p.parse_args();hq,qc,qs,runner=[x.resolve(strict=True) for x in (a.hq,a.quiche_client,a.quiche_server,a.runner)]
 multi=a.scenario in ('handshakeloss','handshakecorruption');early=a.scenario=='zerortt';amp=a.scenario=='amplificationlimit'
 count=50 if multi else 1999 if a.scenario=='multiplexing' else 40 if early else 1 if amp else 3
 size=1024 if multi else 32 if a.scenario=='multiplexing' or early else 5120 if amp else 4096
 timeout=300 if multi else 60
 env={**os.environ,'RUST_LOG':'quiche=trace,quiche_apps=info' if a.diagnostics else 'info'};env.pop('SSLKEYLOGFILE',None)
 result={'scope':'native independent quiche peer','official_pass':None,'scenario':a.scenario,'direction':a.direction,'passed':False,'hq_sha256':hashlib.sha256(hq.read_bytes()).hexdigest(),'quiche_client_sha256':hashlib.sha256(qc.read_bytes()).hexdigest(),'quiche_server_sha256':hashlib.sha256(qs.read_bytes()).hexdigest()}
 result['client_schedule']='simultaneous extra stress' if a.parallel_clients else 'official sequential quiche multiconnect' if multi and a.direction=='reverse' else 'candidate schedule'
 result['impairment_model']={'kind':'QNS-shaped random UDP mutations, Python RNG', 'seed':a.impairment_seed,'rate_percent':30,'max_burst':3,'delay_ms':15} if multi else None
 with tempfile.TemporaryDirectory(prefix='hibana-quiche-') as temporary:
  root=Path(temporary);(root/'www').mkdir();(root/'downloads').mkdir()
  if amp:
   subprocess.run(['bash',str(runner/'certs.sh'),str(root/'certs'),'9'],cwd=runner,env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   cert=root/'certs/cert.pem';key=root/'certs/priv.key';ca=root/'certs/ca.pem';name='server'
  else:
   credentials(root);cert=root/'server.pem';key=root/'server.key';ca=root/'ca.pem';name='localhost'
  names=[(str(i).zfill(3)+'x'*247) if early else f'body-{i}.bin' for i in range(count)]
  for i,n in enumerate(names):(root/'www'/n).write_bytes(bytes([i%251])*size)
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as port:port.bind(('127.0.0.1',0));address=port.getsockname()
  listen=f'{address[0]}:{address[1]}'
  if a.direction=='forward':
   command=[str(qs),'--listen',listen,'--cert',str(cert),'--key',str(key),'--root',str(root/'www'),'--no-retry','--http-version','HTTP/0.9','--idle-timeout','30000','--max-active-cids','8','--enable-active-migration','--disable-gso','--disable-pacing']
   if early:command+=['--early-data']
  else:
   command=[str(hq),'server','--listen',listen,'--cert',str(cert),'--key',str(key),'--www',str(root/'www'),'--timeout-seconds',str(timeout)]
   if multi:command+=['--session','multi','--connections','50','--max-requests','1']
   elif early:command+=['--session','resume','--early','buffered']
   else:command+=['--max-requests',str(count)]
  result['server_command']=command
  server_log=(root/'server.stderr').open('w+')
  server=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=server_log,text=True,env=env)
  clients=[];server_out=''
  try:
   deadline=time.monotonic()+5
   while time.monotonic()<deadline:
    if 'listening' in (root/'server.stderr').read_text().lower():break
    if server.poll() is not None:raise RuntimeError('server exited before readiness')
    time.sleep(0.01)
   else:raise TimeoutError('server startup')
   proxy=MultiEndpointProxy(address,client_endpoints=50,delay=0.015,burst=3,trace_routes=a.diagnostics,impairment_seed=a.impairment_seed,**{('drop_rate' if a.scenario=='handshakeloss' else 'corrupt_rate'):30}) if multi else AmplificationProbe(address) if amp else EarlyWireProbe(address,client_endpoints=2) if early else None
   with proxy if proxy else nullcontext():
    target=proxy.address if proxy else address;connect=f'{target[0]}:{target[1]}'
    if a.direction=='forward':
     cmd=[str(hq),'client','--connect',connect,'--server-name',name,'--ca',str(ca),'--downloads',str(root/'downloads'),'--timeout-seconds',str(timeout)]
     if multi:cmd+=['--session','multi']
     if early:cmd+=['--session','resume','--early','replay-safe']
     for n in names:cmd+=['--request','/'+n]
     clients=[subprocess.run(cmd,capture_output=True,text=True,timeout=timeout+5,env=env)]
    else:
     base=[str(qc),'--http-version','HTTP/0.9','--wire-version','1','--connect-to',connect,'--trust-origin-ca-pem',str(ca),'--dump-responses',str(root/'downloads'),'--idle-timeout','30000','--max-active-cids','8']
     def run(paths,extra=()):return subprocess.run(base+list(extra)+[f'https://{name}:{target[1]}/'+n for n in paths],capture_output=True,text=True,timeout=timeout+5,env=env)
     if multi:
      if a.parallel_clients:
       with ThreadPoolExecutor(max_workers=50) as pool:clients=list(pool.map(lambda n:run([n]),names))
      else:
       # Upstream apps/run_endpoint.sh: for req in $REQUESTS, run one client
       # to completion. Fifty simultaneous processes are a separate stress.
       clients=[run([n]) for n in names]
     elif early:
      session=['--session-file',str(root/'session.bin'),'--early-data']
      clients=[run(names[:1],session),run(names[1:],session)]
     else:clients=[run(names)]
    if a.direction=='reverse':server_out,_=server.communicate(timeout=timeout+5)
    result['proxy']=dict(proxy.stats) if proxy else None
    if multi and a.diagnostics:result['route_trace']=proxy.route_trace
    result['client_exits']=[x.returncode for x in clients]
    result['files']=[{'name':n,'expected_sha256':hashlib.sha256((root/'www'/n).read_bytes()).hexdigest(),'received_sha256':hashlib.sha256((root/'downloads'/n).read_bytes()).hexdigest() if (root/'downloads'/n).exists() else None} for n in names]
    raw=clients[0].stdout if a.direction=='forward' else server_out
    result['candidate']=next((json.loads(x) for x in reversed(raw.splitlines()) if x.startswith('{')),None)
    assert all(x.returncode==0 for x in clients),'client exit'
    assert all(x['expected_sha256']==x['received_sha256'] for x in result['files']),'file mismatch'
    report=result['candidate'];assert report is not None,'candidate terminal missing'
    result['strict_lifecycle_pass'] = bool(report['http_transfer_complete'] and report['lifecycle_closed'] and report['idle_expired_connections']==0)
    assert report['tls_finished_authenticated'] and report['resources_retired'],'candidate authentication/retirement'
    # Pinned runner HandshakeLoss/HandshakeCorruption checks 50 handshakes
    # and received file contents, not receipt of every best-effort CLOSE.
    # Preserve actual idle/close observations; never rewrite the endpoint report.
    result['acceptance_basis'] = 'authenticated connection count and receiver file hashes; close observed separately' if multi else 'authenticated transfer and clean candidate lifecycle'
    if not multi:assert result['strict_lifecycle_pass'],'candidate lifecycle'
    assert report['files_completed']==count and report['connections']==(50 if multi else 2 if early else 1),'candidate count'
    if a.direction=='reverse':assert server.returncode==0,'server exit'
    if early:
     assert report['resumed'] and report['early_finished_streams']>0,'actual early data absent'
     assert proxy.stats['zero_rtt_packets']>0 and proxy.stats['unclassified_client_datagrams']==0,'early packet evidence incomplete'
     assert proxy.stats['one_rtt_protected_payload_upper_bound']<=5000,'too much request data fell back to 1-RTT'
     if a.direction=='reverse':assert report['early_accepted_packets']>0
    if amp:assert proxy.stats['selected_client_datagrams_dropped']==6 and proxy.validation_observed,'amplification injection absent'
    result['passed']=True
  except Exception as error:result['error']=repr(error)
  finally:
   if server.poll() is None:server.terminate()
   try:out,_=server.communicate(timeout=5);server_out=server_out or out
   except subprocess.TimeoutExpired:server.kill();out,_=server.communicate();server_out=server_out or out
   server_log.close()
   result['server_exit']=server.returncode
   if a.private_log_dir:
    a.private_log_dir.mkdir(parents=True,exist_ok=False)
    (a.private_log_dir/'server.stderr').write_text((root/'server.stderr').read_text());(a.private_log_dir/'server.stdout').write_text(server_out)
    for i,x in enumerate(clients):
     (a.private_log_dir/f'client-{i}.stderr').write_text(x.stderr);(a.private_log_dir/f'client-{i}.stdout').write_text(x.stdout)
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
 print(a.scenario,a.direction,'PASS' if result['passed'] else result.get('error'))
 return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
