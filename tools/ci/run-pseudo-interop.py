#!/usr/bin/env python3
"""Native loopback/fault matrix. Never emits an official interop verdict.
Requires an already-built hq, Python stdlib and the system OpenSSL CLI.
The report retains every command, exit code, artifact and binary SHA-256.
"""
import argparse,hashlib,json,subprocess,sys,time,os,signal
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--loss-scope',choices=('global','per-connection'),default='global')
a=p.parse_args();binary=a.binary.resolve(strict=True);out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[2];tests=root/'host/tests'
cases=[
 ('proxy-unit',['-m','unittest','discover','-s',str(tests),'-p','test_udp_impairment.py'],30),
 ('handshake',[str(tests/'test_direct_handshake_localhost.py'),'--binary',str(binary),'--output',str(out/'handshake.json')],60),
 ('transfer',[str(tests/'test_direct_hq_localhost.py'),'--binary',str(binary),'--output',str(out/'transfer.json')],150),
 ('large-transfer',[str(tests/'test_direct_hq_localhost.py'),'--binary',str(binary),'--large','--timeout-seconds','120','--output',str(out/'large-transfer.json')],260),
 ('resumption',[str(tests/'test_direct_resumption_localhost.py'),'--binary',str(binary),'--output',str(out/'resumption.json')],150),
 ('resumption-40',[str(tests/'test_direct_resumption_localhost.py'),'--binary',str(binary),'--files','40','--output',str(out/'resumption-40.json')],260),
 ('version-negotiation',[str(tests/'test_native_version_negotiation.py'),'--hq',str(binary),'--output',str(out/'version-negotiation.json')],120),
 ('idle',[str(tests/'test_native_idle.py'),'--hq',str(binary),'--output',str(out/'idle.json')],180),
]
for name,protocol,cipher in [('transfer-chacha','hq','chacha20'),('http3-aes','3','aes128'),('http3-chacha','3','chacha20')]:
 cases.append((name,[str(tests/'test_direct_hq_localhost.py'),'--binary',str(binary),'--http',protocol,'--cipher',cipher,'--output',str(out/(name+'.json'))],150))
for impairment in ['none','loss','corruption']:
 cases.append(('connections-50-'+impairment,[str(tests/'test_direct_parallel_localhost.py'),'--binary',str(binary),'--connections','50','--impairment',impairment,'--loss-scope',a.loss_scope,'--timeout-seconds','180','--output',str(out/('connections-50-'+impairment+'.json'))],400))
report={'scope':'native same-implementation QUIC loopback/fault matrix','official_interop_runner_verdict':None,'independent_quic_peer':False,'loss_scope':a.loss_scope,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'cases':[]}
for name,args,timeout in cases:
 start=time.monotonic();cmd=[sys.executable,*args]
 try:
  process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  stdout,stderr=process.communicate(timeout=timeout)
  code=process.returncode;log=stdout+stderr
 except subprocess.TimeoutExpired as e:
  os.killpg(process.pid,signal.SIGTERM)
  try: stdout,stderr=process.communicate(timeout=5)
  except subprocess.TimeoutExpired:
   os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate()
  code=None;log='HARNESS TIMEOUT\n'+str(e)+'\n'+stdout+stderr
 (out/(name+'.log')).write_text(log)
 report['cases'].append({'name':name,'command':cmd,'exit_code':code,'passed':code==0,'elapsed_seconds':time.monotonic()-start})
 report['passed']=all(c['passed'] for c in report['cases'])
 (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
 print(name,'PASS' if code==0 else 'FAIL',flush=True)
sys.exit(0 if report['passed'] else 1)
