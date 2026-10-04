#!/usr/bin/env python3
"""Pinned unmodified Neqo CLI/native UDP diagnostics, never QNS verdicts.
Neqo server's ordinary mode generates zero payloads for numeric paths. Reverse
Hibana server uses nonzero deterministic files. This does not reproduce the
QNS simulator topology, impairments, pcap gates, or random forward file fixtures.
"""
import argparse, hashlib, importlib.util, json, os, selectors, socket, subprocess, tempfile, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixture',HERE/'test_direct_handshake_localhost.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(c,env,cwd=None):return subprocess.run(c,env=env,cwd=cwd,capture_output=True,text=True,timeout=70)
def checked(c,env):
 r=run(c,env);assert r.returncode==0,(Path(c[0]).name,r.stderr)
def stop(p):
 if p.poll() is None:p.terminate()
 try:p.wait(timeout=3)
 except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def main():
 ap=argparse.ArgumentParser()
 for k in ('hq','neqo-client','neqo-server','nss','output'):ap.add_argument('--'+k,type=Path,required=True)
 args=ap.parse_args();hq=args.hq.resolve();nc=args.neqo_client.resolve();ns=args.neqo_server.resolve();nss=args.nss.resolve()
 env=os.environ.copy();env['RUST_LOG']='debug';env['LD_LIBRARY_PATH']=str(nss/'lib');env.pop('SSLKEYLOGFILE',None)
 report={'scope':'native-peer-diagnostics','official_interop_pass':False,'coverage_gaps':['no simulator or impairment','no packet-trace verdicts','forward ordinary-Neqo generated-zero payloads'],'binaries':{k:sha(v) for k,v in [('hq',hq),('neqo-client',nc),('neqo-server',ns)]},'runs':[]}
 with tempfile.TemporaryDirectory(prefix='hibana-native-peer-') as tmp:
  root=Path(tmp);fixture.credentials(root);db=root/'db';db.mkdir()
  checked([str(nss/'bin/certutil'),'-N','-d',str(db),'--empty-password'],env)
  checked(['openssl','pkcs12','-export','-inkey',str(root/'server.key'),'-in',str(root/'server.pem'),'-certfile',str(root/'ca.pem'),'-name','native-peer','-passout','pass:','-out',str(root/'fixture.p12')],env)
  checked([str(nss/'bin/pk12util'),'-i',str(root/'fixture.p12'),'-d',str(db),'-W','','-K',''],env)
  for direction in ('baseline','forward','reverse'):
   dst=root/direction;dst.mkdir();www=root/('www-'+direction);www.mkdir();pnum=port();address=f'127.0.0.1:{pnum}'
   sizes=[2<<20,3<<20,5<<20];names=[str(n) for n in sizes]
   for n,name in zip(sizes,names):
    (www/name).write_bytes(bytes([0 if direction!='reverse' else 37])*n)
   if direction=='reverse':sc=[str(hq),'server','--listen',address,'--cert',str(root/'server.pem'),'--key',str(root/'server.key'),'--www',str(www),'--max-requests','3','--timeout-seconds','60']
   else:sc=[str(ns),'-a','hq-interop','-Q','1','-d',str(db),'-k','native-peer','--idle','60',address]
   # Logs remain in the private temporary fixture, not in the source tree.
   with (root/'server.log').open('w+') as log:
    server=subprocess.Popen(sc,env=env,stdout=log,stderr=log,text=True)
    try:
     deadline=time.monotonic()+10;seen=''
     while 'listening' not in seen.lower() and 'waiting for connection' not in seen.lower():
      assert server.poll() is None,('server stopped',seen[-1000:])
      assert time.monotonic()<deadline,('server readiness timeout',seen[-1000:])
      time.sleep(0.02);seen=(root/'server.log').read_text(errors='replace')
     urls=[f'https://localhost:{pnum}/{name}' for name in names]
     if direction=='forward':
      command=[str(hq),'client','--connect',address,'--server-name','localhost','--ca',str(root/'ca.pem'),'--downloads',str(dst),'--timeout-seconds','60']
      for url in urls:command+=['--request',url]
     else:command=[str(nc),'--qns-test','transfer','-Q','1','--ipv4-only','--output-dir',str(dst),'--idle','60']+urls
     result=run(command,env)
     files=[{'name':name,'bytes':n,'expected_sha256':sha(www/name),'received_sha256':sha(dst/name) if (dst/name).is_file() else None} for name,n in zip(names,sizes)]
     row={'direction':direction,'client_exit':result.returncode,'files':files,'client_stderr':result.stderr[-2000:],'server_diagnostics':[line for line in (root/'server.log').read_text(errors='replace').splitlines() if any(k in line.lower() for k in ['path =','stream','error','closing','closed'])][-100:]}
     if direction=='forward' and result.stdout.strip():row['candidate']=json.loads(result.stdout)
     report['runs'].append(row)
     args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
     assert result.returncode==0,row
     assert all(x['expected_sha256']==x['received_sha256'] for x in files),row
    finally:stop(server)
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
