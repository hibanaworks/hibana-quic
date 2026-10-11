#!/usr/bin/env python3
"""Actual two-connection first-file/remaining-files HTTP/0.9 regression."""
import argparse,importlib.util,json,os,subprocess,tempfile
from pathlib import Path
S=importlib.util.spec_from_file_location('hq_helpers',Path(__file__).with_name('test_hq_localhost.py'));H=importlib.util.module_from_spec(S);S.loader.exec_module(H)
def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cipher-suite',choices=['default','aes128','chacha20'],default='default');a=p.parse_args();binary=a.binary.resolve();os.umask(0o077)
 report={'status':'FAILED','scope':'two-connection-first-then-remaining-files','binary_sha256':H.sha256(binary),'script_sha256':H.sha256(Path(__file__)),'cipher_policy':a.cipher_suite}
 try:
  with tempfile.TemporaryDirectory(prefix='hq-resumption-many-') as d:
   root=Path(d);www=root/'www';(www/'nested').mkdir(parents=True);H.certificates(root)
   paths=['empty.bin','five-mib.bin','nested/hello.txt']+[f'small-{i}.txt' for i in range(8)]
   (www/paths[0]).write_bytes(b'');(www/paths[1]).write_bytes(bytes(range(256))*(5*4096));(www/paths[2]).write_bytes(b'more than four live-slot lifetimes\n')
   for i,path in enumerate(paths[3:]):(www/path).write_bytes((f'stream-{i}\n'*(i+1)).encode())
   server,addr=H.launch_server(binary,root,len(paths),45,['--max-connections','2','--cipher-suite',a.cipher_suite])
   command=[str(binary),'client','--connect',addr,'--server-name','localhost','--ca',str(root/'ca.pem'),'--downloads',str(root/'downloads'),'--connections','2','--timeout-seconds','45','--cipher-suite',a.cipher_suite]
   for name in paths:command+=['--request','/'+name]
   try:
    client=subprocess.run(command,capture_output=True,text=True,timeout=95);stdout,stderr=server.communicate(timeout=50)
    report.update(client_exit=client.returncode,server_exit=server.returncode,client=json.loads(client.stdout),server=json.loads(stdout),client_stderr=client.stderr,server_stderr=stderr)
    assert client.returncode==server.returncode==0,report
    hashes={}
    for name in paths:
     expected=H.sha256(www/name);actual=H.sha256(root/'downloads'/name);assert expected==actual;hashes[name]={'bytes':(www/name).stat().st_size,'sha256':actual}
    report['files']=hashes
    for role in ['client','server']:
     connections=report[role]['connections'];assert [r['files_completed'] for r in connections]==[1,10],report
     assert [r['resumed'] for r in connections]==[False,True],report
     assert all(r['lifecycle_closed'] for r in connections),report
     assert all(r['cipher_policy']==a.cipher_suite for r in connections),report
     if a.cipher_suite!='default':assert all(r['negotiated_suite']==(0x1303 if a.cipher_suite=='chacha20' else 0x1301) for r in connections),report
     assert connections[1]['connection_generation']==connections[0]['connection_generation']+1,report
     assert report[role]['files_completed']==11 and report[role]['body_bytes']==sum(f['bytes'] for f in hashes.values()),report
    assert not list((root/'downloads').rglob('.hibana-*.part'))
    report['status']='PASSED'
   finally:
    if server.poll() is None:server.kill();server.communicate()
 finally:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
