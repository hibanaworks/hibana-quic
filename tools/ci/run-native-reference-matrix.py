#!/usr/bin/env python3
"""Execute all 44 catalog cells with native independent peers, without Docker.

No official runner verdict is produced. Per-cell commands, actual sources and
binary hashes are retained; none are replaced by same-implementation results.
"""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser()
for name in ['hq','neqo-client','neqo-server','nss','quiche-client','quiche-server','runner','output']:p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[2];tests=root/'host/tests';out=a.output.resolve()
if out.exists() and any(out.iterdir()):p.error('--output must be a new or empty attempt directory')
out.mkdir(parents=True,exist_ok=True)
files={k:getattr(a,k.replace('-','_')).resolve(strict=True) for k in ['hq','neqo-client','neqo-server','nss','quiche-client','quiche-server','runner']}
catalog=json.loads((root/'tools/ci/interop-request.json').read_text())
report={'scope':'native independent-reference analogues, not official ns-3 qualification','official_pass':None,'catalog_cells':44,'binary_sha256':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in files.items() if v.is_file()},'cells':[]}
for group in catalog['groups']:
 for case in group['cases']:
  for role,direction in [('client','forward'),('server','reverse')]:
   name=case+'-'+role;peer=group['reference_implementation'];dest=out/(name+'.json');logs=out/'private'/name
   if peer=='neqo':
    scenario={'transfer':'clean','transferloss':'loss','transfercorruption':'corruption','retry':'clean','ecn':'clean'}.get(case,case)
    cmd=[sys.executable,str(tests/'test_native_neqo_transfer.py'),'--hq',str(files['hq']),'--neqo-client',str(files['neqo-client']),'--neqo-server',str(files['neqo-server']),'--nss',str(files['nss']),'--scenario',scenario,'--direction',direction,'--timeout-seconds','60','--private-log-dir',str(logs),'--output',str(dest)]
    if case=='keyupdate' and direction=='forward':cmd+=['--client-keyupdate']
    if case=='retry':cmd+=['--client-retry' if direction=='forward' else '--server-retry']
    if case=='ecn':cmd+=['--require-ecn']
   else:
    cmd=[sys.executable,str(tests/'test_native_quiche_transfer.py'),'--hq',str(files['hq']),'--quiche-client',str(files['quiche-client']),'--quiche-server',str(files['quiche-server']),'--runner',str(files['runner']),'--scenario',case,'--direction',direction,'--private-log-dir',str(logs),'--output',str(dest)]
   started=time.monotonic();process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
   try:stdout,_=process.communicate(timeout=650);code=process.returncode
   except subprocess.TimeoutExpired:
    os.killpg(process.pid,signal.SIGTERM)
    try:stdout,_=process.communicate(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);stdout,_=process.communicate()
    code=None
   (out/(name+'.log')).write_text(stdout)
   report['cells'].append({'case':case,'candidate_role':role,'peer':peer,'command':cmd,'exit':code,'passed':code==0,'elapsed_seconds':time.monotonic()-started})
   report['passed_cells']=sum(x['passed'] for x in report['cells']);report['executed_cells']=len(report['cells']);report['all_passed']=len(report['cells'])==44 and report['passed_cells']==44
   (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(name,peer,'PASS' if code==0 else 'FAIL',flush=True)
raise SystemExit(0 if report['all_passed'] else 1)
