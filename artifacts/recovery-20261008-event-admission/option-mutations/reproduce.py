#!/usr/bin/env python3
"""Exercise the actual Z3 model with two Option-identity mutations."""
import hashlib,json,pathlib,subprocess,sys
model=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2]);out.mkdir(exist_ok=True)
source=model.read_text()
expected=['sat','unsat','unsat','unsat','unsat','unsat','unsat','sat','sat','sat']
mutations=[('ignore_presence',' (= requested_arm_present arm_present)','',3,'sat'),('compare_none_payload','(or (not arm_present) (= requested_arm arm))','(= requested_arm arm)',9,'unsat')]
records=[]
for name,old,new,index,result in mutations:
 assert source.count(old)==1
 mutated=source.replace(old,new)
 path=out/(name+'.smt2');path.write_text(mutated)
 process=subprocess.run(['z3',str(path)],capture_output=True,text=True)
 assert process.returncode==0,process.stderr
 rows=process.stdout.splitlines();assert len(rows)==10 and rows[index]==result and rows!=expected,rows
 (out/(name+'.log')).write_text(process.stdout)
 records.append(dict(mutation=name,replace=old,with_text=new,exit=process.returncode,checks=rows,expected_unmutated=expected,caught_at_check=index+1,mutation_rejected=True))
record=dict(core_revision='8302a07b5f0f2d224229afdba4d0afef62d6aa2b',model_sha256=hashlib.sha256(source.encode()).hexdigest(),z3_version=subprocess.check_output(['z3','--version'],text=True).strip(),mutations=records)
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
