import subprocess,pathlib,sys,time,json
image='hibana-local-quic'
variant=sys.argv[1] if len(sys.argv)>1 else 'assigned'
subnetright='193.167.10.0/24'
rightip='193.167.10.100' if variant!='unassigned' else '193.167.10.101'
run=['docker','run','--rm','--entrypoint','python3']
for name,subnet in [('hibana-gateway-left','193.167.9.0/24'),('hibana-gateway-right',subnetright)]: subprocess.run(['docker','network','create','--subnet',subnet,name],check=True)
program='''import socket,time,subprocess
print(subprocess.check_output(['ip','-j','addr'],text=True),flush=True)
print(subprocess.check_output(['ip','route'],text=True),flush=True)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); deadline=time.monotonic()+40; s.settimeout(1)
print('BOUND',flush=True)
try:
 while time.monotonic()<deadline:
  try:b,a=s.recvfrom(4096)
  except TimeoutError:continue
  if b[12:14]==b'\\x08\\x00':print('IP',a,len(b),socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]),'MAC',b[:12].hex(),flush=True)
  else:print('OTHER',a,len(b),b[:42].hex(),flush=True)
except TimeoutError:pass
print(subprocess.check_output(['ip','neigh'],text=True),flush=True)
'''
processes=[]
for name,network,ip in [('hibana-gateway','hibana-gateway-left','193.167.9.2'),('hibana-target','hibana-gateway-right','193.167.10.100')]:
 subprocess.run(['docker','create','--name',name,'--network',network,'--ip',ip,'--entrypoint','python3',image,'-u','-c',program],check=True)
subprocess.run(['docker','network','connect','--ip','193.167.10.2','hibana-gateway-right','hibana-gateway'],check=True)
for name in ['hibana-gateway','hibana-target']:
 p=subprocess.Popen(['docker','start','--attach',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 first=''
 while True:
  line=p.stdout.readline();first+=line
  if line.strip()=='BOUND':break
  if not line:raise RuntimeError('container startup failed: '+first)
 processes.append((p,name,first))
hostlog=open('/workspace/validation/capture-'+variant+'-host.log','w')
hostp=subprocess.Popen(['docker','run','--rm','--privileged','--pid=host','--network=host','--entrypoint','nsenter','hibana-local-interop-tools','-t','198','-n','--','python3','-u','-c',"import socket,time; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)); s.settimeout(1); deadline=time.monotonic()+20; print('HOST_BOUND',flush=True)\nwhile time.monotonic()<deadline:\n try:b,a=s.recvfrom(8192)\n except TimeoutError:continue\n if b[23]==17 and b[34:38].hex().endswith('01bb'): print(a,len(b),socket.inet_ntoa(b[26:30]),socket.inet_ntoa(b[30:34]),b[:42].hex(),flush=True)"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
line=hostp.stdout.readline();hostlog.write(line);hostlog.flush();print(line,flush=True)
sender='''import socket,subprocess,time
subprocess.run(['ip','route','add','193.167.10.0/24','via','193.167.9.2'],check=True)
print(subprocess.check_output(['ip','-j','addr'],text=True)); print(subprocess.check_output(['ip','route','get',DEST],text=True))
a=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); a.bind(('eth0',0)); a.settimeout(1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for dest in ['193.167.9.2',DEST]:
 print('SENT',dest,s.sendto(b'x'*1252,(dest,443)),flush=True)
 try:
  while True:
   b,addr=a.recvfrom(4096); print('PACKET',addr,len(b),b[:42].hex(),flush=True)
 except TimeoutError:pass
print(subprocess.check_output(['ip','neigh'],text=True))
'''.replace('DEST',repr(rightip))
with open('/workspace/validation/capture-'+variant+'-sender.log','w') as logfile:
 subprocess.run(run+['--name','hibana-sender','--cap-add','NET_ADMIN','--network','hibana-gateway-left',image,'-u','-c',sender],stdout=logfile,stderr=subprocess.STDOUT)
with open('/workspace/validation/gateway-active-endpoint-raw.log','w') as rawlog:
 subprocess.run(['docker','run','--rm','--privileged','--pid=host','--network=host','--entrypoint','iptables-legacy','hibana-local-interop-tools','-t','raw','-vnL'],stdout=rawlog,stderr=subprocess.STDOUT)
hostlog.write(hostp.communicate(timeout=45)[0]);hostlog.close()
for p,name,first in processes:
 rest=p.communicate(timeout=45)[0];pathlib.Path('/workspace/validation/capture-'+variant+'-'+name+'.log').write_text(first+rest)
 subprocess.run(['docker','rm',name],check=True)
for name in ['hibana-gateway-left','hibana-gateway-right']:subprocess.run(['docker','network','rm',name],check=True)
for name in ['hibana-gateway','hibana-target','sender']:print(pathlib.Path('/workspace/validation/capture-'+variant+'-'+name+'.log').read_text())
