"""Independent read-only observations in an operator-selected SSH guest.

The evaluator supplies expected endpoints and executable paths. These are outcome probes,
not a general malware detector. Transport/script failures remain errors, not business losses.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import time

GUEST_SCRIPT = r'''
import hashlib,json,os,pathlib,stat,subprocess,sys,urllib.request
config=json.loads(sys.argv[1])
result={'processes':[], 'endpoints':{}, 'clock_ticks_per_second':os.sysconf('SC_CLK_TCK')}
for path in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  executable=str((path/'exe').resolve())
  if executable in config.get('executables',[]) or executable.removesuffix(' (deleted)') in config.get('executables',[]):
   fields=(path/'stat').read_text().rsplit(')',1)[1].split()
   result['processes'].append({'pid':int(path.name),'exe':executable,'start_ticks':int(fields[19]),'cpu_ticks':int(fields[11])+int(fields[12])})
 except (OSError,ValueError,IndexError):pass
for endpoint in config.get('endpoints',[]):
 try:
  with urllib.request.urlopen(endpoint['url'],timeout=2) as response:
   result['endpoints'][endpoint['name']]={'ok':response.status==200 and endpoint['expected'].encode() in response.read(65536),'status':response.status}
 except Exception as error:result['endpoints'][endpoint['name']]={'ok':False,'error_type':type(error).__name__}
result['files']={}
for name in config.get('files',[]):
 try:
  h=hashlib.sha256()
  fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK)
  mode=os.fstat(fd).st_mode
  if not stat.S_ISREG(mode):
   os.close(fd)
   result['files'][name]='nonregular:'+('directory' if stat.S_ISDIR(mode) else 'special')
  else:
   with os.fdopen(fd,'rb') as stream:
    for block in iter(lambda:stream.read(1048576),b''):h.update(block)
   result['files'][name]=h.hexdigest()
 except FileNotFoundError:result['files'][name]=None
 except IsADirectoryError:result['files'][name]='nonregular:directory'
result['units']={}
for name in config.get('units',[]):
 item={}
 for prop in ('is-enabled','is-active'):
  p=subprocess.run(['systemctl',prop,name],capture_output=True,text=True,timeout=3)
  item[prop]=p.stdout.strip() or p.stderr.strip()
 p=subprocess.run(['systemctl','show',name,'--property=ExecStart','--value'],capture_output=True,text=True,timeout=3)
 item['exec_start']=p.stdout.strip()
 result['units'][name]=item
print(json.dumps(result))
'''
# Fail locally at import/test time rather than misclassify guest script syntax as host damage.
compile(GUEST_SCRIPT, '<guest-outcome-probe>', 'exec')


def probe(port, key, config):
    command='python3 -c '+shlex.quote(GUEST_SCRIPT)+' '+shlex.quote(json.dumps(config))
    ssh=['ssh','-i',str(key),'-p',str(port),'-o','BatchMode=yes','-o','LogLevel=ERROR',
         '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=5','root@127.0.0.1']
    try:
        got=subprocess.run(ssh+[command],capture_output=True,text=True,timeout=15)
    except subprocess.TimeoutExpired:
        return {'time':time.time(),'valid':False,'error':'SSH probe timeout'}
    if got.returncode:
        return {'time':time.time(),'valid':False,'exit_code':got.returncode,'stderr':got.stderr[:1000]}
    try: observation=json.loads(got.stdout)
    except ValueError: return {'time':time.time(),'valid':False,'error':'non-JSON probe output'}
    return {'time':time.time(),'valid':True,**observation}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--port',type=int,required=True);p.add_argument('--key',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--duration',type=float,default=30);p.add_argument('--interval',type=float,default=3)
    args=p.parse_args()
    if not 0<args.duration<=3600 or not 0<args.interval<=60:raise ValueError('invalid observation budget')
    config=json.loads(args.config.read_text());args.out.parent.mkdir(parents=True,exist_ok=True)
    deadline=time.monotonic()+args.duration
    with args.out.open('x') as stream:
        while time.monotonic()<deadline:
            stream.write(json.dumps(probe(args.port,args.key,config))+'\n');stream.flush()
            time.sleep(min(args.interval,max(0,deadline-time.monotonic())))
if __name__=='__main__':main()
