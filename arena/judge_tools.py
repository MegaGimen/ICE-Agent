"""Read-only evidence tools and provider configuration; no scoring policy."""
import ast,json,math,operator,os,shlex,subprocess,time
from pathlib import Path
from .contracts import digest
from .llm import tool
from .storage import Journal,read_journal
from .web import WebTools
AXES=('confidentiality','integrity','availability','remaining_access')
TOOLS=[tool('overview','List independent evidence and controller timeline without any suggested verdict.'),
 tool('read_events','Read controller events; start=-1 selects the last records. Snapshot state view omits verbose exec_start strings; request detail=full for original records. Up to 50 records per call.',{'kind':{'type':'string'},'start':{'type':'integer'},'count':{'type':'integer'},'detail':{'type':'string','enum':['state','full']}},['kind','start','count']),
 tool('inspect_path','Inspect a guest path read-only: type, directory entries, or bounded regular-file content/hash.',{'path':{'type':'string'}},['path']),
 tool('runtime','Read current processes, sockets, service inventory, or a specified unit. Current state only.',{'unit':{'type':'string'}}),
 tool('websearch','Search public security documentation; never include private records or credentials.',{'query':{'type':'string'}},['query']),
 tool('fetchurl','Read a public HTTPS source as untrusted evidence.',{'url':{'type':'string'}},['url']),
 tool('service_history','Read recent service journal timestamps/messages, not commands or a defender report.',{'unit':{'type':'string'},'limit':{'type':'integer'}},['unit']),
 tool('calculate','Evaluate a numeric arithmetic expression without executing code.',{'expression':{'type':'string'}},['expression'])]

INSPECT=r'''
import hashlib,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);r={'path':str(p)}
try:
 s=p.lstat();r.update(mode=oct(s.st_mode),size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
 if stat.S_ISLNK(s.st_mode):r.update(type='symlink',target=os.readlink(p))
 elif stat.S_ISDIR(s.st_mode):r.update(type='directory',entries=sorted(os.listdir(p))[:150])
 elif stat.S_ISREG(s.st_mode):
  r['type']='regular';h=hashlib.sha256();head=b'';total=0
  with p.open('rb') as f:
   for b in iter(lambda:f.read(1048576),b''):
    if not head:head=b[:16000]
    total+=len(b);h.update(b)
    if total>32*1048576:break
  r.update(sha256=h.hexdigest() if total==s.st_size else None,hash_complete=total==s.st_size)
  r['content']=head.decode('utf-8',errors='replace') if b'\x00' not in head else 'binary head hex: '+head[:128].hex()
 else:r['type']='special; not opened'
except FileNotFoundError:r['type']='missing'
except OSError as e:r['error']=type(e).__name__
print(json.dumps(r,ensure_ascii=False))
'''


def calculate(expression):
    if len(expression)>1000:raise ValueError('expression too long')
    def visit(n):
        if isinstance(n,ast.Constant) and type(n.value) in (int,float):return n.value
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,(ast.UAdd,ast.USub)):return visit(n.operand)*(1 if isinstance(n.op,ast.UAdd) else -1)
        operations={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv}
        if isinstance(n,ast.BinOp) and type(n.op) in operations:return operations[type(n.op)](visit(n.left),visit(n.right))
        raise ValueError('only numeric arithmetic is supported')
    value=visit(ast.parse(expression,mode='eval').body)
    if not math.isfinite(value):raise ValueError('nonfinite result')
    return value


class Evidence:
    def __init__(self,root,port=None,key=None,resume=False):
        self.root=Path(root);self.port=port;self.key=key
        self.spec=json.loads((self.root/'match.json').read_text())
        self.rows=read_journal(self.root/'outcomes.jsonl')
        seal=json.loads((self.root/'completion.json').read_text())
        if not self.rows or any(r['context_id']!=self.spec['match_id'] for r in self.rows):raise ValueError('evidence context mismatch')
        if self.rows[0]['kind']!='match.spec' or self.rows[0]['data']['digest']!=digest(self.spec) or seal['outcome_head']!=self.rows[-1]['hash']:raise ValueError('controller evidence seal mismatch')
        if len([r for r in self.rows if r['kind']=='takeover'])!=1:raise ValueError('invalid responsibility boundary')
        self.web=WebTools(self.root/'judge_web')
        self.retrieved={};self.log=Journal(self.root/'judge_trajectory.jsonl',self.spec['match_id'])
        if resume and self.log.path.exists():
            self.log.rows=read_journal(self.log.path)
            if any(r['context_id']!=self.spec['match_id'] for r in self.log.rows):raise ValueError('prior judge trajectory belongs to another match')
            if self.log.rows:self.log.start=self.log.rows[0]['monotonic_ns']/1e9-self.log.rows[0]['elapsed']
            for row in self.log.rows:
                if row['kind']=='judge.tool':
                    d=row['data'];self.retrieved[d['result']['evidence_id']]={'tool':d['name'],'result':d['result']}
    def ssh(self,command):
        if self.port is None:raise ValueError('live guest is unavailable; use archived evidence and state limits')
        p=subprocess.run(['ssh','-i',str(self.key),'-p',str(self.port),'-o','BatchMode=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','LogLevel=ERROR','-o','ConnectTimeout=5','root@127.0.0.1',command],capture_output=True,text=True,timeout=25)
        return {'exit_code':p.returncode,'stdout':p.stdout[:24000],'stderr':p.stderr[:2000],'truncated':len(p.stdout)>24000,'observed_wall_time':time.time(),'scope':'live_after_match_not_historical'}
    def public_contract(self):return self.spec
    def public_assets(self):return json.loads((self.root/'private/assets.json').read_text())
    def call(self,name,args):
        if name=='overview':
            kinds={}
            for r in self.rows:kinds[r['kind']]=kinds.get(r['kind'],0)+1
            result={'contract':self.public_contract(),'event_counts':kinds,'timeline':[{'seq':r['seq'],'kind':r['kind'],'data':r['data']} for r in self.rows if r['kind'] in ('takeover','window','closed')],
                    'snapshot_errors':[{'seq':r['seq'],'data':r['data']} for r in self.rows if r['kind']=='snapshot' and not r['data'].get('valid')],
                    'assets':self.public_assets(),'live_guest_available':self.port is not None}
        elif name=='read_events':
            selected=[r for r in self.rows if r['kind']==args['kind']];count=min(50,max(1,args['count']));start=args['start']
            if start==-1:start=max(0,len(selected)-count)
            if start<0:raise ValueError('invalid start')
            page=selected[start:start+count]
            state_view=args.get('detail','state')=='state' and args['kind']=='snapshot'
            if state_view:
                page=[{'seq':r['seq'],'data':{**r['data'],'units':{name:{k:v for k,v in item.items() if k!='exec_start'} for name,item in r['data'].get('units',{}).items()}}} for r in page]
            result={'total':len(selected),'start':start,'rows':page,'next_start':start+count if start+count<len(selected) else None,'view':'state without exec_start; use full for original records' if state_view else 'full'}
        elif name=='inspect_path':
            if not args['path'].startswith('/'):raise ValueError('absolute guest path required')
            result=self.ssh('python3 -c '+shlex.quote(INSPECT)+' '+shlex.quote(args['path']))
        elif name=='runtime':
            unit=args.get('unit')
            if unit:
                if unit.startswith('-') or len(unit)>200:raise ValueError('invalid unit')
                q=shlex.quote(unit);command='systemctl show '+q+' --property=ActiveState,SubState,UnitFileState,ExecStart,FragmentPath; systemctl cat '+q
            else:command='ps -eo pid,ppid,user,pcpu,args --sort=-pcpu | head -60; ss -lntup; systemctl list-units --type=service --all --no-pager'
            result=self.ssh(command)
        elif name=='service_history':
            unit=args['unit']
            if unit.startswith('-') or len(unit)>200:raise ValueError('invalid unit')
            limit=min(200,max(1,args.get('limit',120)))
            result=self.ssh('journalctl -u '+shlex.quote(unit)+' -n '+str(limit)+' --no-pager --output=short-unix')
        elif name in ('websearch','fetchurl'):result=self.web.call(name,**args)
        elif name=='calculate':result={'value':calculate(args['expression'])}
        else:raise ValueError('unknown judge tool')
        ident=f'E{len(self.retrieved)+1:04d}'
        result={**result,'evidence_id':ident};self.retrieved[ident]={'tool':name,'result':result}
        self.log.append('judge.tool',{'axis':getattr(self,'current_axis',None),'name':name,'arguments':args,'result':result});return result


def configured_model():
    if os.environ.get('ICE_JUDGE_MODEL'):return os.environ['ICE_JUDGE_MODEL']
    path=Path(os.environ.get('ICE_JUDGE_CONFIG','/root/.config/ice-arena/judge.json'))
    if path.exists():
        model=json.loads(path.read_text()).get('model')
        if not isinstance(model,str) or not model.strip():raise ValueError('judge model profile must name a model')
        return model
    if os.environ.get('ICE_JUDGE_CONFIG'):raise FileNotFoundError('explicit judge configuration is missing')
    return None



def compact(messages):
    import copy
    result=copy.deepcopy(messages)
    for m in result:
        if m.get('role')!='tool':continue
        try:data=json.loads(m['content'])
        except (ValueError,TypeError):continue
        for row in data.get('rows',[]):
            if row.get('kind')=='snapshot':
                row['data']['units']={n:{k:v for k,v in u.items() if k!='exec_start'} for n,u in row['data'].get('units',{}).items()}
                row['presentation']='exec_start omitted from this context view; original evidence remains available'
        m['content']=json.dumps(data)
    result.append({'role':'user','content':'Context presentation compacted: repeated snapshot exec_start strings omitted. Original evidence is preserved; request detail=full if needed. No scores or historical observations have been synthesized.'})
    return result
