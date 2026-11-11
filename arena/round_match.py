"""Alternating foreground actors with continuous guest state and independent observation."""
import argparse,asyncio,copy,json,math,shlex,subprocess,time,uuid
from pathlib import Path
from .contracts import ArenaClosed,RewardProfile,digest
from .guest_probe import probe
from .host_blue import GuestContext,HOST_ROLE,HOST_TOOLS
from .llm import OpenAIBlue
from .round_scoring import VERSION,finalize
from .storage import Journal,write_json

# A foreground process group must terminate before handing over. systemd-managed workloads
# are detached environment state and remain running, as explicitly declared in the contract.
EXEC_SCRIPT=r'''
import json,os,signal,subprocess,sys,time
p=subprocess.Popen(['/bin/bash','-c',sys.argv[1]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
timed=False
try:out,err=p.communicate(timeout=float(sys.argv[2]))
except subprocess.TimeoutExpired:
 timed=True
 try:os.killpg(p.pid,signal.SIGKILL)
 except ProcessLookupError:pass
 out,err=p.communicate(timeout=3)
print(json.dumps({'exit_code':p.returncode,'stdout':out.decode(errors='replace')[:12000],'stderr':err.decode(errors='replace')[:2000],'timed_out':timed,'foreground_terminal':True,'truncated':len(out)>12000 or len(err)>2000},ensure_ascii=False))
'''
compile(EXEC_SCRIPT,'<bounded-guest-command>','exec')


class ScopedJournal:
    def __init__(self,journal,context):self.journal,self.context=journal,context
    @property
    def rows(self):return self.journal.rows
    def append(self,kind,data):
        self.journal.append(kind,{**data,'round_id':self.context.round_id,'actor':'blue','action_id':uuid.uuid4().hex if kind=='tool' else None})


class Context(GuestContext):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.round_id=0;self.open=False;self.uncertain=False
    def public_brief(self):return {**self.brief,'round_id':self.round_id,'continuity':'Same machine and conversation; earlier actions and responsibility remain in force.'}
    def command(self,command):
        remaining=self.deadline-time.monotonic()
        if remaining<=.5:return {'exit_code':None,'error':'window closed','foreground_terminal':True}
        budget=min(20,max(.1,remaining-.5))
        wrapped='python3 -c '+shlex.quote(EXEC_SCRIPT)+' '+shlex.quote(command)+' '+str(budget)
        # Allow the bounded child to finish cleanup; do not change the public action deadline.
        old=self.deadline;self.deadline=max(old,time.monotonic()+budget+5)
        try:got=super().command(wrapped)
        finally:self.deadline=old
        try:result=json.loads(got['stdout'])
        except (KeyError,TypeError,ValueError):
            self.uncertain=True;return {'error':'foreground completion unknown','foreground_terminal':False}
        return result
    async def call(self,name,**args):
        if not self.open or time.monotonic()>=self.deadline:raise ArenaClosed('blue permission window closed')
        return await super().call(name,**args)


async def run(args):
    cfg=json.loads(args.config.read_text());plan=cfg['round_plan'];n=len(plan)
    red_seconds=float(cfg.get('red_seconds',15));blue_seconds=float(cfg.get('blue_seconds',90));interval=float(cfg.get('probe_interval',2))
    if not n or any(not math.isfinite(x) or x<=0 for x in (red_seconds,blue_seconds,interval)):raise ValueError('invalid schedule')
    if cfg['receipt_coverage']!='closed_scripted_transport':raise ValueError('receipt coverage not declared')
    root=args.out;root.mkdir(parents=True,exist_ok=False,mode=0o700);(root/'private').mkdir(mode=0o700)
    ident=uuid.uuid4().hex;assets={'assets':[{'id':a['id'],'weight':a['weight']} for a in cfg['assets']]}
    write_json(root/'private/assets.json',assets,private=True)
    model=OpenAIBlue(tools=HOST_TOOLS,role=HOST_ROLE,max_turns=12,max_output_tokens=3000,model_timeout=blue_seconds) if args.blue=='model' else None
    spec={'match_id':ident,'reward_version':VERSION,'weights':RewardProfile().weights,'rounds':n,
          'red_seconds':red_seconds,'blue_seconds':blue_seconds,'max_overrun_seconds':12,'max_probe_gap_seconds':12,
          'gamma':cfg.get('gamma',1),'cpu_capacity':cfg.get('cpu_capacity',2),'asset_manifest_hash':digest(assets),
          'endpoints':[e['name'] for e in cfg['probe']['endpoints']],'files':cfg['probe']['files'],'units':cfg['probe']['units'],
          'protected_files':cfg['protected_files'],'protected_units':cfg['protected_units'],'access_channels':cfg['access_channels'],
          'receipt_coverage':cfg['receipt_coverage'],'attribution':'Exclusive foreground action brackets; declared red CPU/restart channels. Persistent background file-mutating actors are outside this closed-world adapter.',
          'operator_brief':cfg['brief'],'blue_policy':args.blue,'blue_policy_id':model.policy_id if model else 'round-fixture:'+args.blue,'red_policy_id':'fixture:'+digest(plan),'scheduling':'alternating foreground actors, continuous background effects; not fully concurrent decisions'}
    write_json(root/'match.json',spec,private=True)
    events=Journal(root/'outcomes.jsonl',ident);events.append('match.spec',{'digest':digest(spec)})
    red=Journal(root/'red_trajectory.jsonl',ident);blue=Journal(root/'blue_trajectory.jsonl',ident)
    ctx=Context(root,args.port,args.key,cfg['brief'],120)
    ctx.trajectory=ScopedJournal(blue,ctx)
    start=time.monotonic();errors=[];collection_warnings=[];lock=asyncio.Lock();stop=asyncio.Event();current_round=0
    async def snapshot():
        async with lock:
            got=await asyncio.to_thread(probe,args.port,args.key,cfg['probe'])
            got['t']=time.monotonic()-start;got['round_id']=current_round
            events.append('snapshot',got)
            if not got['valid']:collection_warnings.append({'t':got['t'],'reason':'independent probe unavailable; judge must investigate evidence limits'})
            return got
    first=await snapshot();boundary=first['t'];versions=set();pending=[]
    async def monitor():
        while not stop.is_set():
            try:await asyncio.wait_for(stop.wait(),interval)
            except asyncio.TimeoutError:await snapshot()
    # Start/stop a monitor per permission window, so no probe can straddle a handoff.
    async def transport_acquire(asset_id,round_id,delay_round):
        a=next(a for a in cfg['assets'] if a['id']==asset_id)
        lo=time.monotonic()-start
        command='python3 -c '+shlex.quote('import pathlib;print(pathlib.Path('+repr(a['path'])+').read_text(),end="")')
        got=await asyncio.to_thread(ctx.command,command);hi=time.monotonic()-start
        if got.get('exit_code')!=0 or not got.get('foreground_terminal') or got.get('truncated'):raise ValueError('acquisition transport failed')
        value=got['stdout'];vid=asset_id+':'+digest(value)
        if vid not in versions:
            versions.add(vid);events.append('asset.version',{'asset_id':asset_id,'version_id':vid,'value_digest':digest(value),'observed_t':hi})
        pending.append({'asset_id':asset_id,'version_id':vid,'value_digest':digest(value),'acquired_start':lo,'acquired_end':hi,'round_id':round_id,'submit_after_round':delay_round})
        red.append('transport.receipt',{'round_id':round_id,'action_id':uuid.uuid4().hex,'asset_id':asset_id,'value':value,'acquired_start':lo,'acquired_end':hi})
    async def publish(round_id):
        for d in list(pending):
            if d['submit_after_round']<=round_id:
                events.append('delivery',{**d,'submitted_t':time.monotonic()-start});pending.remove(d)
    for i,step in enumerate(plan,1):
        current_round=i;ctx.round_id=i
        for actor,seconds in (('red',red_seconds),('blue',blue_seconds)):
            opened=boundary;ctx.deadline=start+opened+seconds;ctx.open=actor=='blue';ctx.calls=0
            if actor=='blue' and i==1:events.append('takeover',{'t':opened,'round_id':i,'authority':'controller_first_blue_permission'})
            stop.clear();monitor_task=asyncio.create_task(monitor())
            try:
                if actor=='red':
                    if cfg.get('payload_source'):
                        transfer=['scp','-q','-i',str(args.key),'-P',str(args.port),'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null',cfg['payload_source'],'root@127.0.0.1:'+cfg['payload_guest_path']]
                        result=await asyncio.to_thread(subprocess.run,transfer,capture_output=True,timeout=max(1,ctx.deadline-time.monotonic()))
                        red.append('fixture.transfer',{'round_id':i,'action_id':uuid.uuid4().hex,'exit_code':result.returncode})
                        if result.returncode:raise ValueError('fixture payload transfer failed')
                    command=step.get('red_command','true');lo=time.monotonic()-start
                    got=await asyncio.to_thread(ctx.command,command)
                    red.append('fixture.action',{'round_id':i,'action_id':uuid.uuid4().hex,'command':command,'result':got,'started_t':lo,'finished_t':time.monotonic()-start})
                    if got.get('exit_code')!=0:raise ValueError('red fixture action failed')
                    for request in step.get('deliver_assets',[]):
                        if isinstance(request,str):request={'id':request}
                        await transport_acquire(request['id'],i,request.get('submit_after_round',i))
                elif model:
                    await model.run(ctx,initial_messages=copy.deepcopy(getattr(model,'messages',None)))
                else:
                    await ctx.call('observe')
                    if args.blue=='script':await ctx.call('shell',command=step.get('blue_command','true'))
            except ArenaClosed:blue.append('window.horizon',{'round_id':i,'actor':'blue'})
            except Exception as exc:errors.append(actor+': '+type(exc).__name__)
            ctx.open=False
            await asyncio.sleep(max(0,start+opened+seconds-time.monotonic()))
            stop.set();await monitor_task
            ending=await snapshot();boundary=ending['t']
            events.append('window',{'round_id':i,'actor':actor,'start':opened,'end':boundary})
            if ctx.uncertain:errors.append('foreground command may still be executing')
            await publish(i)
            if errors:break
        if errors:break
    await publish(n)
    if pending:errors.append('unsubmitted acquired evidence')
    events.append('closed',{'errors':errors})
    write_json(root/'completion.json',{'evidence_complete':not errors,'errors':errors,'collection_warnings':collection_warnings,'outcome_head':events.rows[-1]['hash']},private=True)
    from .judge_agent import judge_match
    try:await judge_match(root,args.port,args.key)
    except Exception as exc:
        write_json(root/'judge_failure.json',{'error_type':type(exc).__name__,'rule_fallback_used':False},private=True)
    result=finalize(root)
    print(json.dumps({'directory':str(root),'scored':result['scored'],'blue_reward':result['blue_reward'],'red_reward':result['red_reward'],'reason':result.get('reason')}))


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--port',type=int,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--blue',choices=['model','idle','script'],default='model')
    asyncio.run(run(p.parse_args()))
if __name__=='__main__':main()
