"""Complete host rollout: T0 -> staged opponent -> concurrent blue/probes -> judge -> bound case."""
import argparse
import asyncio
import json
import math
from pathlib import Path
import shlex
import time
import uuid
from .cases import package_case,verify_case
from .contracts import ArenaClosed,RewardProfile,digest
from .guest_probe import probe
from .host_blue import GuestContext,HOST_ROLE,HOST_TOOLS,FINAL_REVIEW
from .host_scoring import VERSION,finalize_host
from .llm import OpenAIBlue
from .scoring import Deliveries
from .storage import Journal,write_json


async def run(args):
    config=json.loads(args.config.read_text())
    duration=float(config.get('duration_seconds',180));interval=float(config.get('probe_interval',2))
    if not math.isfinite(duration) or not 10<=duration<=1800 or not 0<interval<=10:raise ValueError('invalid horizon')
    if config.get('receipt_coverage')!='closed_staged_opponent':raise ValueError('declare and enforce opponent receipt coverage')
    out=args.out;out.mkdir(parents=True,exist_ok=False,mode=0o700);(out/'private').mkdir(mode=0o700)
    match_id=uuid.uuid4().hex
    ctx=GuestContext(out,args.port,args.key,config['brief'],duration+120)
    ctx.trajectory=Journal(out/'blue_trajectory.jsonl',match_id)
    model=OpenAIBlue(tools=HOST_TOOLS,role=HOST_ROLE,final_review=FINAL_REVIEW,max_turns=24,max_output_tokens=4096,model_timeout=120) if args.blue=='model' else None
    assets=[]
    for a in config['assets']:
        code='import pathlib;print(pathlib.Path('+repr(a['path'])+').read_text(),end="")'
        got=await asyncio.to_thread(ctx.command,'python3 -c '+shlex.quote(code))
        if got.get('exit_code')!=0 or got.get('truncated'):raise ValueError('cannot read baseline asset')
        assets.append({'id':a['id'],'weight':a['weight'],'value':got['stdout']})
    manifest={'assets':assets}
    write_json(out/'private/assets.json',manifest,private=True)
    spec={'match_id':match_id,'reward_version':VERSION,'weights':RewardProfile().weights,
          'duration_seconds':duration,'probe_interval':interval,'minimum_samples':max(2,int(duration/(interval+1)*.65)),
          'max_probe_gap_seconds':max(15,interval*4),'cpu_capacity':config.get('cpu_capacity',2),
          'probe':config['probe'],'protected_files':config['protected_files'],'protected_units':config['protected_units'],
          'access_channels':config['access_channels'],'asset_manifest_hash':digest(manifest),
          'policy_id':model.policy_id if model else 'host-control:'+args.blue,
          'coverage':config['coverage'],'receipt_coverage':config['receipt_coverage']}
    write_json(out/'match.json',spec,private=True)
    events=Journal(out/'outcomes.jsonl',match_id);events.append('match.spec',{'digest':digest(spec)})
    async def observe(kind,offset):
        result=await asyncio.to_thread(probe,args.port,args.key,config['probe'])
        result['offset']=offset if offset is not None else time.monotonic()-start
        events.append(kind,result);return result
    baseline=await observe('baseline',0)
    if not baseline['valid']:raise ValueError('T0 collection failed')
    staging=await asyncio.to_thread(ctx.command,'bash -e -c '+shlex.quote(config.get('stage_command','true')))
    write_json(out/'private/staging.json',staging,private=True)
    if staging.get('exit_code')!=0:raise ValueError('opponent staging failed')
    receipts=Deliveries(out/'private/deliveries.jsonl',20,65536,match_id)
    for ident in config.get('deliver_assets',[]):
        a=next(a for a in config['assets'] if a['id']==ident)
        code='import pathlib;print(pathlib.Path('+repr(a['path'])+').read_text(),end="")'
        got=await asyncio.to_thread(ctx.command,'python3 -c '+shlex.quote(code))
        if got.get('exit_code')!=0 or got.get('truncated'):raise ValueError('red receipt transport failed')
        receipts.submit(ident,got['stdout'],source='controller_observed_red_transport')
    receipts.seal()
    start=time.monotonic();ctx.deadline=start+duration
    await observe('armed',0)
    errors=[]
    async def blue():
        try:
            if model:await model.run(ctx)
            else:
                await ctx.call('observe')
                if args.blue=='shutdown':await ctx.call('shell',command=config['shutdown_command'])
                elif args.blue=='repair':await ctx.call('shell',command=config['repair_command'])
        except ArenaClosed:ctx.trajectory.append('episode.horizon',{'normal_terminal':True})
        except Exception as exc:errors.append('blue infrastructure error: '+type(exc).__name__)
    task=asyncio.create_task(blue())
    while time.monotonic()-start<duration:
        await observe('sample',None)
        await asyncio.sleep(min(interval,max(0,duration-(time.monotonic()-start))))
    await task
    await observe('final',None)
    events.append('closed',{'duration_seconds':time.monotonic()-start})
    write_json(out/'completion.json',{'evidence_complete':not errors,'errors':errors,
               'outcome_head':events.rows[-1]['hash'],'delivery_head':receipts.journal.rows[-1]['hash'] if receipts.journal.rows else None,
               'receipt_collection_complete':True},private=True)
    print(json.dumps(finalize_host(out)))


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--key',type=Path,required=True)
    p.add_argument('--blue',choices=['model','idle','shutdown','repair'],default='model')
    p.add_argument('--legacy-v1',action='store_true',help='Explicitly retain the old incident-based zero-sum reward')
    args=p.parse_args()
    if 'round_plan' in json.loads(args.config.read_text()):
        if args.blue not in ('model','idle'):p.error('Use arena.round_match --blue script for scripted round controls')
        from .round_match import run as run_rounds
        asyncio.run(run_rounds(args))
    elif args.legacy_v1:p.error('Old rule scores are read-only historical records. New host matches require the judge Agent and a round_plan.')
    else:p.error('Responsibility-aware matches require round_plan; --legacy-v1 is only for reproducing the old reward version.')
if __name__=='__main__':main()
