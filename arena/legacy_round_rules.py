"""Archived pre-Agent prototype for historical regression only.

Current rollouts never call this judge. All new judging uses arena.judge_agent.
This module is retained to explain and verify the superseded v2 experiments.
"""
import json, math
from pathlib import Path
from .contracts import RewardProfile,digest
from .storage import read_journal,write_json
from .host_scoring import file_hash
from .cases import package_case,verify_case

VERSION='host-round-outcome-v2'


def judge(spec,rows,assets):
    RewardProfile(weights=spec['weights']).validate()
    if spec['reward_version']!=VERSION:raise ValueError('wrong reward version')
    if any(r['context_id']!=spec['match_id'] for r in rows):raise ValueError('foreign match event')
    if rows[0]['kind']!='match.spec' or rows[0]['data']['digest']!=digest(spec):raise ValueError('spec mismatch')
    take=[r['data'] for r in rows if r['kind']=='takeover']
    if len(take)!=1:raise ValueError('exactly one responsibility boundary required')
    windows=[r['data'] for r in rows if r['kind']=='window']
    expected=[(n,a) for n in range(1,spec['rounds']+1) for a in ('red','blue')]
    if [(w['round_id'],w['actor']) for w in windows]!=expected:raise ValueError('round schedule mismatch')
    for i,w in enumerate(windows):
        if not math.isfinite(w['start']) or w['end']<=w['start']:raise ValueError('invalid action window')
        if i and abs(w['start']-windows[i-1]['end'])>1e-6:raise ValueError('overlap or unaccounted window')
        if w['end']-w['start']>spec[w['actor']+'_seconds']+spec['max_overrun_seconds']:raise ValueError('action window overrun')
    t0,end=windows[0]['start'],windows[-1]['end'];takeover=take[0]['t']
    if abs(takeover-windows[1]['start'])>1e-6:raise ValueError('takeover not first blue permission grant')
    points=[r['data'] for r in rows if r['kind']=='snapshot']
    times=[p['t'] for p in points]
    if times!=sorted(set(times)):raise ValueError('duplicate or reversed observation time')
    if abs(times[0]-t0)>1e-6 or abs(times[-1]-end)>1e-6:raise ValueError('missing boundary coverage')
    for w in windows:
        if w['start'] not in times or w['end'] not in times:raise ValueError('missing handoff snapshot')
    if any(not p.get('valid') for p in points):raise ValueError('invalid probe')
    if max(b-a for a,b in zip(times,times[1:]))>spec['max_probe_gap_seconds']:raise ValueError('unobserved interval')
    ep=set(spec['endpoints']);files=set(spec['files']);units=set(spec['units'])
    if not ep:raise ValueError('no legitimate business probes')
    for p in points:
        if set(p['endpoints'])!=ep or set(p['files'])!=files or set(p['units'])!=units:raise ValueError('incomplete probe coverage')
        if p['clock_ticks_per_second']<=0:raise ValueError('invalid CPU clock')
    baseline=points[0];initial=points[times.index(takeover)];final=points[-1]
    if baseline['processes'] or not all(x['ok'] for x in baseline['endpoints'].values()):raise ValueError('unhealthy clean baseline')
    keys=[('files',x) for x in spec['protected_files']]+[('units',x) for x in spec['protected_units']]
    if not keys or any(baseline['files'][x] is None for x in spec['protected_files']):raise ValueError('invalid protected baseline')
    def values(p):return [p[k][x] if k=='files' else p[k][x]['is-enabled'] for k,x in keys]
    clean=values(baseline);inherited=values(initial)
    def owner(t):return next(w for w in windows if w['start']<=t<w['end'])
    version_rows=[r['data'] for r in rows if r['kind']=='asset.version']
    versions={v['version_id']:v for v in version_rows}
    if len(versions)!=len(version_rows):raise ValueError('duplicate asset version identity')
    asset_map={a['id']:a for a in assets['assets']}
    if not asset_map or any(not math.isfinite(a['weight']) or a['weight']<=0 for a in asset_map.values()):raise ValueError('invalid asset budget')
    deliveries=[]
    for r in rows:
        if r['kind']!='delivery':continue
        d=r['data'];v=versions.get(d['version_id']);a=asset_map.get(d['asset_id'])
        if not a or not v or v['asset_id']!=d['asset_id'] or v['value_digest']!=d['value_digest']:continue
        lo,hi=d['acquired_start'],d['acquired_end']
        if not t0<=lo<=hi<=end or d['submitted_t']<hi or v['observed_t']>hi:raise ValueError('invalid possession timing')
        if lo<takeover<hi:raise ValueError('possession interval crosses responsibility boundary')
        if not any(w['actor']=='red' and w['start']<=lo<=hi<=w['end'] for w in windows):raise ValueError('receipt outside authorized red transport window')
        deliveries.append(d)
    deliveries.sort(key=lambda d:(d['acquired_end'],d['acquired_start']))
    weights=spec['weights'];capacity=spec['cpu_capacity']
    if not math.isfinite(capacity) or capacity<=0:raise ValueError('invalid CPU capacity')
    gamma=spec['gamma']
    if not math.isfinite(gamma) or not 0<=gamma<=1:raise ValueError('invalid discount')
    budget=sum(a['weight'] for a in asset_map.values())
    results=[]
    for round_id in range(1,spec['rounds']+1):
        cutoff=windows[2*round_id-1]['end'];terminal=round_id==spec['rounds']
        red_assets=set();blue_assets=set();known=set()
        for d in deliveries:
            if d['acquired_end']>cutoff:continue
            ident=(d['asset_id'],d['version_id'])
            red_assets.add(d['asset_id'])
            if ident not in known and d['acquired_start']>=takeover:blue_assets.add(d['asset_id'])
            known.add(ident)
        red_i=set();blue_i=set();incident_i=set();blue_healthy=[v==c for v,c in zip(inherited,clean)]
        red_business=blue_business=incident_business=red_cpu=blue_cpu=0.0
        causes={e:None for e in ep};unknown_outage=0.0
        prior=points[0]
        for current in points[1:]:
            if current['t']>cutoff:break
            actor=owner((prior['t']+current['t'])/2)['actor'];dt=current['t']-prior['t']
            old,new=values(prior),values(current)
            for i,(o,n,c) in enumerate(zip(old,new,clean)):
                if n!=c:incident_i.add(i)
                if o==c and n!=c and actor=='red':red_i.add(i)
                if current['t']>takeover:
                    if n!=c and (blue_healthy[i] or n!=inherited[i]):blue_i.add(i)
                    if n==c:blue_healthy[i]=True
            # Left-held business integration; changed faults get provenance only at observation.
            for e in ep:
                if not prior['endpoints'][e]['ok']:
                    incident_business+=dt/len(ep)
                    if prior['t']>=takeover:blue_business+=dt/len(ep)
                    if causes[e]=='red':red_business+=dt/len(ep)
                    elif causes[e] is None:unknown_outage+=dt/len(ep)
                signature_changed=old!=new or prior['units']!=current['units'] or prior['endpoints'][e]['ok']!=current['endpoints'][e]['ok']
                if signature_changed:causes[e]=actor if not current['endpoints'][e]['ok'] else None
            old_proc={(p['pid'],p['start_ticks']):p['cpu_ticks'] for p in prior['processes']}
            for p in current['processes']:
                ident=(p['pid'],p['start_ticks'])
                if ident in old_proc:
                    delta=p['cpu_ticks']-old_proc[ident]
                    if delta<0:raise ValueError('CPU counter reversal')
                    seconds=delta/current['clock_ticks_per_second'];red_cpu+=seconds
                    if prior['t']>=takeover:blue_cpu+=seconds
            prior=current
        if terminal:
            blue_i.update(i for i,(v,c) in enumerate(zip(values(final),clean)) if v!=c)
        remaining=False
        if terminal:
            remaining=bool(final['processes'])
            for c in spec['access_channels']:
                u=final['units'][c['unit']]
                if final['files'][c['executable']] is not None and (u['is-enabled'] in ('enabled','enabled-runtime') or u['is-active']=='active'):
                    if 'exec_start' not in u:raise ValueError('unverified restart command')
                    remaining |= c['executable'] in u['exec_start']
        red={'confidentiality':sum(asset_map[x]['weight'] for x in red_assets)/budget,
             'integrity':len(red_i)/len(keys),'availability':min(1,max(red_business/(end-t0),red_cpu/((end-t0)*capacity))), 'remaining_access':float(remaining)}
        blue={'confidentiality':sum(asset_map[x]['weight'] for x in blue_assets)/budget,
              'integrity':len(blue_i)/len(keys),'availability':min(1,max(blue_business/(end-takeover),blue_cpu/((end-takeover)*capacity))), 'remaining_access':float(remaining)}
        incident={'confidentiality':red['confidentiality'],'integrity':len(incident_i)/len(keys),
                  'availability':min(1,max(incident_business/(end-t0),red_cpu/((end-t0)*capacity))), 'remaining_access':float(remaining)}
        rv=sum(weights[k]*v for k,v in red.items());bv=1-sum(weights[k]*v for k,v in blue.items())
        prev=results[-1] if results else {'red_cumulative_reward':0,'blue_cumulative_reward':0}
        results.append({'round_id':round_id,'end':cutoff,'red_components':red,'blue_components':blue,'incident_components':incident,
                        'red_cumulative_reward':rv,'blue_cumulative_reward':bv,
                        'red_increment':rv-prev['red_cumulative_reward'],'blue_increment':bv-prev['blue_cumulative_reward'],
                        'measured_red_cpu_seconds':red_cpu,'measured_post_takeover_cpu_seconds':blue_cpu,'unattributed_outage_seconds':unknown_outage})
    for i,r in enumerate(results):
        for role in ('red','blue'):r[role+'_return']=sum(gamma**(j-i)*results[j][role+'_increment'] for j in range(i,len(results)))
    last=results[-1]
    return {'scored':True,'reward_version':VERSION,'match_id':spec['match_id'],'red_reward':last['red_cumulative_reward'],
            'blue_reward':last['blue_cumulative_reward'],'incident_loss':sum(weights[k]*v for k,v in last['incident_components'].items()),
            'takeover_t':takeover,'end_t':end,'rounds':results,'weights':weights,
            'semantics':'Red: attributable event outcomes. Blue: post-takeover new harm plus unresolved terminal state. One takeover per match; per-round increments telescope. First blue increment includes the constant initial credit of 1.'}


def score_rounds(root):
    try:
        root=Path(root);spec=json.loads((root/'match.json').read_text());rows=read_journal(root/'outcomes.jsonl')
        seal=json.loads((root/'completion.json').read_text());assets=json.loads((root/'private/assets.json').read_text())
        if not seal['evidence_complete'] or seal['outcome_head']!=rows[-1]['hash']:raise ValueError('incomplete or unsealed event ledger')
        if digest(assets)!=spec['asset_manifest_hash']:raise ValueError('asset manifest mismatch')
        return judge(spec,rows,assets)
    except (OSError,ValueError,TypeError,KeyError,StopIteration,IndexError) as e:
        return {'scored':False,'reward_version':VERSION,'blue_reward':None,'red_reward':None,'reason':str(e)}


def finalize(root):
    root=Path(root);s=score_rounds(root)
    if (root.with_name(root.name+'.case')).exists():
        verify_case(root.with_name(root.name+'.case'))
        if json.loads((root/'score.json').read_text())!=s:raise ValueError('immutable score changed')
        verify(root);return s
    write_json(root/'score.json',s,private=True)
    if s['scored']:
        write_json(root/'incident_outcome.json',{'loss':s['incident_loss'],'components':s['rounds'][-1]['incident_components']},private=True)
        write_json(root/'blue_reward.json',{'reward':s['blue_reward'],'components':s['rounds'][-1]['blue_components'],'takeover_t':s['takeover_t']},private=True)
        write_json(root/'red_reward.json',{'reward':s['red_reward'],'components':s['rounds'][-1]['red_components']},private=True)
        names=['match.json','completion.json','outcomes.jsonl','score.json','private/assets.json','blue_trajectory.jsonl','red_trajectory.jsonl','incident_outcome.json','blue_reward.json','red_reward.json']
        roles={}
        for role in ('red','blue'):
            rows=read_journal(root/(role+'_trajectory.jsonl'))
            if not rows or any(r['context_id']!=s['match_id'] for r in rows):raise ValueError('trajectory context mismatch')
            roles[role]={'reward':s[role+'_reward'],'model_trajectory':any(r['kind']=='model.output' for r in rows),'trajectory_head':rows[-1]['hash']}
        write_json(root/'training_binding.json',{'match_id':s['match_id'],'roles':roles,'files':{n:file_hash(root/n) for n in names},'supervision':'whole-match GRPO reward; round returns are audit data, not claimed token advantages','token_training_ready':False},private=True)
        verify(root)
    package_case(root,root.with_name(root.name+'.case'),{'title':'Responsibility-aware multi-round host match','summary':f"scored={s['scored']}; blue={s['blue_reward']}; red={s['red_reward']}",'evidence_context':'alternating_actions_continuous_guest_state','limitations':['Scripted red fixtures, not a trained adaptive red agent.','SSH probes trust guest OS/toolchain; attribution limited to declared closed-world workload and exclusive action windows.','Time-sampled losses are not continuous perfect observation. No model parameter update.']})
    verify_case(root.with_name(root.name+'.case'));return s


def verify(root):
    root=Path(root);b=json.loads((root/'training_binding.json').read_text())
    for name,h in b['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or file_hash(root/name)!=h:raise ValueError('artifact binding mismatch')
    s=score_rounds(root)
    if not s['scored'] or s['match_id']!=b['match_id']:raise ValueError('invalid reward context')
    for role in ('red','blue'):
        rows=read_journal(root/(role+'_trajectory.jsonl'))
        if any(r['context_id']!=b['match_id'] for r in rows) or rows[-1]['hash']!=b['roles'][role]['trajectory_head'] or s[role+'_reward']!=b['roles'][role]['reward']:raise ValueError('role reward binding mismatch')
    return {'verified':True,'blue_reward':s['blue_reward'],'red_reward':s['red_reward']}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('command',choices=['score','verify']);p.add_argument('directory',type=Path);a=p.parse_args()
    print(json.dumps({'score':score_rounds,'finalize':finalize,'verify':verify}[a.command](a.directory),indent=2))
