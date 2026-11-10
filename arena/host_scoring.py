"""Versioned four-axis host outcome judge. No model prose or commands enter scoring."""
import hashlib
import json
import math
from pathlib import Path
from .contracts import RewardProfile, canonical, digest
from .storage import read_journal, write_json

VERSION='host-outcome-v1'


def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()


def score_host(directory):
    try:return _score(Path(directory))
    except (ValueError,KeyError,TypeError,OSError,ZeroDivisionError) as exc:
        return {'scored':False,'blue_reward':None,'red_reward':None,'reward_version':VERSION,'reason':[str(exc)]}


def _score(root):
    spec=json.loads((root/'match.json').read_text())
    if spec['reward_version']!=VERSION:raise ValueError('unknown reward version')
    profile=RewardProfile(version=VERSION,weights=spec['weights']);profile.validate()
    events=read_journal(root/'outcomes.jsonl')
    if not events or any(r['context_id']!=spec['match_id'] for r in events):raise ValueError('wrong match context')
    if events[0]['kind']!='match.spec' or events[0]['data']['digest']!=digest(spec):raise ValueError('spec binding mismatch')
    seal=json.loads((root/'completion.json').read_text())
    if not seal['evidence_complete']:raise ValueError('incomplete evidence: '+str(seal['errors']))
    if seal['outcome_head']!=events[-1]['hash']:raise ValueError('outcome seal mismatch')
    manifest=json.loads((root/'private/assets.json').read_text())
    if digest(manifest)!=spec['asset_manifest_hash']:raise ValueError('asset manifest mismatch')
    phases={k:[r for r in events if r['kind']==k] for k in ('baseline','armed','final','closed')}
    if any(len(rows)!=1 for rows in phases.values()):raise ValueError('missing or duplicate T0/T1/T2/closure')
    observations=[r for r in events if r['kind'] in ('baseline','armed','sample','final')]
    if any(not r['data'].get('valid') for r in observations):raise ValueError('invalid outcome observation')
    samples=[r for r in events if r['kind']=='sample']
    if len(samples)<spec['minimum_samples']:raise ValueError('insufficient time coverage')
    baseline=phases['baseline'][0]['data'];final=phases['final'][0]['data']
    points=[phases['armed'][0],*samples,phases['final'][0]]
    times=[r['data']['offset'] for r in points]
    if times!=sorted(times) or times[-1]<spec['duration_seconds']:raise ValueError('window incomplete or reordered')
    if max(b-a for a,b in zip(times,times[1:]))>spec['max_probe_gap_seconds']:raise ValueError('unobserved interval too large')
    expected_endpoints={e['name'] for e in spec['probe']['endpoints']}
    expected_files=set(spec['probe']['files']);expected_units=set(spec['probe']['units'])
    for row in observations:
        data=row['data']
        if set(data['endpoints'])!=expected_endpoints or set(data['files'])!=expected_files or set(data['units'])!=expected_units:raise ValueError('incomplete observation coverage')
        if not isinstance(data['processes'],list):raise ValueError('invalid process observation')
        if data['clock_ticks_per_second']<=0:raise ValueError('invalid CPU clock')
    if not expected_endpoints or not all(v['ok'] for v in baseline['endpoints'].values()):raise ValueError('business baseline not healthy')
    if any(baseline['files'].get(p) is None for p in spec['protected_files']):raise ValueError('protected file absent at T0')
    if baseline['processes']:raise ValueError('unauthorized execution predates baseline')
    items=[('files',p) for p in spec['protected_files']]+[('units',u) for u in spec['protected_units']]
    if not items:raise ValueError('empty integrity scope')
    def integrity(data):
        return sum((data[k][p]['is-enabled']!=baseline[k][p]['is-enabled']) if k=='units' else (data[k][p]!=baseline[k][p]) for k,p in items)/len(items)
    integrity_loss=max(integrity(r['data']) for r in points)
    business_loss=sum(sum(not x['ok'] for x in r['data']['endpoints'].values())/len(expected_endpoints) for r in samples)/len(samples)
    # Measured process CPU tick increments only, within a fixed declared horizon.
    # Exited processes may lose their last sub-interval: explicitly a sampled lower bound.
    seen={};cpu_seconds=0.0
    for row in points:
        data=row['data']
        for p in data['processes']:
            key=(p['pid'],p['start_ticks']);ticks=p['cpu_ticks']
            if ticks<0:raise ValueError('negative CPU counter')
            if key in seen:
                if ticks<seen[key]:raise ValueError('CPU counter went backwards')
                cpu_seconds+=(ticks-seen[key])/data['clock_ticks_per_second']
            seen[key]=ticks
    capacity=spec['cpu_capacity']
    if not math.isfinite(capacity) or capacity<=0:raise ValueError('invalid CPU capacity')
    resource_loss=min(1,cpu_seconds/(spec['duration_seconds']*capacity))
    channels=[]
    for c in spec['access_channels']:
        active=final['units'][c['unit']]['is-active']=='active'
        enabled=final['units'][c['unit']]['is-enabled'] in ('enabled','enabled-runtime')
        runnable=final['files'][c['executable']] is not None
        if runnable and (active or enabled):
            command=final['units'][c['unit']].get('exec_start')
            if command is None:raise ValueError('effective restart command not observed')
            if c['executable'] in command and (not c.get('sha256') or final['files'][c['executable']]==c['sha256']):
                channels.append(c['unit'])
    # This scenario declares execution/restart channels, not an invented remote login shell.
    access_loss=float(bool(final['processes'] or channels))
    receipt_rows=read_journal(root/'private/deliveries.jsonl') if (root/'private/deliveries.jsonl').exists() else []
    if any(r['context_id']!=spec['match_id'] for r in receipt_rows):raise ValueError('receipt context mismatch')
    if seal['delivery_head']!=(receipt_rows[-1]['hash'] if receipt_rows else None):raise ValueError('receipt seal mismatch')
    if not seal['receipt_collection_complete']:raise ValueError('receipt coverage unknown')
    assets={a['id']:a for a in manifest['assets']}; acquired=set(); findings=[]
    if not assets or any(a['weight']<=0 for a in assets.values()):raise ValueError('invalid asset budget')
    for r in receipt_rows:
        d=r['data'];a=assets.get(d['asset_id'])
        ok=a is not None and canonical(a['value'])==canonical(d['value'])
        findings.append({'receipt':d['receipt'],'verified':ok,'asset_id':d['asset_id']})
        if ok:acquired.add(a['id'])
    confidentiality=sum(assets[k]['weight'] for k in acquired)/sum(a['weight'] for a in assets.values())
    losses={'confidentiality':confidentiality,'integrity':integrity_loss,'availability':max(business_loss,resource_loss),'remaining_access':access_loss}
    if any(not math.isfinite(x) or not 0<=x<=1 for x in losses.values()):raise ValueError('invalid loss')
    components={k:{'loss':v,'weight':profile.weights[k],'deduction':v*profile.weights[k]} for k,v in losses.items()}
    reward=round(1-sum(x['deduction'] for x in components.values()),8)
    return {'scored':True,'reward_version':VERSION,'match_id':spec['match_id'],'blue_reward':reward,'red_reward':-reward,
            'components':components,'business_probe_count':len(samples),'business_loss':business_loss,
            'observed_unauthorized_cpu_seconds':cpu_seconds,'resource_loss':resource_loss,
            'remaining_channels':channels,'acquired_assets':sorted(acquired),'delivery_findings':findings,
            'outcome_head':seal['outcome_head'],'scope':spec['coverage'],
            'semantics':'Historical verified delivery and peak protected-state loss; sampled business/resource loss; final effective declared execution/access channels.'}


def bind_training(root,score):
    root=Path(root)
    rows=read_journal(root/'blue_trajectory.jsonl')
    if not rows or any(r['context_id']!=score.get('match_id') for r in rows):raise ValueError('trajectory belongs to another match')
    if score_host(root)!=score:raise ValueError('reward does not match evidence')
    model_trajectory=any(r['kind']=='model.output' for r in rows)
    binding={'schema':'arena.host-training-binding.v1','match_id':score['match_id'],'reward':score['blue_reward'],
             'training_signal_ready':score['scored'] and model_trajectory,'outcome_reward_ready':score['scored'],
             'policy_kind':'model' if model_trajectory else 'scripted_control','token_training_ready':False,
             'note':'Trainer must still collect token IDs, action masks and behavior log probabilities.',
             'files':{p:file_hash(root/p) for p in ('match.json','completion.json','outcomes.jsonl','blue_trajectory.jsonl','score.json','private/assets.json')},
             'trajectory_head':rows[-1]['hash']}
    if (root/'private/deliveries.jsonl').exists():binding['files']['private/deliveries.jsonl']=file_hash(root/'private/deliveries.jsonl')
    write_json(root/'training_binding.json',binding,private=True)
    return binding


def verify_training(root):
    root=Path(root);binding=json.loads((root/'training_binding.json').read_text())
    for p,h in binding['files'].items():
        if Path(p).is_absolute() or '..' in Path(p).parts:raise ValueError('invalid binding path')
        if file_hash(root/p)!=h:raise ValueError('training artifact changed: '+p)
    actual=score_host(root)
    if not actual['scored'] or actual['blue_reward']!=binding['reward'] or actual['match_id']!=binding['match_id']:raise ValueError('reward binding mismatch')
    rows=read_journal(root/'blue_trajectory.jsonl')
    if any(r['context_id']!=binding['match_id'] for r in rows) or rows[-1]['hash']!=binding['trajectory_head']:raise ValueError('trajectory binding mismatch')
    return {'verified':True,'match_id':binding['match_id'],'reward':binding['reward']}


def finalize_host(root):
    from .cases import package_case,verify_case
    root=Path(root)
    result=score_host(root)
    case_path=root.with_name(root.name+'.case')
    if case_path.exists():
        verify_case(case_path)
        archived=json.loads((case_path/'private/raw/score.json').read_text())
        if archived!=result:raise ValueError('sealed case has a different score; create a new version')
    write_json(root/'score.json',result,private=True)
    if result['scored']:
        if not (root/'training_binding.json').exists():bind_training(root,result)
        verify_training(root)
    else:
        write_json(root/'training_binding.json',{'training_signal_ready':False,'reason':result['reason']},private=True)
    case_path=root.with_name(root.name+'.case')
    if not case_path.exists():
        spec=json.loads((root/'match.json').read_text())
        package_case(root,case_path,{
            'title':'Scored host defence rollout','summary':f"Scored: {result['scored']}; blue reward: {result['blue_reward']}",
            'evidence_context':'controller_observed_host_outcomes',
            'findings':[{'basis':'independent_outcome_judge','summary':f"{k}: loss {v['loss']}, deduction {v['deduction']}",'evidence_refs':['score.json','outcomes.jsonl']} for k,v in result.get('components',{}).items()],
            'limitations':[spec['coverage'],'CPU loss is a sampled lower bound. Invalid evidence is not assigned zero loss.','No parameter update performed; token-level training metadata is learner-owned.']})
    verify_case(case_path)
    for name in ('score.json','training_binding.json','blue_trajectory.jsonl','outcomes.jsonl'):
        if file_hash(root/name)!=file_hash(case_path/'private/raw'/name):raise ValueError('case/run artifact mismatch: '+name)
    return {'directory':str(root),'score':result,'case_verified':True}


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('command',choices=['score','finalize','verify']);p.add_argument('directory',type=Path)
    args=p.parse_args()
    result={'score':score_host,'finalize':finalize_host,'verify':verify_training}[args.command](args.directory)
    print(json.dumps(result,ensure_ascii=False,indent=2))
