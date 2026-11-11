"""New rollouts require the judge Agent. No rule-based scoring fallback."""
import json
from pathlib import Path
from .judge_agent import VERSION,load_score
from .host_scoring import file_hash
from .storage import read_journal,write_json
from .cases import package_case,verify_case


def score_rounds(root):
    try:return load_score(root)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        return {'scored':False,'judge_kind':'agent_required','blue_reward':None,'red_reward':None,'reason':str(exc)}


def finalize(root):
    root=Path(root);s=score_rounds(root);case=root.with_name(root.name+'.case')
    if case.exists():
        verify_case(case)
        if json.loads((root/'score.json').read_text())!=s:raise ValueError('preserve prior verdict; create a new adjudication bundle')
        if s['scored']:verify(root)
        return s
    write_json(root/'score.json',s,private=True)
    if s['scored']:
        verdict=json.loads((root/'judge_verdict.json').read_text())
        for role in ('red','blue'):
            write_json(root/(role+'_reward.json'),{'reward':s[role+'_reward'],'assessment':verdict['rounds'][-1][role],'judge_kind':'agent','profile_id':s.get('profile_id'),'contributions':s['rounds'][-1].get('components',{}).get(role)},private=True)
        incident={'assessment':verdict['rounds'][-1]['incident'],'judge_kind':'agent'}
        if 'incident_loss' in s:incident['historical_v3_loss']=s['incident_loss']
        write_json(root/'incident_outcome.json',incident,private=True)
        roles={}
        for role in ('red','blue'):
            rows=read_journal(root/(role+'_trajectory.jsonl'))
            if not rows or any(r['context_id']!=s['match_id'] for r in rows):raise ValueError('trajectory context mismatch')
            roles[role]={'reward':s[role+'_reward'],'model_trajectory':any(r['kind']=='model.output' for r in rows),'trajectory_head':rows[-1]['hash']}
        names=['match.json','completion.json','outcomes.jsonl','private/assets.json','score.json','judge_verdict.json','judge_seal.json','judge_trajectory.jsonl','red_trajectory.jsonl','blue_trajectory.jsonl','red_reward.json','blue_reward.json','incident_outcome.json']
        write_json(root/'training_binding.json',{'match_id':s['match_id'],'judge_kind':'agent','reward_version':s.get('reward_version'),'judgment_hash':file_hash(root/'judge_seal.json'),'roles':roles,'files':{n:file_hash(root/n) for n in names},'token_training_ready':False,'supervision':'whole-match Agent rewards; per-round returns are audit values, not token advantages'},private=True)
        verify(root)
    package_case(root,case,{'title':'Agent-judged multi-round host defence','summary':f"judge=Agent; scored={s['scored']}; blue={s['blue_reward']}; red={s['red_reward']}",'evidence_context':'agent_investigation_over_controller_evidence','limitations':['Judge findings and scores are model judgments with cited evidence, not infallible ground truth.','Live guest inspection is after-match state, not retrospective proof of missing history.','No rule-based substitute when the judge fails or evidence is insufficient.','Scripted red fixture; no optimizer update.']})
    verify_case(case);return s


def verify(root):
    root=Path(root);b=json.loads((root/'training_binding.json').read_text())
    if b.get('judge_kind')!='agent':raise ValueError('Agent judgment required')
    for n,h in b['files'].items():
        if Path(n).is_absolute() or '..' in Path(n).parts or file_hash(root/n)!=h:raise ValueError('bound artifact changed')
    s=load_score(root)
    if not s['scored'] or s['match_id']!=b['match_id']:raise ValueError('invalid judgment')
    for role in ('red','blue'):
        rows=read_journal(root/(role+'_trajectory.jsonl'))
        if any(r['context_id']!=b['match_id'] for r in rows) or rows[-1]['hash']!=b['roles'][role]['trajectory_head'] or s[role+'_reward']!=b['roles'][role]['reward']:raise ValueError('reward/trajectory mismatch')
    return {'verified':True,'judge_kind':'agent','blue_reward':s['blue_reward'],'red_reward':s['red_reward']}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('command',choices=['score','finalize','verify']);p.add_argument('directory',type=Path);a=p.parse_args()
    print(json.dumps({'score':score_rounds,'finalize':finalize,'verify':verify}[a.command](a.directory),indent=2))
