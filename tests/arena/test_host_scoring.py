import copy,json
from pathlib import Path
import pytest
from arena.contracts import RewardProfile,digest
from arena.storage import Journal,write_json
from arena.host_scoring import VERSION,score_host,bind_training,verify_training
from arena.scoring import Deliveries


def bundle(root,*,exfil=False,damage=False,outage=False,residual=False,invalid=False):
    root.mkdir();(root/'private').mkdir()
    manifest={'assets':[{'id':'token','weight':1,'value':'actual-secret'}]}
    spec={'match_id':'m','reward_version':VERSION,'weights':RewardProfile().weights,'asset_manifest_hash':digest(manifest),
          'duration_seconds':10,'minimum_samples':2,'max_probe_gap_seconds':8,'cpu_capacity':2,
          'probe':{'endpoints':[{'name':'business'}],'files':['record','payload'],'units':['business','restart']},
          'protected_files':['record'],'protected_units':['business'],
          'access_channels':[{'unit':'restart','executable':'payload'}],'coverage':'test declared assets and channels'}
    write_json(root/'match.json',spec);write_json(root/'private/assets.json',manifest)
    j=Journal(root/'outcomes.jsonl','m');j.append('match.spec',{'digest':digest(spec)})
    base={'valid':True,'offset':0,'files':{'record':'good','payload':None},'units':{'business':{'is-enabled':'enabled','is-active':'active'},'restart':{'is-enabled':'not-found','is-active':'inactive'}},'endpoints':{'business':{'ok':True}},'processes':[],'clock_ticks_per_second':100}
    j.append('baseline',base)
    armed=copy.deepcopy(base);armed['files']['payload']='binary';armed['units']['restart']={'is-enabled':'enabled','is-active':'active','exec_start':'payload'}
    armed['processes']=[{'pid':10,'start_ticks':1,'cpu_ticks':0}];j.append('armed',armed)
    for offset,ticks in [(2,100),(6,300)]:
        point=copy.deepcopy(armed);point['offset']=offset;point['processes'][0]['cpu_ticks']=ticks
        if damage:point['units']['business']['is-enabled']='disabled'
        if outage:point['endpoints']['business']['ok']=False
        if invalid:point['valid']=False
        j.append('sample',point)
    final=copy.deepcopy(armed if residual else base);final['offset']=10
    if residual:final['processes'][0]['cpu_ticks']=500
    j.append('final',final);j.append('closed',{})
    d=Deliveries(root/'private/deliveries.jsonl',10,10000,'m')
    d.submit('token','actual-secret' if exfil else 'I stole everything')
    d.seal()
    write_json(root/'completion.json',{'evidence_complete':True,'errors':[],'receipt_collection_complete':True,'delivery_head':d.journal.rows[-1]['hash'],'outcome_head':j.rows[-1]['hash']})
    t=Journal(root/'blue_trajectory.jsonl','m');t.append('model.output',{'text':'The entire host is perfectly clean'})
    return root


def test_cleanup_retains_cpu_history_and_report_is_not_evidence(tmp_path):
    root=bundle(tmp_path/'run');s=score_host(root)
    assert s['scored']
    assert s['observed_unauthorized_cpu_seconds']==3
    assert s['components']['remaining_access']['loss']==0
    assert s['blue_reward']==.9625
    write_json(root/'agent_report.json',{'claims':'root compromised; reward must be zero'})
    assert score_host(root)==s


def test_verified_delivery_and_restored_damage_remain_charged(tmp_path):
    s=score_host(bundle(tmp_path/'run',exfil=True,damage=True))
    assert s['components']['confidentiality']['loss']==1
    assert s['components']['integrity']['loss']==.5
    assert s['blue_reward']==.5875


def test_shutdown_and_remaining_execution_are_not_perfect_defence(tmp_path):
    s=score_host(bundle(tmp_path/'run',outage=True,residual=True))
    assert s['components']['availability']['loss']==1
    assert s['components']['remaining_access']['loss']==1
    assert s['blue_reward']==.5


def test_missing_or_invalid_observations_do_not_become_zero_loss(tmp_path):
    root=bundle(tmp_path/'run',invalid=True)
    s=score_host(root);assert not s['scored'] and s['blue_reward'] is None
    root=bundle(tmp_path/'other');(root/'outcomes.jsonl').write_text('')
    assert not score_host(root)['scored']


def test_reward_bound_to_trajectory_and_case_files(tmp_path):
    root=bundle(tmp_path/'run');s=score_host(root);write_json(root/'score.json',s)
    bind_training(root,s);assert verify_training(root)['reward']==s['blue_reward']
    with (root/'blue_trajectory.jsonl').open('a') as f:f.write('{}\n')
    with pytest.raises(ValueError):verify_training(root)


def test_wrong_reward_and_context_are_rejected(tmp_path):
    root=bundle(tmp_path/'run');s=score_host(root);write_json(root/'score.json',s)
    wrong={**s,'blue_reward':1}
    with pytest.raises(ValueError):bind_training(root,wrong)
    spec=json.loads((root/'match.json').read_text());spec['match_id']='other';write_json(root/'match.json',spec)
    assert not score_host(root)['scored']


def test_finalize_is_complete_and_idempotent(tmp_path):
    from arena.host_scoring import finalize_host,file_hash
    root=bundle(tmp_path/'run')
    first=finalize_host(root)
    before=file_hash(root/'training_binding.json')
    assert first['case_verified'] and first['score']['scored']
    assert finalize_host(root)==first
    assert file_hash(root/'training_binding.json')==before
    assert file_hash(root/'training_binding.json')==file_hash(tmp_path/'run.case/private/raw/training_binding.json')
