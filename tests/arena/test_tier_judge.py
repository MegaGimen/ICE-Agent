import asyncio,json
from pathlib import Path
import pytest
from test_rounds import fixture
from arena.storage import Journal,write_json
from arena.judge_tools import AXES
from arena.tier_judge import DEFAULT_PROFILE,adjudicate_tiers,load_tier_score,axis_for
from arena.llm import OpenAIBlue


def prepare(root):
    s,j,a=fixture(root)
    write_json(root/'match.json',s);write_json(root/'private/assets.json',a)
    write_json(root/'completion.json',{'evidence_complete':True,'outcome_head':j.rows[-1]['hash']})
    return s


def response(profile,axis,eid):
    rounds=[]
    for n in (1,2):
        row={'round_id':n}
        for role in ('red','blue','incident'):
            label='none'
            if axis=='confidentiality':label='credentials' if role in ('red','incident') else ('none' if n==1 else 'user_data')
            a=axis_for(profile,'red' if role=='incident' else role,axis)
            row[role]={'tier':label,'criterion':a['tiers'][label]['criterion'],'reason':'observed test evidence supports this semantic criterion','evidence_ids':[eid]}
        rounds.append(row)
    return {'scorable':True,'reason':'bounded assessment','uncertainties':[],'rounds':rounds}


def test_tiers_survive_api_failure_resume_and_bind_to_cases(tmp_path,monkeypatch):
    from arena.round_scoring import finalize,verify
    prepare(tmp_path);profile=json.loads(DEFAULT_PROFILE.read_text())
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ICE_JUDGE_MODEL','test')
    state={'fail':True,'c_calls':0}
    def generate(p,messages,timeout):
        axis=next(a for a in AXES if 'THIS PASS JUDGES ONLY '+a+'.' in p.role)
        if axis=='confidentiality':state['c_calls']+=1
        if axis=='integrity' and state['fail']:raise TimeoutError('provider down')
        outputs=[m for m in messages if m['role']=='tool']
        if not outputs:return {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'r','type':'function','function':{'name':'read_events','arguments':'{"kind":"snapshot","start":0,"count":3}'}}]}}]}
        eid=json.loads(outputs[-1]['content'])['evidence_id']
        return {'choices':[{'message':{'role':'assistant','content':json.dumps(response(profile,axis,eid))},'finish_reason':'stop'}]}
    monkeypatch.setattr(OpenAIBlue,'_generate',generate)
    with pytest.raises(TimeoutError):asyncio.run(adjudicate_tiers(tmp_path))
    assert not (tmp_path/'judge_verdict.json').exists()
    saved=(tmp_path/'tier_verdicts/confidentiality.json').read_bytes();calls=state['c_calls'];state['fail']=False
    score=asyncio.run(adjudicate_tiers(tmp_path,resume=True))
    assert state['c_calls']==calls and (tmp_path/'tier_verdicts/confidentiality.json').read_bytes()==saved
    assert score['red_reward']==pytest.approx(.24)
    assert score['blue_reward']==pytest.approx(.925)
    assert score['rounds'][0]['blue_reward']==1
    for role in ('red','blue'):
        j=Journal(tmp_path/(role+'_trajectory.jsonl'),'m');j.append('model.output' if role=='blue' else 'fixture.action',{'round_id':1})
    assert finalize(tmp_path)['scored'] and verify(tmp_path)['verified']
    assert load_tier_score(tmp_path)==score
    profile_file=tmp_path/'tier_profile.json';altered=json.loads(profile_file.read_text());altered['blue']['base']=.8;write_json(profile_file,altered)
    with pytest.raises(ValueError):load_tier_score(tmp_path)


def test_free_decimal_cannot_bypass_tier_contract(tmp_path):
    from arena.tier_judge import validate_axis
    spec=prepare(tmp_path);profile=json.loads(DEFAULT_PROFILE.read_text())
    v=response(profile,'availability','E1');v['rounds'][0]['blue']['reward']=.55
    with pytest.raises(ValueError):validate_axis(v,spec,{'E1':{'tool':'read_events'}},profile,'availability')


def test_approved_ladders_and_profile_weights_are_explicit():
    profile=json.loads(DEFAULT_PROFILE.read_text())
    for role in ('red','blue'):
        assert sum(a['weight'] for a in profile[role]['axes'])==1
        assert list(axis_for(profile,role,'remaining_access')['tiers'])==['none','minor','significant','severe']
        assert [v['value'] for v in axis_for(profile,role,'integrity')['tiers'].values()]==[0,.02,.05,.1,.25,.5,.8,1]
