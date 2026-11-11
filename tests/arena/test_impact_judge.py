import asyncio,json
from pathlib import Path
import pytest
from test_rounds import fixture
from arena.storage import write_json
from arena.impact_judge import ImpactEvidence,render_score,validate_finding,validate_verdict,adjudicate_impact,load_impact_score
from arena.llm import OpenAIBlue


def prepare(root):
    s,j,a=fixture(root)
    write_json(root/'match.json',s);write_json(root/'private/assets.json',a)
    write_json(root/'completion.json',{'evidence_complete':True,'outcome_head':j.rows[-1]['hash']})
    return s


def answer(eid):
    return {'scorable':True,'reason':'Direct contextual Agent assessment','uncertainties':[],
            'rounds':[{'round_id':n,'red':{'reward':.43 if n==1 else .61,'reason':'Verified attack impact, not a metric fraction','evidence_ids':[eid]},
                       'blue':{'reward':.64 if n==1 else .79,'reason':'Recovery improves the response while history remains acknowledged','evidence_ids':[eid]},
                       'incident':{'assessment':'Observed consequences with stated limits','evidence_ids':[eid]}} for n in (1,2)]}


def test_old_weights_and_budgets_not_shown_to_new_agent(tmp_path):
    prepare(tmp_path);e=ImpactEvidence(tmp_path)
    view=e.call('overview',{})
    def check_keys(value):
        if isinstance(value,dict):
            assert not {'weights','weight','asset_budget','score','reward'} & set(value)
            for child in value.values():check_keys(child)
        elif isinstance(value,list):
            for child in value:check_keys(child)
    check_keys(view)
    assert all('weight' not in a for a in view['assets']['assets'])
    assert 'cpu_capacity' in view['contract']['source_scenario'] # factual hardware context survives


def test_reward_is_agent_value_not_weighted_loss_or_cpu_formula():
    v=answer('E1')
    a=render_score(v,{'match_id':'m','gamma':1,'weights':{'availability':1},'cpu_capacity':2})
    b=render_score(v,{'match_id':'m','gamma':1,'weights':{'availability':0},'cpu_capacity':10000})
    assert a==b
    assert a['blue_reward']==.79 and a['red_reward']==.61
    assert 'incident_loss' not in a
    assert a['rounds'][-1]['blue_increment']>0 # no hidden monotonic penalty rule


def test_qualitative_axes_cannot_smuggle_numeric_component_scores():
    v={'evidence_sufficient':True,'reason':'test','rounds':[{'round_id':1,**{r:{'assessment':'fact','evidence_ids':['E1'],'loss':.25} for r in ('red','blue','incident')}}]}
    with pytest.raises(ValueError):validate_finding(v,{'rounds':1},{'E1':{'tool':'read_events'}})


def test_full_impact_pipeline_and_resume_do_not_rerun_completed_findings(tmp_path,monkeypatch):
    prepare(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ICE_JUDGE_MODEL','test')
    state={'fail':True,'confidentiality':0}
    def generate(p,messages,timeout):
        scope=next((x for x in ('confidentiality','integrity','availability','remaining_access') if 'Investigate ONLY '+x+'.' in p.role),'overall')
        if scope=='confidentiality':state[scope]+=1
        if scope=='integrity' and state['fail']:raise TimeoutError('provider failure')
        results=[m for m in messages if m['role']=='tool']
        if not results:return {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'r','type':'function','function':{'name':'read_events','arguments':'{"kind":"snapshot","start":0,"count":2}'}}]}}]}
        eid=json.loads(results[-1]['content'])['evidence_id']
        if scope=='overall':v=answer(eid)
        else:v={'evidence_sufficient':True,'reason':'Scope assessed','uncertainties':[],'rounds':[{'round_id':n,**{r:{'assessment':'Contextual evidence, no numeric component score','evidence_ids':[eid]} for r in ('red','blue','incident')}} for n in (1,2)]}
        return {'choices':[{'message':{'role':'assistant','content':json.dumps(v)},'finish_reason':'stop'}]}
    monkeypatch.setattr(OpenAIBlue,'_generate',generate)
    with pytest.raises(TimeoutError):asyncio.run(adjudicate_impact(tmp_path))
    assert not (tmp_path/'judge_verdict.json').exists()
    calls=state['confidentiality'];state['fail']=False
    result=asyncio.run(adjudicate_impact(tmp_path,resume=True))
    assert state['confidentiality']==calls
    assert result['blue_reward']==.79 and result['red_reward']==.61
    assert load_impact_score(tmp_path)==result
    (tmp_path/'impact_findings/availability.json').write_text('{}')
    with pytest.raises(ValueError):load_impact_score(tmp_path)


def test_current_entry_rejects_metric_based_resume(tmp_path):
    from arena.impact_judge import adjudicate_impact as judge_match
    from arena.storage import Journal
    prepare(tmp_path)
    j=Journal(tmp_path/'judge_trajectory.jsonl','m')
    j.append('judge.input',{'messages':[],'axis':'availability'})
    with pytest.raises(ValueError,match='metric-based'):
        asyncio.run(judge_match(tmp_path,resume=True))


def test_impact_reward_binds_and_packages_without_axis_weights(tmp_path,monkeypatch):
    from arena.round_scoring import finalize,verify
    from arena.storage import Journal
    prepare(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ICE_JUDGE_MODEL','test')
    def generate(p,messages,timeout):
        scope=next((x for x in ('confidentiality','integrity','availability','remaining_access') if 'Investigate ONLY '+x+'.' in p.role),'overall')
        tools=[m for m in messages if m['role']=='tool']
        if not tools:return {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'r','type':'function','function':{'name':'read_events','arguments':'{"kind":"snapshot","start":0,"count":2}'}}]}}]}
        eid=json.loads(tools[-1]['content'])['evidence_id']
        v=answer(eid) if scope=='overall' else {'evidence_sufficient':True,'reason':'facts','uncertainties':[],'rounds':[{'round_id':n,**{r:{'assessment':'observed context','evidence_ids':[eid]} for r in ('red','blue','incident')}} for n in (1,2)]}
        return {'choices':[{'message':{'role':'assistant','content':json.dumps(v)},'finish_reason':'stop'}]}
    monkeypatch.setattr(OpenAIBlue,'_generate',generate)
    asyncio.run(adjudicate_impact(tmp_path))
    for role in ('red','blue'):
        j=Journal(tmp_path/(role+'_trajectory.jsonl'),'m');j.append('model.output' if role=='blue' else 'fixture.action',{'round_id':1})
    result=finalize(tmp_path)
    assert result['blue_reward']==.79
    assert verify(tmp_path)['blue_reward']==.79
    assert json.loads((tmp_path/'blue_reward.json').read_text())['assessment']['reward']==.79
    assert 'loss' not in json.loads((tmp_path/'incident_outcome.json').read_text())
    assert finalize(tmp_path)==result
