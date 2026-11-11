import asyncio,json,subprocess,sys
import pytest
from arena.judge_agent import Evidence,INSPECT,aggregate,adjudicate,load_score,validate,calculate
from arena.round_scoring import score_rounds
from arena.storage import write_json
from test_rounds import fixture


def prepare_fixture(tmp_path):
    s,j,a=fixture(tmp_path)
    write_json(tmp_path/'match.json',s);write_json(tmp_path/'private/assets.json',a)
    write_json(tmp_path/'completion.json',{'evidence_complete':True,'outcome_head':j.rows[-1]['hash']})
    return s


def verdict(value):
    return {'scorable':True,'reason':'test Agent judgment','rounds':[{'round_id':n,**{role:{axis:{'loss':value if axis=='confidentiality' else 0,'evidence_ids':['E0002'],'reason':'based on fetched test evidence'} for axis in ('confidentiality','integrity','availability','remaining_access')} for role in ('red','blue','incident')}} for n in (1,2)],'uncertainties':[]}


def test_no_rule_judge_fallback_even_when_raw_evidence_complete(tmp_path):
    prepare_fixture(tmp_path);s=score_rounds(tmp_path)
    assert not s['scored'] and s['judge_kind']=='agent_required'


def test_agent_verdict_not_rule_result_controls_score(tmp_path,monkeypatch):
    from arena.llm import OpenAIBlue
    prepare_fixture(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ARENA_BLUE_MODEL','test')
    responses=iter([
      {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'read','type':'function','function':{'name':'read_events','arguments':'{"kind":"delivery","start":0,"count":5}'}}]}}]},
      {'choices':[{'message':{'role':'assistant','content':json.dumps(verdict(.4))},'finish_reason':'stop'}]},
      {'choices':[{'message':{'role':'assistant','content':json.dumps(verdict(.3))},'finish_reason':'stop'}]}])
    monkeypatch.setattr(OpenAIBlue,'_generate',lambda *a:next(responses))
    result=asyncio.run(adjudicate(tmp_path))
    assert result['blue_reward']==.925 and result['red_reward']==.075
    assert load_score(tmp_path)==result
    (tmp_path/'judge_verdict.json').write_text(json.dumps(verdict(0)))
    with pytest.raises(ValueError):load_score(tmp_path)


def test_invalid_evidence_references_rejected_not_replaced():
    v=verdict(.2)
    with pytest.raises(ValueError):validate(v,{'rounds':2},{})
    with pytest.raises(ValueError):calculate('__import__("os").system("true")')
    assert calculate('(20-5)/30')==.5


def test_path_inspection_does_not_execute_and_handles_directory_fifo_binary(tmp_path):
    directory=tmp_path/'slot';directory.mkdir()
    for path,expected in [(directory,'directory'),(tmp_path/'missing','missing')]:
        p=subprocess.run([sys.executable,'-c',INSPECT,str(path)],capture_output=True,text=True,check=True)
        assert json.loads(p.stdout)['type']==expected
    import os
    fifo=tmp_path/'pipe';os.mkfifo(fifo)
    got=subprocess.run([sys.executable,'-c',INSPECT,str(fifo)],capture_output=True,text=True,check=True,timeout=2)
    assert json.loads(got.stdout)['type']=='special; not opened'
    marker=tmp_path/'executed';script=tmp_path/'payload.sh';script.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');script.chmod(0o700)
    subprocess.run([sys.executable,'-c',INSPECT,str(script)],capture_output=True,text=True,check=True)
    assert not marker.exists()
    binary=tmp_path/'sample';binary.write_bytes(b'\x7fELF\x00hello')
    p=subprocess.run([sys.executable,'-c',INSPECT,str(binary)],capture_output=True,text=True,check=True)
    assert json.loads(p.stdout)['content'].startswith('binary head hex:')


def test_file_becomes_directory_does_not_abort_other_observations(tmp_path):
    from arena.guest_probe import GUEST_SCRIPT
    p=tmp_path/'slot';p.mkdir()
    result=subprocess.run([sys.executable,'-c',GUEST_SCRIPT,json.dumps({'files':[str(p),str(tmp_path/'gone')],'units':[],'endpoints':[]})],capture_output=True,text=True,check=True)
    data=json.loads(result.stdout)
    assert data['files'][str(p)]=='nonregular:directory'
    assert data['files'][str(tmp_path/'gone')] is None


def test_resume_keeps_original_judge_audit_and_does_not_fallback(tmp_path,monkeypatch):
    from arena.llm import OpenAIBlue
    from arena.storage import read_journal
    prepare_fixture(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ARENA_BLUE_MODEL','test')
    def fail(*args):raise TimeoutError('provider timeout')
    monkeypatch.setattr(OpenAIBlue,'_generate',fail)
    with pytest.raises(TimeoutError):asyncio.run(adjudicate(tmp_path))
    original=(tmp_path/'judge_trajectory.jsonl').read_bytes()
    assert not score_rounds(tmp_path)['scored']
    responses=iter([
      {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'read','type':'function','function':{'name':'read_events','arguments':'{"kind":"delivery","start":0,"count":5}'}}]}}]},
      {'choices':[{'message':{'role':'assistant','content':json.dumps(verdict(.2))},'finish_reason':'stop'}]},
      {'choices':[{'message':{'role':'assistant','content':json.dumps(verdict(.2))},'finish_reason':'stop'}]}])
    monkeypatch.setattr(OpenAIBlue,'_generate',lambda *args:next(responses))
    result=asyncio.run(adjudicate(tmp_path,resume=True))
    assert result['scored']
    assert (tmp_path/'judge_trajectory.jsonl').read_bytes().startswith(original)
    assert any(r['kind']=='judge.resume' for r in read_journal(tmp_path/'judge_trajectory.jsonl'))


def test_budget_failure_does_not_forge_an_agent_verdict(tmp_path,monkeypatch):
    from arena.llm import OpenAIBlue
    prepare_fixture(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ARENA_BLUE_MODEL','test')
    monkeypatch.setattr(OpenAIBlue,'_generate',lambda *args:{'choices':[{'message':{'role':'assistant','content':'not a valid judgment'},'finish_reason':'stop'}]})
    result=asyncio.run(adjudicate(tmp_path))
    assert not result['scored'] and result['blue_reward'] is None
    assert not (tmp_path/'judge_verdict.json').exists()
    assert json.loads((tmp_path/'judge_failure.json').read_text())['source']=='controller'


def test_axis_panel_assembles_only_agent_values_and_keeps_axis_evidence(tmp_path,monkeypatch):
    from arena.llm import OpenAIBlue
    from arena.judge_agent import adjudicate_axes,AXES
    prepare_fixture(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ARENA_BLUE_MODEL','test')
    def generate(provider,messages,timeout):
        axis=next(a for a in AXES if ('THIS INVESTIGATION IS ONLY FOR '+a+'.') in provider.role)
        tools=[m for m in messages if m['role']=='tool']
        if not tools:return {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'read','type':'function','function':{'name':'read_events','arguments':'{"kind":"snapshot","start":0,"count":2}'}}]}}]}
        eid=json.loads(tools[-1]['content'])['evidence_id']
        value=.2 if axis=='integrity' else 0
        part={'scorable':True,'reason':'Agent-chosen value for test','uncertainties':[],'rounds':[{'round_id':n,**{r:{axis:{'loss':value,'evidence_ids':[eid],'reason':'observed test evidence'}} for r in ('red','blue','incident')}} for n in (1,2)]}
        return {'choices':[{'message':{'role':'assistant','content':json.dumps(part)},'finish_reason':'stop'}]}
    monkeypatch.setattr(OpenAIBlue,'_generate',generate)
    result=asyncio.run(adjudicate_axes(tmp_path))
    assert result['red_reward']==.05 and result['blue_reward']==.95
    assert len(list((tmp_path/'judge_axes').glob('*.json')))==4
    assert load_score(tmp_path)==result
    (tmp_path/'judge_axes/integrity.json').write_text('{}')
    with pytest.raises(ValueError):load_score(tmp_path)


def test_axis_resume_reuses_sealed_complete_axes_without_new_model_calls(tmp_path,monkeypatch):
    from arena.llm import OpenAIBlue
    from arena.judge_agent import adjudicate_axes,AXES,judge_match
    prepare_fixture(tmp_path)
    monkeypatch.setenv('ARENA_BLUE_BASE_URL','https://example.org');monkeypatch.setenv('ICE_JUDGE_MODEL','test')
    state={'fail':True,'confidentiality_calls':0}
    def generate(provider,messages,timeout):
        axis=next(a for a in AXES if ('THIS INVESTIGATION IS ONLY FOR '+a+'.') in provider.role)
        if axis=='confidentiality':state['confidentiality_calls']+=1
        if axis=='integrity' and state['fail']:raise TimeoutError('interrupted provider')
        got=[m for m in messages if m['role']=='tool']
        if not got:return {'choices':[{'message':{'role':'assistant','tool_calls':[{'id':'r','type':'function','function':{'name':'read_events','arguments':'{"kind":"snapshot","start":0,"count":2}'}}]}}]}
        eid=json.loads(got[-1]['content'])['evidence_id']
        v={'scorable':True,'reason':'fixture','uncertainties':[],'rounds':[{'round_id':n,**{r:{axis:{'loss':0,'evidence_ids':[eid],'reason':'test observation'}} for r in ('red','blue','incident')}} for n in (1,2)]}
        return {'choices':[{'message':{'role':'assistant','content':json.dumps(v)},'finish_reason':'stop'}]}
    monkeypatch.setattr(OpenAIBlue,'_generate',generate)
    with pytest.raises(TimeoutError):asyncio.run(adjudicate_axes(tmp_path))
    before=(tmp_path/'judge_axes/confidentiality.json').read_bytes();calls=state['confidentiality_calls']
    state['fail']=False
    result=asyncio.run(judge_match(tmp_path,resume=True))
    assert result['scored'] and state['confidentiality_calls']==calls
    assert (tmp_path/'judge_axes/confidentiality.json').read_bytes()==before
    assert load_score(tmp_path)==result
