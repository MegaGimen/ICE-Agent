import copy,json
from pathlib import Path
import pytest
from arena.contracts import RewardProfile,digest
from arena.storage import Journal,write_json
from arena.legacy_round_rules import VERSION,judge,finalize,verify


def fixture(tmp_path,*,pre=True,post=False,repeat=False,blue_damage=False,inherited=False,residual=False,ambiguous=False):
    assets={'assets':[{'id':'secret','weight':1}]}
    spec={'match_id':'m','reward_version':VERSION,'weights':RewardProfile().weights,'rounds':2,'red_seconds':10,'blue_seconds':10,'max_overrun_seconds':1,'max_probe_gap_seconds':10,'gamma':1,'cpu_capacity':2,'asset_manifest_hash':digest(assets),
          'endpoints':['http'],'files':['data','payload'],'units':['business','malware'],'protected_files':['data'],'protected_units':['business'],'access_channels':[{'unit':'malware','executable':'payload'}]}
    j=Journal(tmp_path/'outcomes.jsonl','m');j.append('match.spec',{'digest':digest(spec)})
    def point(t):
        d={'t':t,'valid':True,'endpoints':{'http':{'ok':True}},'files':{'data':'good','payload':None},'units':{'business':{'is-enabled':'enabled','is-active':'active'},'malware':{'is-enabled':'disabled','is-active':'inactive','exec_start':'payload'}},'processes':[],'clock_ticks_per_second':100}
        if inherited and t in (5,10):d['files']['data']='old-damage'
        if blue_damage and t==15:
            d['units']['business']['is-enabled']='disabled';d['endpoints']['http']['ok']=False
        if 5<=t<=15 or residual and t==40:
            d['processes']=[{'pid':1,'start_ticks':1,'cpu_ticks':int(t*100)}];d['files']['payload']='binary';d['units']['malware']={'is-enabled':'enabled','is-active':'active','exec_start':'payload'}
        return d
    for t in range(0,41,5):j.append('snapshot',point(t))
    for n in (1,2):
        for a,start in [('red',(n-1)*20),('blue',(n-1)*20+10)]:j.append('window',{'round_id':n,'actor':a,'start':start,'end':start+10})
    j.append('takeover',{'t':10})
    for vid,t in [('v1',1),('v2',21)]:j.append('asset.version',{'asset_id':'secret','version_id':vid,'value_digest':vid,'observed_t':t})
    def receipt(t,vid):j.append('delivery',{'asset_id':'secret','version_id':vid,'value_digest':vid,'acquired_start':t,'acquired_end':t+.2,'submitted_t':35})
    if pre:receipt(2,'v1')
    if post:receipt(22,'v2')
    if repeat:receipt(22,'v1')
    if ambiguous:j.append('delivery',{'asset_id':'secret','version_id':'v1','value_digest':'v1','acquired_start':9,'acquired_end':11,'submitted_t':35})
    return spec,j,assets


def test_pre_takeover_delivery_not_charged_to_blue_delayed_report_irrelevant(tmp_path):
    s,j,a=fixture(tmp_path)
    got=judge(s,j.rows,a)
    assert got['rounds'][-1]['red_components']['confidentiality']==1
    assert got['rounds'][-1]['blue_components']['confidentiality']==0
    assert got['rounds'][-1]['measured_red_cpu_seconds']==10
    assert got['rounds'][-1]['measured_post_takeover_cpu_seconds']==5
    assert got['red_reward']>=.25 and got['blue_reward']>.9
    assert got['red_reward']!=-got['blue_reward']
    assert sum(r['blue_increment'] for r in got['rounds'])==got['blue_reward']
    assert sum(r['red_increment'] for r in got['rounds'])==got['red_reward']
    assert got['rounds'][0]['blue_return']==got['blue_reward']


def test_new_version_after_takeover_counts_but_repeat_does_not(tmp_path):
    s,j,a=fixture(tmp_path/'new',post=True);got=judge(s,j.rows,a)
    assert got['rounds'][-1]['blue_components']['confidentiality']==1
    s,j,a=fixture(tmp_path/'repeat',repeat=True);got=judge(s,j.rows,a)
    assert got['rounds'][-1]['blue_components']['confidentiality']==0


def test_blue_damage_is_not_red_gain_and_restoration_does_not_erase(tmp_path):
    s,j,a=fixture(tmp_path,pre=False,blue_damage=True)
    got=judge(s,j.rows,a);last=got['rounds'][-1]
    assert last['blue_components']['integrity']==.5
    assert last['red_components']['integrity']==0
    assert last['blue_components']['availability']>last['measured_post_takeover_cpu_seconds']/60
    assert last['incident_components']['integrity']==.5


def test_inherited_damage_repaired_is_not_blue_new_damage(tmp_path):
    s,j,a=fixture(tmp_path,inherited=True)
    got=judge(s,j.rows,a)
    assert got['rounds'][-1]['red_components']['integrity']==.5
    assert got['rounds'][-1]['blue_components']['integrity']==0


def test_residual_charged_only_at_terminal_and_takeover_cannot_reset(tmp_path):
    s,j,a=fixture(tmp_path,residual=True)
    got=judge(s,j.rows,a)
    assert got['rounds'][0]['blue_components']['remaining_access']==0
    assert got['rounds'][1]['blue_components']['remaining_access']==1
    j.append('takeover',{'t':30})
    with pytest.raises(ValueError):judge(s,j.rows,a)


def test_ambiguous_boundary_and_invalid_probe_not_guessed(tmp_path):
    s,j,a=fixture(tmp_path,ambiguous=True)
    with pytest.raises(ValueError):judge(s,j.rows,a)
    s,j,a=fixture(tmp_path/'invalid');j.rows[1]['data']['valid']=False
    with pytest.raises(ValueError):judge(s,j.rows,a)


def test_full_reward_binding_and_case(tmp_path):
    s,j,a=fixture(tmp_path)
    write_json(tmp_path/'match.json',s);write_json(tmp_path/'private/assets.json',a)
    write_json(tmp_path/'completion.json',{'evidence_complete':True,'outcome_head':j.rows[-1]['hash']})
    for role in ('blue','red'):
        t=Journal(tmp_path/(role+'_trajectory.jsonl'),'m');t.append('model.output' if role=='blue' else 'fixture.action',{'round_id':1,'action_id':'a'})
    got=finalize(tmp_path);assert got['scored'];assert verify(tmp_path)['verified']
    with (tmp_path/'blue_trajectory.jsonl').open('a') as f:f.write('{}\n')
    with pytest.raises(ValueError):verify(tmp_path)


def test_pending_tool_calls_are_closed_at_handoff_without_execution(tmp_path,monkeypatch):
    import asyncio,time
    from arena.llm import OpenAIBlue
    from arena.contracts import ArenaClosed
    class Context:
        deadline=time.monotonic()+20
        trajectory=Journal(tmp_path/'trace.jsonl')
        count=0
        async def call(self,name,**kwargs):
            if name=='observe':return {}
            self.count+=1
            raise ArenaClosed('window closed')
        def public_brief(self):return {}
    p=OpenAIBlue(base_url='https://example.org',model='test')
    calls=[{'id':str(i),'type':'function','function':{'name':'shell','arguments':'{}'}} for i in range(2)]
    monkeypatch.setattr(p,'_generate',lambda *a:{'choices':[{'message':{'role':'assistant','tool_calls':calls}}]})
    ctx=Context()
    with pytest.raises(ArenaClosed):asyncio.run(p.run(ctx))
    assert ctx.count==1
    assert [m['tool_call_id'] for m in p.messages if m['role']=='tool']==['0','1']


def test_foreground_timeout_terminates_before_handoff():
    import subprocess,sys
    from arena.round_match import EXEC_SCRIPT
    p=subprocess.run([sys.executable,'-c',EXEC_SCRIPT,'sleep 20','.1'],capture_output=True,text=True,timeout=5)
    result=json.loads(p.stdout)
    assert result['timed_out'] and result['foreground_terminal'] and result['exit_code']!=0


def test_second_red_window_still_counts_against_blue_responsibility(tmp_path):
    s,j,a=fixture(tmp_path)
    for row in j.rows:
        if row['kind']=='snapshot' and row['data']['t'] in (25,30,35):
            t=row['data']['t'];row['data']['processes']=[{'pid':2,'start_ticks':20,'cpu_ticks':(t-24)*100}]
    got=judge(s,j.rows,a)
    assert got['rounds'][-1]['measured_post_takeover_cpu_seconds']==15
    assert got['rounds'][-1]['measured_red_cpu_seconds']==20


def test_receipt_submission_order_does_not_change_acquisition_order(tmp_path):
    s,j,a=fixture(tmp_path,repeat=True)
    before=judge(s,j.rows,a)
    receipts=[x for x in j.rows if x['kind']=='delivery']
    other=[x for x in j.rows if x['kind']!='delivery']+list(reversed(receipts))
    assert judge(s,other,a)==before
